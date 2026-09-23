import asyncio
import io
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from urllib.parse import quote

import qrcode
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload
from starlette.middleware.sessions import SessionMiddleware

from .config import settings
from .database import SessionLocal, get_db, init_db
from .models import AuditLog, Proxy, Server, Sponsor, User, utcnow
from .mtproxy import action_proxy, bootstrap_server, delete_proxy, deploy_proxy, proxy_status
from .security import (
    encrypt_text,
    generate_csrf,
    generate_proxy_secret,
    hash_password,
    proxy_links,
    validate_slug,
    validate_tag,
    verify_password,
)
from .ssh import probe


templates = Jinja2Templates(directory="app/templates")


def flash(request: Request, message: str, kind: str = "info") -> None:
    request.session["flash"] = {"message": message, "kind": kind}


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = generate_csrf()
        request.session["csrf"] = token
    return token


async def require_csrf(request: Request) -> None:
    form = await request.form()
    expected = request.session.get("csrf", "")
    supplied = str(form.get("csrf_token", ""))
    if not expected or supplied != expected:
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


def auth_user(request: Request, db: Session) -> User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return db.get(User, int(user_id))


def require_user(request: Request, db: Session) -> User:
    user = auth_user(request, db)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def context(request: Request, **extra):
    data = {
        "request": request,
        "csrf_token": csrf_token(request),
        "flash": request.session.pop("flash", None),
        "app_name": settings.app_name,
        "current_path": request.url.path,
    }
    data.update(extra)
    return data


def audit(db: Session, request: Request | None, action: str, target_type: str = "", target_id: str = "", details: str = ""):
    email = "system"
    ip = ""
    if request is not None:
        ip = request.client.host if request.client else ""
        uid = request.session.get("user_id")
        if uid:
            user = db.get(User, int(uid))
            if user:
                email = user.email
    db.add(
        AuditLog(
            user_email=email,
            action=action,
            target_type=target_type,
            target_id=str(target_id),
            details=details[:2000],
            ip_address=ip,
        )
    )


def ensure_admin() -> None:
    if not settings.admin_password:
        return
    with SessionLocal() as db:
        existing = db.scalar(select(User).where(User.email == settings.admin_email.lower()))
        if existing:
            return
        db.add(
            User(
                email=settings.admin_email.lower(),
                password_hash=hash_password(settings.admin_password),
            )
        )
        db.commit()


async def refresh_proxy(proxy_id: int) -> None:
    with SessionLocal() as db:
        proxy = db.scalar(
            select(Proxy)
            .options(joinedload(Proxy.server))
            .where(Proxy.id == proxy_id)
        )
        if not proxy:
            return
        try:
            status = await proxy_status(proxy.server, proxy)
            proxy.state = "online" if status.active else "offline"
            proxy.current_connections = status.current_connections
            proxy.last_error = status.error
            proxy.last_checked = utcnow()
            if status.active:
                proxy.server.state = "online"
                proxy.server.last_seen = utcnow()
                proxy.server.last_error = ""
        except Exception as exc:
            proxy.state = "error"
            proxy.last_error = str(exc)[:2000]
        db.commit()


async def health_loop() -> None:
    while True:
        try:
            with SessionLocal() as db:
                ids = list(db.scalars(select(Proxy.id)).all())
            semaphore = asyncio.Semaphore(5)

            async def guarded(pid: int):
                async with semaphore:
                    await refresh_proxy(pid)

            await asyncio.gather(*(guarded(pid) for pid in ids), return_exceptions=True)
        except Exception:
            pass
        await asyncio.sleep(max(settings.health_interval, 20))


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    ensure_admin()
    task = asyncio.create_task(health_loop())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    same_site="strict",
    https_only=settings.session_https_only,
    max_age=60 * 60 * 12,
)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.get("/health")
def health():
    return {"ok": True, "name": settings.app_name}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    if auth_user(request, db):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse("login.html", context(request))


@app.post("/login")
async def login(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    await require_csrf(request)
    user = db.scalar(select(User).where(User.email == email.strip().lower()))
    if not user or not user.is_active or not verify_password(password, user.password_hash):
        flash(request, "ایمیل یا رمز عبور اشتباه است.", "danger")
        return RedirectResponse("/login", status_code=303)
    request.session.clear()
    request.session["user_id"] = user.id
    request.session["csrf"] = generate_csrf()
    audit(db, request, "login", "user", str(user.id))
    db.commit()
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    await require_csrf(request)
    require_user(request, db)
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    counts = {
        "servers": db.scalar(select(func.count()).select_from(Server)) or 0,
        "proxies": db.scalar(select(func.count()).select_from(Proxy)) or 0,
        "online": db.scalar(select(func.count()).select_from(Proxy).where(Proxy.state == "online")) or 0,
        "connections": db.scalar(select(func.coalesce(func.sum(Proxy.current_connections), 0))) or 0,
    }
    recent = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(8)).all()
    proxies = db.scalars(
        select(Proxy).options(joinedload(Proxy.server), joinedload(Proxy.sponsor)).order_by(Proxy.id.desc()).limit(8)
    ).all()
    return templates.TemplateResponse("dashboard.html", context(request, counts=counts, recent=recent, proxies=proxies))


@app.get("/servers", response_class=HTMLResponse)
def servers_page(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    servers = db.scalars(select(Server).order_by(Server.id.desc())).all()
    return templates.TemplateResponse("servers.html", context(request, servers=servers))


@app.post("/servers")
async def add_server(
    request: Request,
    name: str = Form(...),
    host: str = Form(...),
    ssh_port: int = Form(22),
    ssh_user: str = Form("root"),
    auth_type: str = Form("password"),
    credential: str = Form(""),
    db: Session = Depends(get_db),
):
    await require_csrf(request)
    require_user(request, db)
    if auth_type not in {"password", "private_key"}:
        raise HTTPException(400, "Invalid auth type")
    server = Server(
        name=name.strip(),
        host=host.strip(),
        ssh_port=ssh_port,
        ssh_user=ssh_user.strip(),
        auth_type=auth_type,
        credential_enc=encrypt_text(credential),
    )
    db.add(server)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        flash(request, "نام سرور تکراری است.", "danger")
        return RedirectResponse("/servers", status_code=303)
    audit(db, request, "server.create", "server", str(server.id), server.name)
    db.commit()
    flash(request, "سرور اضافه شد. ابتدا اتصال را تست و سپس Bootstrap را اجرا کنید.", "success")
    return RedirectResponse("/servers", status_code=303)


@app.post("/servers/{server_id}/test")
async def test_server(server_id: int, request: Request, db: Session = Depends(get_db)):
    await require_csrf(request)
    require_user(request, db)
    server = db.get(Server, server_id)
    if not server:
        raise HTTPException(404)
    try:
        result = await probe(server)
        if result.exit_status != 0:
            raise RuntimeError(result.stderr or "SSH test failed")
        if not server.host_key_fingerprint:
            server.host_key_fingerprint = result.fingerprint
        server.state = "online"
        server.last_seen = utcnow()
        server.last_error = ""
        flash(request, f"اتصال موفق بود. Fingerprint: {result.fingerprint}", "success")
    except Exception as exc:
        server.state = "error"
        server.last_error = str(exc)[:2000]
        flash(request, f"خطای اتصال: {exc}", "danger")
    audit(db, request, "server.test", "server", str(server.id))
    db.commit()
    return RedirectResponse("/servers", status_code=303)


@app.post("/servers/{server_id}/bootstrap")
async def bootstrap_node(server_id: int, request: Request, db: Session = Depends(get_db)):
    await require_csrf(request)
    require_user(request, db)
    server = db.get(Server, server_id)
    if not server:
        raise HTTPException(404)
    try:
        await bootstrap_server(server)
        server.state = "ready"
        server.last_error = ""
        server.last_seen = utcnow()
        flash(request, "MTProxy رسمی روی سرور نصب/به‌روزرسانی شد.", "success")
    except Exception as exc:
        server.state = "error"
        server.last_error = str(exc)[:2000]
        flash(request, f"Bootstrap ناموفق: {exc}", "danger")
    audit(db, request, "server.bootstrap", "server", str(server.id))
    db.commit()
    return RedirectResponse("/servers", status_code=303)


@app.post("/servers/{server_id}/delete")
async def remove_server(server_id: int, request: Request, db: Session = Depends(get_db)):
    await require_csrf(request)
    require_user(request, db)
    server = db.get(Server, server_id)
    if not server:
        raise HTTPException(404)
    if server.proxies:
        flash(request, "ابتدا پروکسی‌های این سرور را حذف کنید.", "danger")
        return RedirectResponse("/servers", status_code=303)
    audit(db, request, "server.delete", "server", str(server.id), server.name)
    db.delete(server)
    db.commit()
    flash(request, "سرور از پنل حذف شد.", "success")
    return RedirectResponse("/servers", status_code=303)


@app.get("/sponsors", response_class=HTMLResponse)
def sponsors_page(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    sponsors = db.scalars(select(Sponsor).order_by(Sponsor.id.desc())).all()
    return templates.TemplateResponse("sponsors.html", context(request, sponsors=sponsors))


@app.post("/sponsors")
async def add_sponsor(
    request: Request,
    name: str = Form(...),
    channel: str = Form(""),
    proxy_tag: str = Form(...),
    db: Session = Depends(get_db),
):
    await require_csrf(request)
    require_user(request, db)
    tag = proxy_tag.strip().lower()
    if not validate_tag(tag):
        flash(request, "Proxy Tag باید دقیقاً ۳۲ کاراکتر hexadecimal باشد.", "danger")
        return RedirectResponse("/sponsors", status_code=303)
    sponsor = Sponsor(name=name.strip(), channel=channel.strip(), proxy_tag=tag)
    db.add(sponsor)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        flash(request, "نام یا Tag تکراری است.", "danger")
        return RedirectResponse("/sponsors", status_code=303)
    audit(db, request, "sponsor.create", "sponsor", str(sponsor.id), sponsor.channel)
    db.commit()
    flash(request, "اسپانسر ثبت شد.", "success")
    return RedirectResponse("/sponsors", status_code=303)


@app.post("/sponsors/{sponsor_id}/delete")
async def remove_sponsor(sponsor_id: int, request: Request, db: Session = Depends(get_db)):
    await require_csrf(request)
    require_user(request, db)
    sponsor = db.get(Sponsor, sponsor_id)
    if not sponsor:
        raise HTTPException(404)
    if sponsor.proxies:
        flash(request, "این اسپانسر هنوز به یک یا چند پروکسی متصل است.", "danger")
        return RedirectResponse("/sponsors", status_code=303)
    audit(db, request, "sponsor.delete", "sponsor", str(sponsor.id), sponsor.name)
    db.delete(sponsor)
    db.commit()
    flash(request, "اسپانسر حذف شد.", "success")
    return RedirectResponse("/sponsors", status_code=303)


@app.get("/proxies", response_class=HTMLResponse)
def proxies_page(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    proxies = db.scalars(
        select(Proxy).options(joinedload(Proxy.server), joinedload(Proxy.sponsor)).order_by(Proxy.id.desc())
    ).all()
    servers = db.scalars(select(Server).order_by(Server.name)).all()
    sponsors = db.scalars(select(Sponsor).where(Sponsor.is_active.is_(True)).order_by(Sponsor.name)).all()

    link_map = {}
    for proxy in proxies:
        from .security import decrypt_text
        try:
            link_map[proxy.id] = proxy_links(
                proxy.public_host,
                proxy.public_port,
                decrypt_text(proxy.secret_enc),
                proxy.padding_enabled,
            )
        except Exception:
            link_map[proxy.id] = {"tg": "", "https": ""}

    return templates.TemplateResponse(
        "proxies.html",
        context(request, proxies=proxies, servers=servers, sponsors=sponsors, link_map=link_map),
    )


@app.post("/proxies")
async def add_proxy(
    request: Request,
    name: str = Form(...),
    slug: str = Form(...),
    server_id: int = Form(...),
    sponsor_id: str = Form(""),
    public_host: str = Form(...),
    public_port: int = Form(443),
    stats_port: int = Form(8888),
    workers: int = Form(1),
    padding_enabled: str | None = Form(None),
    db: Session = Depends(get_db),
):
    await require_csrf(request)
    require_user(request, db)
    slug = slug.strip().lower()
    if not validate_slug(slug):
        flash(request, "Slug فقط حروف کوچک انگلیسی، عدد و خط تیره و حداقل ۳ کاراکتر باشد.", "danger")
        return RedirectResponse("/proxies", status_code=303)
    if not (1 <= public_port <= 65535 and 1 <= stats_port <= 65535 and public_port != stats_port):
        flash(request, "پورت‌ها نامعتبر یا یکسان هستند.", "danger")
        return RedirectResponse("/proxies", status_code=303)
    if not (1 <= workers <= 64):
        flash(request, "Workers باید بین ۱ تا ۶۴ باشد.", "danger")
        return RedirectResponse("/proxies", status_code=303)

    server = db.get(Server, server_id)
    if not server:
        raise HTTPException(404, "Server not found")
    sponsor = db.get(Sponsor, int(sponsor_id)) if sponsor_id else None

    proxy = Proxy(
        name=name.strip(),
        slug=slug,
        server_id=server.id,
        sponsor_id=sponsor.id if sponsor else None,
        public_host=public_host.strip(),
        public_port=public_port,
        stats_port=stats_port,
        secret_enc=encrypt_text(generate_proxy_secret()),
        padding_enabled=bool(padding_enabled),
        workers=workers,
    )
    db.add(proxy)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        flash(request, "Slug یا پورت انتخابی قبلاً استفاده شده است.", "danger")
        return RedirectResponse("/proxies", status_code=303)

    try:
        await deploy_proxy(server, proxy, sponsor.proxy_tag if sponsor else "")
        proxy.state = "online"
        proxy.last_error = ""
        proxy.last_checked = utcnow()
        flash(request, "پروکسی ساخته و روی سرور فعال شد.", "success")
    except Exception as exc:
        proxy.state = "error"
        proxy.last_error = str(exc)[:2000]
        flash(request, f"رکورد ساخته شد اما Deploy خطا داد: {exc}", "danger")

    audit(db, request, "proxy.create", "proxy", str(proxy.id), proxy.slug)
    db.commit()
    return RedirectResponse("/proxies", status_code=303)


@app.post("/proxies/{proxy_id}/{action}")
async def proxy_action(proxy_id: int, action: str, request: Request, db: Session = Depends(get_db)):
    await require_csrf(request)
    require_user(request, db)
    if action not in {"start", "stop", "restart", "redeploy"}:
        raise HTTPException(400, "Invalid action")
    proxy = db.scalar(
        select(Proxy).options(joinedload(Proxy.server), joinedload(Proxy.sponsor)).where(Proxy.id == proxy_id)
    )
    if not proxy:
        raise HTTPException(404)
    try:
        if action == "redeploy":
            await deploy_proxy(proxy.server, proxy, proxy.sponsor.proxy_tag if proxy.sponsor else "")
        else:
            await action_proxy(proxy.server, proxy, action)
        await refresh_proxy(proxy.id)
        flash(request, "عملیات انجام شد.", "success")
    except Exception as exc:
        proxy.state = "error"
        proxy.last_error = str(exc)[:2000]
        db.commit()
        flash(request, f"عملیات ناموفق: {exc}", "danger")
    audit(db, request, f"proxy.{action}", "proxy", str(proxy.id), proxy.slug)
    db.commit()
    return RedirectResponse("/proxies", status_code=303)


@app.post("/proxies/{proxy_id}/delete")
async def remove_proxy(proxy_id: int, request: Request, db: Session = Depends(get_db)):
    await require_csrf(request)
    require_user(request, db)
    proxy = db.scalar(select(Proxy).options(joinedload(Proxy.server)).where(Proxy.id == proxy_id))
    if not proxy:
        raise HTTPException(404)
    try:
        await delete_proxy(proxy.server, proxy)
    except Exception as exc:
        flash(request, f"حذف سرویس ریموت ناموفق بود: {exc}", "danger")
        return RedirectResponse("/proxies", status_code=303)
    audit(db, request, "proxy.delete", "proxy", str(proxy.id), proxy.slug)
    db.delete(proxy)
    db.commit()
    flash(request, "پروکسی از سرور و پنل حذف شد.", "success")
    return RedirectResponse("/proxies", status_code=303)


@app.get("/proxies/{proxy_id}/qr")
def proxy_qr(proxy_id: int, request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    proxy = db.get(Proxy, proxy_id)
    if not proxy:
        raise HTTPException(404)
    from .security import decrypt_text
    link = proxy_links(proxy.public_host, proxy.public_port, decrypt_text(proxy.secret_enc), proxy.padding_enabled)["https"]
    img = qrcode.make(link)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return Response(buf.getvalue(), media_type="image/png")


@app.get("/share/{slug}", response_class=HTMLResponse)
def public_share(slug: str, request: Request, db: Session = Depends(get_db)):
    proxy = db.scalar(
        select(Proxy).options(joinedload(Proxy.sponsor)).where(Proxy.slug == slug)
    )
    if not proxy:
        raise HTTPException(404)
    from .security import decrypt_text
    links = proxy_links(proxy.public_host, proxy.public_port, decrypt_text(proxy.secret_enc), proxy.padding_enabled)
    return templates.TemplateResponse(
        "share.html",
        {
            "request": request,
            "proxy": proxy,
            "links": links,
            "app_name": settings.app_name,
        },
    )


@app.get("/api/v1/proxies")
def api_proxies(request: Request, db: Session = Depends(get_db)):
    if not settings.api_token:
        raise HTTPException(404)
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {settings.api_token}":
        raise HTTPException(401)
    from .security import decrypt_text
    items = []
    for proxy in db.scalars(select(Proxy).options(joinedload(Proxy.server), joinedload(Proxy.sponsor))).all():
        links = proxy_links(proxy.public_host, proxy.public_port, decrypt_text(proxy.secret_enc), proxy.padding_enabled)
        items.append(
            {
                "id": proxy.id,
                "name": proxy.name,
                "slug": proxy.slug,
                "server": proxy.server.name,
                "state": proxy.state,
                "connections": proxy.current_connections,
                "sponsor": proxy.sponsor.name if proxy.sponsor else None,
                "links": links,
                "share_url": settings.public_base_url.rstrip("/") + "/share/" + quote(proxy.slug),
            }
        )
    return JSONResponse({"items": items})
