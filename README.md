# Telegram Proxy Control

پنل RTL مدیریت MTProto Proxy تلگرام با چند سرور، چند پروکسی، Sponsor/Promoted Channel، مانیتورینگ، QR، لینک Share و نصب خودکار.

## امکانات

- مدیریت چند Node از یک Control Plane
- اتصال Agentless با SSH (Password / Private Key)
- Pin کردن SSH Host Key با TOFU
- Build خودکار MTProxy رسمی Telegram روی Ubuntu/Debian
- چند Instance مستقل روی هر Node
- Secret تصادفی 128-bit و Random Padding با `dd`
- Sponsor / Promoted Channel با Proxy Tag رسمی و آرگومان `-P`
- `--http-stats`، Health Check و شمارش اتصال‌ها
- Start / Stop / Restart / Redeploy / Delete
- QR، `tg://`، `https://t.me/proxy` و صفحه Share
- Audit Log
- Fernet برای credentialها و Secretها
- Argon2، CSRF، Security Headers و Secure Session option
- PostgreSQL + Docker Compose
- API خواندنی اختیاری
- GitHub Actions CI

## Sponsor

در Telegram به **@MTProxyBot** بروید، `/newproxy` را اجرا کنید و Proxy Tag را بگیرید. Tag را در بخش «اسپانسرها» وارد و هنگام ساخت Proxy انتخاب کنید. پنل آن را با `-P <proxy tag>` روی MTProxy اعمال می‌کند.

## نصب

```bash
git clone https://github.com/hazhanhasani/telegram-proxy.git
cd telegram-proxy
sudo bash scripts/install.sh
```

پنل پیش‌فرض روی پورت 8080 است. برای Production آن را پشت HTTPS قرار دهید و `SESSION_HTTPS_ONLY=true` کنید.

## افزودن Node

1. Servers → Add Node
2. IP/Host و SSH credential
3. Test SSH برای ثبت fingerprint
4. Bootstrap برای Build و نصب MTProxy رسمی

Bootstrap فایل‌های `proxy-secret` و `proxy-multi.conf` را از Telegram می‌گیرد و timer روزانه refresh می‌سازد.

## ساخت Proxy

در Proxies، Node، Host/Port، Stats Port، Workers، Sponsor و Random Padding را تعیین کنید. هر Proxy یک `tgproxy-SLUG.service` مستقل دارد.

## معماری

```text
Browser
   |
FastAPI Control Plane ---- PostgreSQL
   |
   +---- SSH ---- Node A ---- tgproxy-a.service
   |                    \--- tgproxy-b.service
   |
   \---- SSH ---- Node B ---- tgproxy-c.service
```

Control Plane ترافیک Telegram را عبور نمی‌دهد؛ MTProxy روی Nodeها اجرا می‌شود.

## API

اگر `API_TOKEN` تنظیم شود:

```text
GET /api/v1/proxies
Authorization: Bearer YOUR_TOKEN
```

## Production

- HTTPS اجباری شود.
- `.env` خصوصی بماند.
- SSH Key اختصاصی پنل استفاده شود.
- Firewall پنل به IPهای مدیریتی محدود شود.
- از PostgreSQL بکاپ گرفته شود.
- `SECRET_KEY` یا `ENCRYPTION_KEY` بدون برنامه مهاجرت تغییر نکند.

MTProxy محتوای پیام Telegram را رمزگشایی نمی‌کند، اما Node در لایه شبکه IP و زمان اتصال را می‌بیند؛ لاگ‌گیری حداقلی توصیه می‌شود.
