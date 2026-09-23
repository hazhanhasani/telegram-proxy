import re
from dataclasses import dataclass
from textwrap import dedent

from .models import Proxy, Server
from .security import decrypt_text
from .ssh import run


REMOTE_ROOT = "/opt/telegram-proxy-panel"
SERVICE_PREFIX = "tgproxy"


@dataclass
class ProxyStatus:
    active: bool
    current_connections: int
    raw_stats: str
    error: str = ""


def _valid_port(port: int) -> bool:
    return 1 <= int(port) <= 65535


def _unit_name(slug: str) -> str:
    return f"{SERVICE_PREFIX}-{slug}.service"


def _stats_connections(raw: str) -> int:
    patterns = [
        r"active_connections\\s*[:\\t ]+([0-9]+)",
        r"active connections\\s*[:\\t ]+([0-9]+)",
        r"connections\\s*[:\\t ]+([0-9]+)",
        r"active_special_connections\\s*[:\\t ]+([0-9]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, raw, flags=re.IGNORECASE)
        if match:
            return int(match.group(1))
    return 0


async def bootstrap_server(server: Server) -> str:
    script = dedent(
        f"""
        set -euo pipefail
        export DEBIAN_FRONTEND=noninteractive

        if ! command -v apt-get >/dev/null 2>&1; then
          echo "This installer currently supports Debian/Ubuntu nodes." >&2
          exit 41
        fi

        apt-get update -y
        apt-get install -y git curl ca-certificates build-essential libssl-dev zlib1g-dev

        install -d -m 0755 {REMOTE_ROOT}/src {REMOTE_ROOT}/bin {REMOTE_ROOT}/data

        if [ ! -d {REMOTE_ROOT}/src/MTProxy/.git ]; then
          git clone --depth 1 https://github.com/TelegramMessenger/MTProxy.git {REMOTE_ROOT}/src/MTProxy
        else
          git -C {REMOTE_ROOT}/src/MTProxy fetch --depth 1 origin master
          git -C {REMOTE_ROOT}/src/MTProxy reset --hard origin/master
        fi

        make -C {REMOTE_ROOT}/src/MTProxy clean >/dev/null 2>&1 || true
        make -C {REMOTE_ROOT}/src/MTProxy -j"$(nproc)"
        install -m 0755 {REMOTE_ROOT}/src/MTProxy/objs/bin/mtproto-proxy {REMOTE_ROOT}/bin/mtproto-proxy

        curl -fsSL https://core.telegram.org/getProxySecret -o {REMOTE_ROOT}/data/proxy-secret
        curl -fsSL https://core.telegram.org/getProxyConfig -o {REMOTE_ROOT}/data/proxy-multi.conf
        chmod 0644 {REMOTE_ROOT}/data/proxy-secret {REMOTE_ROOT}/data/proxy-multi.conf

        cat >/etc/systemd/system/tgproxy-config-update.service <<'EOF'
        [Unit]
        Description=Refresh Telegram MTProxy upstream configuration
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=oneshot
        ExecStart=/usr/bin/curl -fsSL https://core.telegram.org/getProxySecret -o {REMOTE_ROOT}/data/proxy-secret
        ExecStart=/usr/bin/curl -fsSL https://core.telegram.org/getProxyConfig -o {REMOTE_ROOT}/data/proxy-multi.conf
        EOF

        cat >/etc/systemd/system/tgproxy-config-update.timer <<'EOF'
        [Unit]
        Description=Daily Telegram MTProxy configuration refresh

        [Timer]
        OnCalendar=daily
        RandomizedDelaySec=20m
        Persistent=true

        [Install]
        WantedBy=timers.target
        EOF

        systemctl daemon-reload
        systemctl enable --now tgproxy-config-update.timer
        {REMOTE_ROOT}/bin/mtproto-proxy --help >/dev/null 2>&1 || true
        echo "bootstrap-ok"
        """
    )
    result = await run(server, script, timeout=900)
    if result.exit_status != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Bootstrap failed")
    return result.stdout.strip()


async def deploy_proxy(server: Server, proxy: Proxy, sponsor_tag: str = "") -> str:
    if not _valid_port(proxy.public_port) or not _valid_port(proxy.stats_port):
        raise ValueError("Invalid port")

    raw_secret = decrypt_text(proxy.secret_enc)
    if not re.fullmatch(r"[0-9a-f]{32}", raw_secret):
        raise ValueError("Invalid proxy secret")

    tag_arg = ""
    if sponsor_tag:
        tag = sponsor_tag.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{32}", tag):
            raise ValueError("Invalid sponsor tag")
        tag_arg = f" -P {tag}"

    unit = _unit_name(proxy.slug)
    service = dedent(
        f"""
        [Unit]
        Description=Telegram MTProxy - {proxy.slug}
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=simple
        WorkingDirectory={REMOTE_ROOT}\n        ExecStart={REMOTE_ROOT}/bin/mtproto-proxy -u nobody -p {proxy.stats_port} -H {proxy.public_port} --http-stats -S {raw_secret}{tag_arg} --aes-pwd {REMOTE_ROOT}/data/proxy-secret {REMOTE_ROOT}/data/proxy-multi.conf -M {proxy.workers}
        Restart=always
        RestartSec=3
        LimitNOFILE=1048576
        NoNewPrivileges=true
        PrivateTmp=true
        ProtectHome=true

        [Install]
        WantedBy=multi-user.target
        """
    ).strip()

    script = dedent(
        f"""
        set -euo pipefail
        test -x {REMOTE_ROOT}/bin/mtproto-proxy
        cat >/etc/systemd/system/{unit} <<'EOF'
        {service}
        EOF
        systemctl daemon-reload
        systemctl enable --now {unit}
        if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
          ufw allow {proxy.public_port}/tcp >/dev/null || true
        fi
        sleep 1
        systemctl is-active {unit}
        """
    )
    result = await run(server, script, timeout=90)
    if result.exit_status != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Proxy deployment failed")
    return result.stdout.strip()


async def action_proxy(server: Server, proxy: Proxy, action: str) -> str:
    if action not in {"start", "stop", "restart"}:
        raise ValueError("Unsupported action")
    unit = _unit_name(proxy.slug)
    result = await run(
        server,
        f"systemctl {action} {unit} && systemctl is-active {unit} || true",
        timeout=45,
    )
    if result.exit_status != 0:
        raise RuntimeError(result.stderr.strip() or "Service action failed")
    return result.stdout.strip()


async def delete_proxy(server: Server, proxy: Proxy) -> None:
    unit = _unit_name(proxy.slug)
    script = dedent(
        f"""
        set -e
        systemctl disable --now {unit} >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/{unit}
        systemctl daemon-reload
        """
    )
    result = await run(server, script, timeout=45)
    if result.exit_status != 0:
        raise RuntimeError(result.stderr.strip() or "Remote proxy removal failed")


async def proxy_status(server: Server, proxy: Proxy) -> ProxyStatus:
    unit = _unit_name(proxy.slug)
    command = (
        f"state=$(systemctl is-active {unit} 2>/dev/null || true); "
        "printf '%s\\n---STATS---\\n' \"$state\"; "
        f"(curl -fsS --max-time 4 http://127.0.0.1:{proxy.stats_port}/stats 2>/dev/null || true)"
    )
    try:
        result = await run(server, command, timeout=12)
    except Exception as exc:
        return ProxyStatus(False, 0, "", str(exc))

    first, _, stats = result.stdout.partition("---STATS---")
    active = first.strip().splitlines()[-1:] == ["active"]
    return ProxyStatus(
        active=active,
        current_connections=_stats_connections(stats),
        raw_stats=stats.strip(),
        error=result.stderr.strip() if result.exit_status not in (0, 3) else "",
    )
