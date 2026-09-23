import asyncio
import shlex
from dataclasses import dataclass

import asyncssh

from .config import settings
from .models import Server
from .security import decrypt_text


@dataclass
class SSHResult:
    exit_status: int
    stdout: str
    stderr: str
    fingerprint: str


async def _connect(server: Server):
    credential = decrypt_text(server.credential_enc)
    kwargs = dict(
        host=server.host,
        port=server.ssh_port,
        username=server.ssh_user,
        known_hosts=None,
        connect_timeout=settings.ssh_connect_timeout,
        login_timeout=settings.ssh_connect_timeout,
    )

    if server.auth_type == "password":
        kwargs["password"] = credential
        kwargs["client_keys"] = None
    elif server.auth_type == "private_key":
        if not credential:
            raise RuntimeError("Private key is empty")
        kwargs["client_keys"] = [asyncssh.import_private_key(credential)]
    else:
        raise RuntimeError("Unsupported SSH auth type")

    conn = await asyncssh.connect(**kwargs)
    key = conn.get_server_host_key()
    fingerprint = key.get_fingerprint("sha256")

    if server.host_key_fingerprint and fingerprint != server.host_key_fingerprint:
        conn.close()
        await conn.wait_closed()
        raise RuntimeError(
            f"SSH host key changed. Expected {server.host_key_fingerprint}, got {fingerprint}"
        )
    return conn, fingerprint


async def run(server: Server, command: str, timeout: int | None = None, root: bool = True) -> SSHResult:
    conn, fingerprint = await _connect(server)
    try:
        shell = f"bash -lc {shlex.quote(command)}"
        if root and server.ssh_user != "root":
            shell = f"sudo -n {shell}"

        result = await asyncio.wait_for(
            conn.run(shell, check=False),
            timeout=timeout or settings.ssh_timeout,
        )
        return SSHResult(
            exit_status=result.exit_status,
            stdout=result.stdout or "",
            stderr=result.stderr or "",
            fingerprint=fingerprint,
        )
    finally:
        conn.close()
        await conn.wait_closed()


async def probe(server: Server) -> SSHResult:
    return await run(
        server,
        "printf 'ok\\n'; uname -srm; command -v systemctl >/dev/null",
        timeout=settings.ssh_connect_timeout + 5,
        root=False,
    )
