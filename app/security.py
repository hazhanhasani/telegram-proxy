import base64
import hashlib
import re
import secrets
from urllib.parse import urlencode

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken

from .config import settings


ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
TAG_RE = re.compile(r"^[0-9a-fA-F]{32}$")
SECRET_RE = re.compile(r"^[0-9a-fA-F]{32}$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")


def _fernet() -> Fernet:
    if settings.encryption_key.strip():
        key = settings.encryption_key.strip().encode()
    else:
        digest = hashlib.sha256(settings.secret_key.encode()).digest()
        key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def encrypt_text(value: str) -> str:
    if not value:
        return ""
    return _fernet().encrypt(value.encode()).decode()


def decrypt_text(value: str) -> str:
    if not value:
        return ""
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise RuntimeError("Encrypted value cannot be decrypted. Check ENCRYPTION_KEY/SECRET_KEY.") from exc


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def generate_proxy_secret() -> str:
    return secrets.token_hex(16)


def generate_csrf() -> str:
    return secrets.token_urlsafe(32)


def validate_tag(tag: str) -> bool:
    return bool(TAG_RE.fullmatch(tag.strip()))


def validate_secret(secret: str) -> bool:
    return bool(SECRET_RE.fullmatch(secret.strip()))


def validate_slug(slug: str) -> bool:
    return bool(SLUG_RE.fullmatch(slug.strip()))


def client_secret(raw_secret: str, padded: bool) -> str:
    return ("dd" if padded else "") + raw_secret


def proxy_links(host: str, port: int, raw_secret: str, padded: bool) -> dict[str, str]:
    secret = client_secret(raw_secret, padded)
    query = urlencode({"server": host, "port": str(port), "secret": secret})
    return {
        "tg": f"tg://proxy?{query}",
        "https": f"https://t.me/proxy?{query}",
    }
