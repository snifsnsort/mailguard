from cryptography.fernet import Fernet
from app.core.config import settings
import base64, hashlib


def _get_fernet() -> Fernet:
    key = settings.ENCRYPTION_KEY
    if key:
        # ENCRYPTION_KEY is set. PowerShell's [Convert]::ToBase64String produces
        # standard base64 (+, /, = padding). Fernet requires URL-safe base64
        # (-, _, no padding). Normalise by decoding then re-encoding URL-safe.
        try:
            raw_bytes = base64.b64decode(key + "==")   # add padding to be safe
            raw = base64.urlsafe_b64encode(raw_bytes)
        except Exception:
            # Key may already be URL-safe base64 — use as-is
            raw = key.encode() if isinstance(key, str) else key
    else:
        # No ENCRYPTION_KEY — derive a stable key from SECRET_KEY so encrypted
        # values survive container restarts. SHA-256 → 32 bytes → url-safe b64.
        raw = base64.urlsafe_b64encode(
            hashlib.sha256(settings.SECRET_KEY.encode()).digest()
        )
    return Fernet(raw)


def encrypt(plain: str) -> str:
    return _get_fernet().encrypt(plain.encode()).decode()


def decrypt(token: str) -> str:
    return _get_fernet().decrypt(token.encode()).decode()
