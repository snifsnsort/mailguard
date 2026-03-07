"""
Simple username/password auth for MailGuard.

Credentials set via env vars:
  ADMIN_USERNAME  (default: admin)
  ADMIN_PASSWORD  (default: changeme)

On first login with default password, must_change_password=True forces a reset.
New password stored hashed in DB settings table.
"""

from fastapi import APIRouter, HTTPException, Depends, Header
from sqlalchemy.orm import Session
from pydantic import BaseModel
import hashlib, hmac, secrets, os, json, base64
from datetime import datetime, timedelta
from typing import Optional

from app.core.database import get_db

router = APIRouter()

DEFAULT_USERNAME = os.environ.get("ADMIN_USERNAME", "admin").lower()
DEFAULT_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme")
SECRET_KEY       = os.environ.get("SECRET_KEY", "change-me-in-production")
TOKEN_TTL_HOURS  = 24 * 7  # 7 days


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def _make_token(username: str) -> str:
    rand    = secrets.token_hex(32)
    exp     = (datetime.utcnow() + timedelta(hours=TOKEN_TTL_HOURS)).isoformat()
    payload = json.dumps({"u": username, "r": rand, "exp": exp})
    sig     = hmac.new(SECRET_KEY.encode(), f"{username}:{rand}".encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(payload.encode()).decode() + "." + sig


def _verify_token(token: str) -> Optional[str]:
    try:
        parts = token.rsplit(".", 1)
        if len(parts) != 2:
            return None
        payload_b64, sig = parts
        padding = 4 - len(payload_b64) % 4
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * padding).decode())
        username = payload["u"]
        rand     = payload["r"]
        exp      = datetime.fromisoformat(payload["exp"])
        if datetime.utcnow() > exp:
            return None
        expected = hmac.new(SECRET_KEY.encode(), f"{username}:{rand}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        return username
    except Exception:
        return None


def _get_stored_password(db: Session) -> Optional[str]:
    try:
        from app.models.setting import Setting
        s = db.query(Setting).filter(Setting.key == "admin_password_hash").first()
        return s.value if s else None
    except Exception:
        return None


def _set_stored_password(db: Session, password: str):
    from app.models.setting import Setting
    try:
        s = db.query(Setting).filter(Setting.key == "admin_password_hash").first()
        if s:
            s.value = _hash_password(password)
        else:
            db.add(Setting(key="admin_password_hash", value=_hash_password(password)))
        db.commit()
    except Exception as e:
        db.rollback()
        raise e


# — Auth dependency for other routes ————————————————————

def get_current_user(authorization: Optional[str] = Header(default=None)) -> Optional[str]:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    return _verify_token(authorization.split(" ", 1)[1])


# — Request models ——————————————————————————————————————

class LoginRequest(BaseModel):
    username: str
    password: str

class ChangePasswordRequest(BaseModel):
    token: str
    new_password: str


# — Routes ——————————————————————————————————————————————

@router.post("/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    if payload.username.lower() != DEFAULT_USERNAME:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    stored_hash = _get_stored_password(db)

    if stored_hash:
        if _hash_password(payload.password) != stored_hash:
            raise HTTPException(status_code=401, detail="Invalid username or password")
        return {"token": _make_token(payload.username), "must_change_password": False}
    else:
        if payload.password != DEFAULT_PASSWORD:
            raise HTTPException(status_code=401, detail="Invalid username or password")
        hardcoded_default = "changeme"
        must_change = (payload.password == hardcoded_default)
        return {"token": _make_token(payload.username), "must_change_password": must_change}


@router.post("/change-password")
def change_password(payload: ChangePasswordRequest, db: Session = Depends(get_db)):
    username = _verify_token(payload.token)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    if len(payload.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    _set_stored_password(db, payload.new_password)
    return {"ok": True}
