"""
Google Workspace OAuth2 onboarding flow.

Flow:
  1. GET  /api/v1/google/connect           — redirect to Google consent screen
  2. GET  /api/v1/google/callback          — exchange code for tokens, save tenant
  3. POST /api/v1/google/refresh/{tenant}  — refresh access token (called by scan engine)
"""
import os
import json
import urllib.parse
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.core.database import get_db, SessionLocal
from app.core.security import encrypt, decrypt
from app.models.tenant import Tenant
from app.api.auth import get_current_user
from typing import Optional

router = APIRouter()

# ── Config ─────────────────────────────────────────────────────────────────────
GWS_CLIENT_ID     = os.getenv("GWS_CLIENT_ID", "")
GWS_CLIENT_SECRET = os.getenv("GWS_CLIENT_SECRET", "")
GWS_REDIRECT_URI  = os.getenv("GWS_REDIRECT_URI", "")

GOOGLE_AUTH_URL  = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO  = "https://www.googleapis.com/oauth2/v3/userinfo"

# Admin SDK scopes needed for posture checks
SCOPES = [
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.domain.readonly",
    "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
    "openid",
    "email",
    "profile",
]


def _configured() -> bool:
    return bool(GWS_CLIENT_ID and GWS_CLIENT_SECRET and GWS_REDIRECT_URI)


@router.get("/connect")
async def gws_connect(request: Request):
    """Redirect browser to Google consent screen."""
    if not _configured():
        raise HTTPException(status_code=501, detail="Google Workspace OAuth not configured. Set GWS_CLIENT_ID, GWS_CLIENT_SECRET, GWS_REDIRECT_URI.")

    params = {
        "client_id":     GWS_CLIENT_ID,
        "redirect_uri":  GWS_REDIRECT_URI,
        "response_type": "code",
        "scope":         " ".join(SCOPES),
        "access_type":   "offline",   # get refresh token
        "prompt":        "consent",   # always show consent to get refresh token
        "hd":            "*",         # restrict to Workspace domains
    }
    url = GOOGLE_AUTH_URL + "?" + urllib.parse.urlencode(params)
    return RedirectResponse(url)


@router.get("/callback")
async def gws_callback(
    request: Request,
    code: str = None,
    error: str = None,
    db: Session = Depends(get_db),
):
    """Handle Google OAuth callback, exchange code for tokens, register tenant."""
    # Derive frontend base from the request if FRONTEND_URL not explicitly set
    frontend = os.getenv("FRONTEND_URL", "").rstrip("/")
    if not frontend:
        base = str(request.base_url).rstrip("/")
        # Strip port if it's standard https
        frontend = base

    if error or not code:
        return RedirectResponse(f"{frontend}/?gws_error={error or 'no_code'}")

    if not _configured():
        return RedirectResponse(f"{frontend}/?gws_error=not_configured")

    # Exchange code for tokens
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(GOOGLE_TOKEN_URL, data={
            "code":          code,
            "client_id":     GWS_CLIENT_ID,
            "client_secret": GWS_CLIENT_SECRET,
            "redirect_uri":  GWS_REDIRECT_URI,
            "grant_type":    "authorization_code",
        })

    if token_resp.status_code != 200:
        return RedirectResponse(f"{frontend}/?gws_error=token_exchange_failed")

    tokens = token_resp.json()
    access_token  = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")

    if not access_token:
        return RedirectResponse(f"{frontend}/?gws_error=no_access_token")

    # Get user info to determine domain
    async with httpx.AsyncClient() as client:
        info_resp = await client.get(
            GOOGLE_USERINFO,
            headers={"Authorization": f"Bearer {access_token}"}
        )

    if info_resp.status_code != 200:
        return RedirectResponse(f"{frontend}/?gws_error=userinfo_failed")

    info = info_resp.json()
    email  = info.get("email", "")
    domain = email.split("@")[-1] if "@" in email else ""
    name   = info.get("name") or info.get("hd") or domain

    if not domain:
        return RedirectResponse(f"{frontend}/?gws_error=no_domain")

    # Upsert — if a tenant with this domain already exists (e.g. M365 already connected),
    # add GWS credentials to it rather than creating a duplicate
    tenant = db.query(Tenant).filter(Tenant.domain == domain).first()
    if tenant:
        if refresh_token:
            tenant.gws_refresh_token = encrypt(refresh_token)
        # Update display name only if not already set from M365
        if not tenant.display_name or tenant.display_name == domain:
            tenant.display_name = name
        db.commit()
    else:
        tenant = Tenant(
            display_name      = name,
            tenant_id         = None,
            domain            = domain,
            client_id         = None,
            client_secret     = None,
            gws_refresh_token = encrypt(refresh_token) if refresh_token else None,
        )
        db.add(tenant)
        db.commit()
        db.refresh(tenant)

    return RedirectResponse(f"{frontend}/?gws_connected=1&tenant_id={tenant.id}")


async def get_gws_access_token(tenant: Tenant) -> Optional[str]:
    """Get a fresh GWS access token using the stored refresh token."""
    if not tenant.gws_refresh_token:
        return None

    refresh_token = decrypt(tenant.gws_refresh_token)

    async with httpx.AsyncClient() as client:
        resp = await client.post(GOOGLE_TOKEN_URL, data={
            "client_id":     GWS_CLIENT_ID,
            "client_secret": GWS_CLIENT_SECRET,
            "refresh_token": refresh_token,
            "grant_type":    "refresh_token",
        })

    print(f"[gws] token refresh status={resp.status_code}", flush=True)
    if resp.status_code != 200:
        print(f"[gws] token refresh failed: {resp.text[:200]}", flush=True)
        return None

    token = resp.json().get("access_token")
    print(f"[gws] token refresh ok, token present={bool(token)}", flush=True)
    return token
