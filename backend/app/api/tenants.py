from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional

from app.core.database import get_db
from app.core.security import encrypt
from app.core.auth import get_current_user
from app.core.config import settings
from app.models.tenant import Tenant
from app.models.schemas import TenantCreate, TenantOut
from app.services.graph_client import GraphClient

router = APIRouter()


def _tenant_query(db: Session, user_id: Optional[str]):
    """Base query scoped to user in SaaS mode, all tenants in single-org mode."""
    q = db.query(Tenant).filter(Tenant.is_active == True)
    if settings.multi_tenant_mode and user_id:
        q = q.filter(Tenant.user_id == user_id)
    return q


@router.get("/", response_model=List[TenantOut])
def list_tenants(
    db: Session = Depends(get_db),
    user_id: Optional[str] = Depends(get_current_user)
):
    return _tenant_query(db, user_id).all()


@router.post("/", response_model=TenantOut, status_code=status.HTTP_201_CREATED)
async def create_tenant(
    payload: TenantCreate,
    db: Session = Depends(get_db),
    user_id: Optional[str] = Depends(get_current_user)
):
    try:
        client = GraphClient(payload.tenant_id, payload.client_id, payload.client_secret)
        await client._get_token()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Cannot authenticate with provided credentials: {e}")

    # In SaaS mode: same Azure tenant can exist for different users
    # In single-org mode: Azure tenant must be unique globally
    existing_q = db.query(Tenant).filter(Tenant.tenant_id == payload.tenant_id)
    if settings.multi_tenant_mode and user_id:
        existing_q = existing_q.filter(Tenant.user_id == user_id)
    if existing_q.first():
        raise HTTPException(status_code=409, detail="Tenant already registered.")

    tenant = Tenant(
        user_id       = user_id,
        display_name  = payload.display_name,
        tenant_id     = payload.tenant_id,
        domain        = payload.domain,
        extra_domains = payload.extra_domains or [],
        client_id     = payload.client_id,
        client_secret = encrypt(payload.client_secret),
    )
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return tenant


@router.post("/{tenant_id}/sync-domains", response_model=TenantOut)
async def sync_domains(
    tenant_id: str,
    db: Session = Depends(get_db),
    user_id: Optional[str] = Depends(get_current_user)
):
    """
    Auto-discover all verified domains from the Microsoft 365 tenant via Graph API
    and store them as extra_domains on the tenant record.
    Filters out *.onmicrosoft.com domains (internal routing only).
    """
    from app.core.security import decrypt
    t = _tenant_query(db, user_id).filter(Tenant.id == tenant_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Tenant not found.")

    client = GraphClient(t.tenant_id, t.client_id, decrypt(t.client_secret))
    try:
        raw_domains = await client.get_domains()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Graph API domain fetch failed: {e}")

    discovered = []
    for d in raw_domains:
        name = d.get("id", "").lower().strip()
        if not name:
            continue
        # Skip onmicrosoft.com routing-only domains
        if name.endswith(".onmicrosoft.com"):
            continue
        # Only include verified domains
        if not d.get("isVerified", False):
            continue
        discovered.append(name)

    # Primary domain stays in t.domain; extras = everything else
    extras = [d for d in discovered if d != t.domain.lower()]

    t.extra_domains = extras
    db.commit()
    db.refresh(t)
    return t


@router.get("/{tenant_id}", response_model=TenantOut)
def get_tenant(
    tenant_id: str,
    db: Session = Depends(get_db),
    user_id: Optional[str] = Depends(get_current_user)
):
    t = _tenant_query(db, user_id).filter(Tenant.id == tenant_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Tenant not found.")
    return t


@router.delete("/{tenant_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_tenant(
    tenant_id: str,
    db: Session = Depends(get_db),
    user_id: Optional[str] = Depends(get_current_user)
):
    t = _tenant_query(db, user_id).filter(Tenant.id == tenant_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Tenant not found.")
    db.delete(t)
    db.commit()
