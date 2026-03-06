#!/usr/bin/env python
"""
Application startup — initialises DB, seeds tenant from env if needed, launches uvicorn.

If SEED_TENANT_* env vars are set and the tenants table is empty on boot,
the tenant is automatically registered. This ensures the app is always
functional after a container restart without manual re-registration.
"""
import os
import uuid
from app.core.database import init_db, SessionLocal
from app.core.security import encrypt


def seed_tenant():
    """Auto-register a tenant from environment variables if DB is empty."""
    # All fields required — skip silently if any are missing
    required = [
        "SEED_TENANT_NAME",
        "SEED_TENANT_ID",
        "SEED_TENANT_DOMAIN",
        "SEED_CLIENT_ID",
        "SEED_CLIENT_SECRET",
    ]
    if not all(os.environ.get(k) for k in required):
        return

    from app.models.tenant import Tenant
    db = SessionLocal()
    try:
        domain = os.environ["SEED_TENANT_DOMAIN"]
        gws_token = os.environ.get("SEED_GWS_REFRESH_TOKEN", "")

        existing = db.query(Tenant).filter(Tenant.domain == domain, Tenant.client_id != None).first()
        if existing:
            # Already seeded — but ensure M365 creds are up to date
            if not existing.tenant_id:
                existing.tenant_id    = os.environ["SEED_TENANT_ID"]
                existing.client_id    = os.environ["SEED_CLIENT_ID"]
                existing.client_secret= encrypt(os.environ["SEED_CLIENT_SECRET"])
                db.commit()
                print(f"[startup] Updated M365 credentials on existing tenant '{existing.display_name}'")
            # Re-seed GWS token if provided and not already set
            if gws_token and not existing.gws_refresh_token:
                existing.gws_refresh_token = encrypt(gws_token)
                db.commit()
                print(f"[startup] Restored GWS refresh token for '{existing.display_name}'")
            return

        # Check if a GWS-only tenant exists for this domain — if so, add M365 creds to it
        gws_tenant = db.query(Tenant).filter(Tenant.domain == domain).first()
        if gws_tenant:
            print(f"[startup] Adding M365 credentials to existing GWS tenant '{gws_tenant.display_name}'...")
            gws_tenant.tenant_id    = os.environ["SEED_TENANT_ID"]
            gws_tenant.client_id    = os.environ["SEED_CLIENT_ID"]
            gws_tenant.client_secret= encrypt(os.environ["SEED_CLIENT_SECRET"])
            if not gws_tenant.display_name or gws_tenant.display_name == domain:
                gws_tenant.display_name = os.environ["SEED_TENANT_NAME"]
            if gws_token and not gws_tenant.gws_refresh_token:
                gws_tenant.gws_refresh_token = encrypt(gws_token)
                print(f"[startup] Restored GWS refresh token for '{gws_tenant.display_name}'")
            db.commit()
            print(f"[startup] M365 credentials added to '{gws_tenant.display_name}'")
            return

        print("[startup] Seeding tenant from environment variables...")
        tenant = Tenant(
            id=str(uuid.uuid4()),
            display_name=os.environ["SEED_TENANT_NAME"],
            tenant_id=os.environ["SEED_TENANT_ID"],
            domain=os.environ["SEED_TENANT_DOMAIN"],
            client_id=os.environ["SEED_CLIENT_ID"],
            client_secret=encrypt(os.environ["SEED_CLIENT_SECRET"]),
            gws_refresh_token=encrypt(gws_token) if gws_token else None,
            is_active=True,
        )
        db.add(tenant)
        db.commit()
        print(f"[startup] Tenant '{tenant.display_name}' registered (id={tenant.id})")
    except Exception as e:
        print(f"[startup] Tenant seeding failed: {e}")
        db.rollback()
    finally:
        db.close()


def seed_admin_password():
    """If ADMIN_PASSWORD env var is set, ensure it's stored in the DB on every startup.
    This means changing ADMIN_PASSWORD in Azure env vars persists the new password."""
    password = os.environ.get("ADMIN_PASSWORD", "")
    if not password or password == "changeme":
        return  # Don't persist the default password

    from app.models.setting import Setting
    import hashlib
    db = SessionLocal()
    try:
        hashed = hashlib.sha256(password.encode()).hexdigest()
        s = db.query(Setting).filter(Setting.key == "admin_password_hash").first()
        if s:
            if s.value != hashed:
                s.value = hashed
                db.commit()
                print("[startup] Admin password updated from ADMIN_PASSWORD env var")
        else:
            db.add(Setting(key="admin_password_hash", value=hashed))
            db.commit()
            print("[startup] Admin password seeded from ADMIN_PASSWORD env var")
    except Exception as e:
        print(f"[startup] Admin password seeding failed: {e}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    import uvicorn
    init_db()
    seed_tenant()
    seed_admin_password()
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=False)
