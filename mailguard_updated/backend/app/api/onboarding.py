from fastapi import APIRouter, Query
from fastapi.responses import RedirectResponse
from app.services.onboarding import generate_auth_url, exchange_code_for_token, provision_tenant
from app.core.database import get_db
from app.models.tenant import Tenant
from sqlalchemy.orm import Session
from fastapi import Depends
import logging
import asyncio

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/auth/start")
async def auth_start():
    """Redirect to Microsoft admin consent screen."""
    try:
        auth_url, state = generate_auth_url()
        return RedirectResponse(auth_url)
    except RuntimeError as e:
        return RedirectResponse(f"/?onboard_error=config_error&detail={str(e)}")


@router.get("/auth/callback")
async def auth_callback(
    code: str = Query(None),
    state: str = Query(None),
    error: str = Query(None),
    error_description: str = Query(None),
    db: Session = Depends(get_db),
):
    """Handle Microsoft OAuth callback."""
    if error:
        logger.error(f"OAuth error: {error} - {error_description}")
        return RedirectResponse(f"/connect?onboard_error={error}&detail={error_description or ''}")

    if not code or not state:
        return RedirectResponse("/connect?onboard_error=missing_params")

    try:
        # Exchange code for token
        token_data, tenant_id = await exchange_code_for_token(code, state)
        access_token = token_data["access_token"]

        # Check if tenant already exists
        existing = db.query(Tenant).filter(Tenant.tenant_id == tenant_id).first()
        if existing:
            logger.info(f"Tenant {tenant_id} already exists, skipping provisioning")
            return RedirectResponse(f"/?onboard_success=already_exists&domain={existing.domain}")

        # Provision tenant using our app directly
        tenant_info = await provision_tenant(access_token, tenant_id)

        # Save tenant
        tenant = Tenant(
            display_name=tenant_info["display_name"],
            tenant_id=tenant_info["tenant_id"],
            domain=tenant_info["domain"],
            client_id=tenant_info["client_id"],
            client_secret=tenant_info["client_secret"],
            is_active=True,
        )
        db.add(tenant)
        db.commit()
        db.refresh(tenant)

        logger.info(f"Successfully onboarded tenant {tenant_info['domain']}")

        # Trigger first scan in background
        async def run_first_scan():
            await asyncio.sleep(3)  # let the DB commit settle
            try:
                from app.models.scan import Scan as ScanModel
                from app.services.scan_engine import ScanEngine
                from app.core.security import decrypt

                scan = ScanModel(tenant_id=tenant.id)
                db.add(scan)
                db.commit()
                db.refresh(scan)

                scan.status = "running"
                db.commit()

                engine = ScanEngine(
                    tenant_id     = tenant.tenant_id,
                    client_id     = tenant.client_id,
                    client_secret = decrypt(tenant.client_secret),
                    domain        = tenant.domain,
                    domains       = tenant.all_domains,
                )
                result = await engine.run()

                scan.score             = result["score"]
                scan.grade             = result["grade"]
                scan.findings          = result["findings"]
                scan.domains_scanned   = result.get("domains_scanned", [tenant.domain])
                scan.penalty_breakdown = result.get("penalty_breakdown", [])
                scan.status            = "completed"
                from datetime import datetime
                scan.finished_at       = datetime.utcnow()
                tenant.last_scan_at    = datetime.utcnow()
                db.commit()

            except Exception as e:
                logger.error(f"First scan failed: {e}")

        asyncio.create_task(run_first_scan())

        return RedirectResponse(f"/?onboard_success=true&domain={tenant_info['domain']}")

    except Exception as e:
        logger.error(f"Onboarding failed: {e}", exc_info=True)
        return RedirectResponse(f"/connect?onboard_error=provision_failed&detail={str(e)}")
