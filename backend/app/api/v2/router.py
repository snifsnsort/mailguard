# router.py
#
# MailGuard V2 API router.
# Mounts all V2 sub-routers and is registered in main.py at /api/v2.

import dataclasses
from fastapi import APIRouter, HTTPException, Query

from app.models.v2.scan_request import ScanRequest
from app.services.v2.scan_orchestrator.run_scan import run_scan
from app.api.v2.jobs import jobs_router

v2_router = APIRouter(tags=["v2"])

# Register jobs router (orchestrated scans)
v2_router.include_router(jobs_router)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@v2_router.get("/health")
async def v2_health():
    """V2 API health check."""
    return {"status": "ok", "version": "v2"}


# ---------------------------------------------------------------------------
# TRANSITIONAL — Direct-execution family endpoints
#
# These endpoints call scanners directly without creating job or task records.
# They exist only to keep existing page fetch() calls functional while pages
# are migrated to the orchestrated jobs API in the next block.
#
# Do not add new endpoints in this style.
# These will be retired when pages are migrated.
# ---------------------------------------------------------------------------

@v2_router.get("/public-intel/{domain}")
async def get_public_tenant_intel(
    domain: str,
    platform: str = Query(default="microsoft365"),
):
    """
    [TRANSITIONAL] Discover public tenant intelligence for the given domain.
    """
    domain = domain.strip().lower()
    if not domain or "." not in domain:
        raise HTTPException(status_code=422, detail="Invalid domain.")
    request = ScanRequest(domain=domain, platform=platform, families=["public_intel"])
    return await _run_and_serialize(request)


@v2_router.get("/exposure/mx/{domain}")
async def get_mx_exposure(
    domain: str,
    platform: str = Query(default="microsoft365"),
):
    """
    [TRANSITIONAL] Resolve and classify MX records for a domain.
    """
    domain = domain.strip().lower()
    if not domain or "." not in domain:
        raise HTTPException(status_code=422, detail="Invalid domain.")
    request = ScanRequest(domain=domain, platform=platform, families=["exposure"])
    return await _run_and_serialize(request)


@v2_router.get("/authentication/{domain}")
async def get_authentication_health(
    domain: str,
    platform: str = Query(default="global"),
):
    """
    [TRANSITIONAL] Evaluate authentication posture (SPF, DKIM, DMARC) for a domain.
    """
    domain = domain.strip().lower()
    if not domain or "." not in domain:
        raise HTTPException(status_code=422, detail="Invalid domain.")
    request = ScanRequest(domain=domain, platform=platform, families=["authentication"])
    return await _run_and_serialize(request)


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------

async def _run_and_serialize(request: ScanRequest) -> dict:
    try:
        result = await run_scan(request)
    except NotImplementedError as e:
        raise HTTPException(status_code=501, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
    return dataclasses.asdict(result)
