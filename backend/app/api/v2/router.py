# router.py
#
# MailGuard V2 API router.
# Mount this in the main FastAPI app with:
#
#   from app.api.v2.router import v2_router
#   app.include_router(v2_router, prefix="/api/v2")

import dataclasses
from fastapi import APIRouter, HTTPException, Query

from app.models.v2.scan_request import ScanRequest
from app.services.v2.scan_orchestrator.run_scan import run_scan

v2_router = APIRouter(tags=["v2"])


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@v2_router.get("/health")
async def v2_health():
    """V2 API health check."""
    return {"status": "ok", "version": "v2"}


# ---------------------------------------------------------------------------
# Public Tenant Intelligence
# ---------------------------------------------------------------------------

@v2_router.get("/public-intel/{domain}")
async def get_public_tenant_intel(
    domain: str,
    platform: str = Query(default="microsoft365"),
):
    """
    Discover public Microsoft 365 tenant intelligence for the given domain.
    """
    domain = domain.strip().lower()
    if not domain or "." not in domain:
        raise HTTPException(status_code=422, detail="Invalid domain.")

    request = ScanRequest(
        domain=domain,
        platform=platform,
        families=["public_intel"],
    )
    return await _run_and_serialize(request)


# ---------------------------------------------------------------------------
# Exposure — MX Analysis
# ---------------------------------------------------------------------------

@v2_router.get("/exposure/mx/{domain}")
async def get_mx_exposure(
    domain: str,
    platform: str = Query(default="microsoft365"),
):
    """
    Resolve and classify MX records for a domain.

    Returns routing posture, detected providers, and exposure findings.

    Example:
        GET /api/v2/exposure/mx/pfptdev.com
        GET /api/v2/exposure/mx/contoso.com
    """
    domain = domain.strip().lower()
    if not domain or "." not in domain:
        raise HTTPException(status_code=422, detail="Invalid domain.")

    request = ScanRequest(
        domain=domain,
        platform=platform,
        families=["exposure"],
    )
    return await _run_and_serialize(request)


# ---------------------------------------------------------------------------
# Authentication Health — SPF / DKIM / DMARC
# ---------------------------------------------------------------------------

@v2_router.get("/authentication/{domain}")
async def get_authentication_health(
    domain: str,
    platform: str = Query(
        default="global",
        description="Platform context — authentication checks are DNS-based and platform-agnostic.",
    ),
):
    """
    Evaluate email authentication posture (SPF, DKIM, DMARC) for a domain.

    Returns a health score, per-protocol analysis, security findings, and
    raw DNS evidence. Checks are platform-agnostic — results are identical
    regardless of whether the domain uses Microsoft 365 or Google Workspace.

    Example:
        GET /api/v2/authentication/pfptdev.com
        GET /api/v2/authentication/cloud4you.ca
    """
    domain = domain.strip().lower()
    if not domain or "." not in domain:
        raise HTTPException(status_code=422, detail="Invalid domain.")

    request = ScanRequest(
        domain=domain,
        platform=platform,
        families=["authentication"],
    )
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
