from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone, timedelta

def _et_now():
    return datetime.now(timezone.utc).astimezone(timezone(timedelta(hours=-5)))
import traceback, sys

from app.core.database import get_db, SessionLocal
from app.core.security import decrypt
from app.core.auth import get_current_user
from app.core.config import settings
from app.models.tenant import Tenant
from app.models.scan import Scan, ScanStatus
from app.models.schemas import ScanOut, ScanSummary
from app.services.scan_engine import ScanEngine

router = APIRouter()


def _get_tenant(db: Session, tenant_id: str, user_id: Optional[str]) -> Tenant:
    q = db.query(Tenant).filter(Tenant.id == tenant_id)
    if settings.MULTI_TENANT_MODE and user_id:
        q = q.filter(Tenant.user_id == user_id)
    tenant = q.first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found.")
    return tenant


async def _run_scan_task(scan_id: str, tenant_id: str):
    """Background task — creates its own DB session so the request session doesn't expire."""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        if not tenant:
            return

        scan.status = ScanStatus.running
        db.commit()

        # Get GWS access token if tenant has Google Workspace connected
        gws_token = None
        if tenant.has_gws:
            gws_token = await get_gws_access_token(tenant)

        engine = ScanEngine(
            tenant_id        = tenant.tenant_id or "",
            client_id        = tenant.client_id or "",
            client_secret    = decrypt(tenant.client_secret) if tenant.client_secret else "",
            domain           = tenant.domain,
            domains          = tenant.all_domains,
            gws_access_token = gws_token,
            has_m365         = tenant.has_m365,
            has_gws          = tenant.has_gws,
        )
        result = await engine.run()

        scan.score             = result["score"]
        scan.grade             = result["grade"]
        scan.findings          = result["findings"]
        scan.domains_scanned   = result.get("domains_scanned", [tenant.domain])
        scan.penalty_breakdown = result.get("penalty_breakdown", [])
        scan.status            = ScanStatus.completed
        scan.finished_at       = _et_now()

        tenant.last_scan_at = _et_now()
        db.commit()

    except Exception as e:
        tb = traceback.format_exc()
        print(f"[scan_error] Scan {scan_id} failed: {e}\n{tb}", flush=True)
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status      = ScanStatus.failed
                scan.error       = f"{e}\n{tb}"
                scan.finished_at = _et_now()
                db.commit()
        except Exception as e2:
            print(f"[scan_error] Failed to save error state: {e2}", flush=True)
    finally:
        db.close()


@router.post("/{tenant_id}/trigger", response_model=ScanSummary, status_code=202)
async def trigger_scan(
    tenant_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user_id: Optional[str] = Depends(get_current_user)
):
    tenant = _get_tenant(db, tenant_id, user_id)
    scan = Scan(tenant_id=tenant.id)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    # Pass only IDs — background task creates its own session
    background_tasks.add_task(_run_scan_task, scan.id, tenant.id)
    return ScanSummary(
        id=scan.id, status=scan.status, score=None, grade=None,
        started_at=scan.started_at, finished_at=None,
    )


@router.get("/{tenant_id}/history", response_model=List[ScanSummary])
def scan_history(
    tenant_id: str,
    db: Session = Depends(get_db),
    user_id: Optional[str] = Depends(get_current_user)
):
    tenant = _get_tenant(db, tenant_id, user_id)
    scans = (
        db.query(Scan)
        .filter(Scan.tenant_id == tenant.id)
        .order_by(Scan.started_at.desc())
        .limit(20)
        .all()
    )
    result = []
    for s in scans:
        findings = s.findings or []
        result.append(ScanSummary(
            id=s.id, status=s.status.value, score=s.score, grade=s.grade,
            started_at=s.started_at, finished_at=s.finished_at,
            critical=sum(1 for f in findings if f.get("status") == "fail"),
            warnings=sum(1 for f in findings if f.get("status") == "warn"),
            passing =sum(1 for f in findings if f.get("status") == "pass"),
        ))
    return result


@router.get("/result/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


@router.get("/status/{scan_id}")
def scan_status(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return {"id": scan.id, "status": scan.status, "score": scan.score, "grade": scan.grade, "error": scan.error}
