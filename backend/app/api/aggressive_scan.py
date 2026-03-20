from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime, timezone, timedelta
import traceback
from pydantic import BaseModel, Field

from app.core.database import get_db, SessionLocal
from app.core.auth import get_current_user
from app.core.config import settings
from app.models.tenant import Tenant
from app.models.aggressive_scan import AggressiveScan, AggressiveScanStatus
from app.services.aggressive_lookalike import run_aggressive_scan
from app.services.reputation import reputation_service

router = APIRouter()


class ReputationBatchRequest(BaseModel):
    root_domain: Optional[str] = None
    domains: dict[str, list[str]] = Field(default_factory=dict)


def _et_now():
    return datetime.now(timezone.utc).astimezone(timezone(timedelta(hours=-5)))


async def _run_aggressive_task(scan_id: str, user_id: Optional[str]):
    """Background task — own DB session, same pattern as _run_scan_task in scans.py."""
    db = SessionLocal()
    try:
        scan = db.query(AggressiveScan).filter(AggressiveScan.id == scan_id).first()
        if not scan:
            return

        scan.status = AggressiveScanStatus.running
        db.commit()

        # Collect all domains from all tenants visible to this user
        q = db.query(Tenant)
        if settings.multi_tenant_mode and user_id:
            q = q.filter(Tenant.user_id == user_id)
        tenants = q.all()

        domains = []
        for t in tenants:
            all_d = t.all_domains if t.all_domains else [t.domain]
            domains.extend(all_d)
        domains = list(set(d.strip().lower() for d in domains if d and d.strip()))

        if not domains:
            scan.status      = AggressiveScanStatus.failed
            scan.error       = "No domains found across connected tenants."
            scan.finished_at = _et_now()
            db.commit()
            return

        scan.domains = domains
        db.commit()

        results = await run_aggressive_scan(domains)

        scan.results     = results
        scan.status      = AggressiveScanStatus.completed
        scan.finished_at = _et_now()
        db.commit()

    except Exception as e:
        tb = traceback.format_exc()
        print(f"[aggressive_scan] {scan_id} failed: {e}\n{tb}", flush=True)
        try:
            scan = db.query(AggressiveScan).filter(AggressiveScan.id == scan_id).first()
            if scan:
                scan.status      = AggressiveScanStatus.failed
                scan.error       = f"{e}\n{tb}"
                scan.finished_at = _et_now()
                db.commit()
        except Exception as e2:
            print(f"[aggressive_scan] Failed to save error: {e2}", flush=True)
    finally:
        db.close()


@router.post("/trigger", status_code=202)
async def trigger_aggressive_scan(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user_id: Optional[str] = Depends(get_current_user),
):
    scan = AggressiveScan()
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_run_aggressive_task, scan.id, user_id)
    return {"id": scan.id, "status": scan.status}


@router.get("/status/{scan_id}")
def aggressive_scan_status(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(AggressiveScan).filter(AggressiveScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return {
        "id":          scan.id,
        "status":      scan.status,
        "domains":     scan.domains,
        "started_at":  scan.started_at,
        "finished_at": scan.finished_at,
        "error":       scan.error,
    }


@router.get("/result/{scan_id}")
def get_aggressive_result(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(AggressiveScan).filter(AggressiveScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return {
        "id":          scan.id,
        "status":      scan.status,
        "domains":     scan.domains,
        "results":     scan.results or [],
        "started_at":  scan.started_at,
        "finished_at": scan.finished_at,
        "error":       scan.error,
    }


@router.get("/latest")
def get_latest_aggressive_scan(db: Session = Depends(get_db)):
    """Return the most recent completed aggressive scan, or 404 if none exists."""
    scan = (
        db.query(AggressiveScan)
        .filter(AggressiveScan.status == AggressiveScanStatus.completed)
        .order_by(AggressiveScan.finished_at.desc())
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="No completed scan found.")
    return {
        "id":          scan.id,
        "status":      scan.status,
        "domains":     scan.domains,
        "results":     scan.results or [],
        "started_at":  scan.started_at,
        "finished_at": scan.finished_at,
        "error":       scan.error,
    }


@router.post("/reputation")
async def get_reputation_batch(payload: ReputationBatchRequest):
    return await reputation_service.summarize_many(payload.domains, root_domain=payload.root_domain)
