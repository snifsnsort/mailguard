from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional

from app.core.auth import get_current_user
from app.core.config import settings
from app.core.database import get_db
from app.models.scan import Scan
from app.models.scan_schedule import ScanSchedule
from app.models.schemas import ScanOut, ScanScheduleOut, ScanScheduleUpsert, ScanSummary
from app.models.tenant import Tenant
from app.services.scan_runner import create_pending_scan, run_scan_task
from app.services.scan_scheduler import apply_schedule_payload

router = APIRouter()


def _get_tenant(db: Session, tenant_id: str, user_id: Optional[str]) -> Tenant:
    q = db.query(Tenant).filter(Tenant.id == tenant_id)
    if settings.multi_tenant_mode and user_id:
        q = q.filter(Tenant.user_id == user_id)
    tenant = q.first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found.")
    return tenant


@router.post("/{tenant_id}/trigger", response_model=ScanSummary, status_code=202)
async def trigger_scan(
    tenant_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user_id: Optional[str] = Depends(get_current_user),
):
    tenant = _get_tenant(db, tenant_id, user_id)
    scan = create_pending_scan(db, tenant.id)
    background_tasks.add_task(run_scan_task, scan.id, tenant.id)
    return ScanSummary(
        id=scan.id,
        status=scan.status,
        score=None,
        grade=None,
        started_at=scan.started_at,
        finished_at=None,
    )


@router.get("/{tenant_id}/schedule", response_model=Optional[ScanScheduleOut])
def get_scan_schedule(
    tenant_id: str,
    db: Session = Depends(get_db),
    user_id: Optional[str] = Depends(get_current_user),
):
    tenant = _get_tenant(db, tenant_id, user_id)
    return db.query(ScanSchedule).filter(ScanSchedule.tenant_id == tenant.id).first()


@router.put("/{tenant_id}/schedule", response_model=ScanScheduleOut)
def upsert_scan_schedule(
    tenant_id: str,
    payload: ScanScheduleUpsert,
    db: Session = Depends(get_db),
    user_id: Optional[str] = Depends(get_current_user),
):
    tenant = _get_tenant(db, tenant_id, user_id)
    schedule = db.query(ScanSchedule).filter(ScanSchedule.tenant_id == tenant.id).first()
    if not schedule:
        schedule = ScanSchedule(tenant_id=tenant.id)
        db.add(schedule)

    try:
        apply_schedule_payload(schedule, payload.dict())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    db.commit()
    db.refresh(schedule)
    return schedule


@router.delete("/{tenant_id}/schedule", status_code=204)
def delete_scan_schedule(
    tenant_id: str,
    db: Session = Depends(get_db),
    user_id: Optional[str] = Depends(get_current_user),
):
    tenant = _get_tenant(db, tenant_id, user_id)
    schedule = db.query(ScanSchedule).filter(ScanSchedule.tenant_id == tenant.id).first()
    if schedule:
        db.delete(schedule)
        db.commit()
    return None


@router.get("/{tenant_id}/history", response_model=List[ScanSummary])
def scan_history(
    tenant_id: str,
    db: Session = Depends(get_db),
    user_id: Optional[str] = Depends(get_current_user),
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
        result.append(
            ScanSummary(
                id=s.id,
                status=s.status.value,
                score=s.score,
                grade=s.grade,
                started_at=s.started_at,
                finished_at=s.finished_at,
                critical=sum(1 for f in findings if f.get("status") == "fail"),
                warnings=sum(1 for f in findings if f.get("status") == "warn"),
                passing=sum(1 for f in findings if f.get("status") == "pass"),
            )
        )
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
