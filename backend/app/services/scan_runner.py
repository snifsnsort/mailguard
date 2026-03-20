import traceback
from datetime import datetime, timezone, timedelta

from sqlalchemy.orm import Session

from app.api.google_auth import get_gws_access_token
from app.core.database import SessionLocal
from app.core.security import decrypt
from app.models.scan import Scan, ScanStatus
from app.models.tenant import Tenant
from app.services.scan_engine import ScanEngine


def et_now():
    return datetime.now(timezone.utc).astimezone(timezone(timedelta(hours=-5)))


def create_pending_scan(db: Session, tenant_id: str) -> Scan:
    scan = Scan(tenant_id=tenant_id)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


async def run_scan_task(scan_id: str, tenant_id: str):
    """Background task — creates its own DB session so the caller session can close safely."""
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

        gws_token = None
        if tenant.has_gws:
            gws_token = await get_gws_access_token(tenant)

        engine = ScanEngine(
            tenant_id=tenant.tenant_id or "",
            client_id=tenant.client_id or "",
            client_secret=decrypt(tenant.client_secret) if tenant.client_secret else "",
            domain=tenant.domain,
            domains=tenant.all_domains,
            gws_access_token=gws_token,
            has_m365=tenant.has_m365,
            has_gws=tenant.has_gws,
        )
        result = await engine.run()

        scan.score = result["score"]
        scan.grade = result["grade"]
        scan.platform = result.get("platform")
        scan.findings = result["findings"]
        scan.benchmark_results = result.get("benchmark_results", [])
        scan.benchmark_findings = result.get("benchmark_findings", {})
        scan.domains_scanned = result.get("domains_scanned", [tenant.domain])
        scan.penalty_breakdown = result.get("penalty_breakdown", [])
        scan.status = ScanStatus.completed
        scan.finished_at = et_now()

        tenant.last_scan_at = et_now()
        db.commit()

    except Exception as exc:
        tb = traceback.format_exc()
        print(f"[scan_error] Scan {scan_id} failed: {exc}\n{tb}", flush=True)
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.failed
                scan.error = f"{exc}\n{tb}"
                scan.finished_at = et_now()
                db.commit()
        except Exception as save_exc:
            print(f"[scan_error] Failed to save error state: {save_exc}", flush=True)
    finally:
        db.close()
