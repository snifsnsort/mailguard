from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta

def _et_now():
    return datetime.now(timezone.utc).astimezone(timezone(timedelta(hours=-5)))

from app.core.database import get_db
from app.models.scan import Scan, ScanStatus
from app.models.tenant import Tenant
from app.services.report_generator import generate_report

router = APIRouter()


@router.get("/{scan_id}/pdf")
def download_pdf_report(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if scan.status != ScanStatus.completed:
        raise HTTPException(status_code=400, detail="Scan not yet completed.")

    tenant = db.query(Tenant).filter(Tenant.id == scan.tenant_id).first()

    tenant_dict = {
        "display_name": tenant.display_name if tenant else "Unknown",
        "domain":       tenant.domain       if tenant else "Unknown",
        "extra_domains": tenant.extra_domains if tenant else [],
    }
    scan_dict = {
        "score":             scan.score,
        "grade":             scan.grade,
        "findings":          scan.findings or [],
        "penalty_breakdown": scan.penalty_breakdown or [],
        "domains_scanned":   scan.domains_scanned or [],
        "platform":          "Microsoft 365",  # TODO: persist platform in scan model
    }

    pdf_bytes = generate_report(tenant_dict, scan_dict)
    filename  = f"mailguard-report-{_et_now().strftime('%Y%m%d-%H%M')}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
