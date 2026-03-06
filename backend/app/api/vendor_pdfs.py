"""
Vendor Best-Practices PDF Integration — Backend Stub

This module provides the placeholder API routes for a future feature:
  Upload a vendor security best-practices PDF (Mimecast, Barracuda, Cisco, etc.)
  and have MailGuard parse + evaluate the tenant's configuration against it.

Current state: STUB
  - Routes are registered and return 501 Not Implemented with a clear message
  - The data models and upload mechanics are fully specified so frontend can
    be built against them without waiting for the extraction engine
  - A basic file metadata store is included for when the feature ships

Future implementation plan:
  1. PDF text extraction (pdfplumber / PyMuPDF)
  2. LLM-assisted control extraction (Claude API) — parse vendor recommendations
     into a structured list of check_id → expected_value mappings
  3. Diff engine — compare extracted expectations against live scan findings
  4. Report overlay — findings page shows "Vendor Recommendation" badge on
     checks that appear in the uploaded PDF

To enable: set VENDOR_PDF_ENABLED=true in environment and implement
_extract_controls_from_pdf() in vendor_pdf_parser.py
"""

from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from fastapi.responses import JSONResponse
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel
import uuid
import os

from app.core.auth import get_current_user

router = APIRouter()

# ── Response models ────────────────────────────────────────────────────────────

class VendorPdfMeta(BaseModel):
    id:          str
    filename:    str
    vendor_hint: Optional[str]   # auto-detected vendor name (Mimecast, Barracuda, etc.)
    page_count:  Optional[int]
    uploaded_at: datetime
    status:      str             # "pending_parse" | "parsed" | "error"
    check_count: Optional[int]   # number of controls extracted (once parsed)
    description: str             # human-readable status message


class VendorPdfListResponse(BaseModel):
    docs: List[VendorPdfMeta]
    feature_enabled: bool
    message: str


FEATURE_ENABLED = os.environ.get("VENDOR_PDF_ENABLED", "false").lower() == "true"

SUPPORTED_VENDORS = [
    "Mimecast", "Barracuda", "Proofpoint", "Cisco Secure Email",
    "Sophos Email", "Broadcom/Symantec", "Trellix", "Trend Micro",
    "Forcepoint", "Check Point", "Hornetsecurity", "Microsoft Defender",
]

_STUB_DOCS: List[VendorPdfMeta] = []   # In-memory store for dev/demo


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.get("/vendor-pdfs", response_model=VendorPdfListResponse, tags=["Vendor PDFs"])
async def list_vendor_pdfs(user_id: Optional[str] = Depends(get_current_user)):
    """
    List all uploaded vendor best-practices PDFs.
    Returns feature status so the UI can show appropriate messaging.
    """
    return VendorPdfListResponse(
        docs=_STUB_DOCS,
        feature_enabled=FEATURE_ENABLED,
        message=(
            "Vendor PDF analysis is enabled."
            if FEATURE_ENABLED else
            "Vendor PDF analysis is coming soon. Upload your vendor's security "
            "best-practices guide and MailGuard will evaluate your configuration "
            "against it automatically. Supported vendors include: "
            + ", ".join(SUPPORTED_VENDORS) + "."
        ),
    )


@router.post("/vendor-pdfs/upload", tags=["Vendor PDFs"])
async def upload_vendor_pdf(
    file: UploadFile = File(...),
    user_id: Optional[str] = Depends(get_current_user),
):
    """
    Upload a vendor security best-practices PDF.

    STUB: Accepts the upload and returns a 501 with a friendly message.
    When VENDOR_PDF_ENABLED=true, this will:
      1. Validate the file is a PDF (≤ 50 MB)
      2. Store it in object storage (S3 / Azure Blob)
      3. Queue an async job to extract controls via PDF parser + LLM
      4. Return a job ID the frontend can poll
    """
    # Basic validation even in stub mode
    if not file.filename or not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are supported.")

    content = await file.read()
    if len(content) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File exceeds 50 MB limit.")

    if not FEATURE_ENABLED:
        # Log the intent — useful for prioritisation
        doc = VendorPdfMeta(
            id=str(uuid.uuid4()),
            filename=file.filename,
            vendor_hint=_guess_vendor(file.filename),
            page_count=None,
            uploaded_at=datetime.utcnow(),
            status="pending_parse",
            check_count=None,
            description=(
                "Your PDF has been received. Vendor PDF analysis is coming soon — "
                "we'll notify you when this feature is available. Your document "
                "will be analysed automatically once the feature launches."
            ),
        )
        _STUB_DOCS.append(doc)
        return JSONResponse(status_code=202, content={
            "id": doc.id,
            "status": "queued",
            "feature_enabled": False,
            "message": doc.description,
            "supported_vendors": SUPPORTED_VENDORS,
        })

    # ── Feature-enabled path (future implementation) ───────────────────────
    raise HTTPException(
        status_code=501,
        detail="PDF analysis engine not yet implemented. Set VENDOR_PDF_ENABLED=true to enable.",
    )


@router.delete("/vendor-pdfs/{doc_id}", status_code=204, tags=["Vendor PDFs"])
async def delete_vendor_pdf(
    doc_id: str,
    user_id: Optional[str] = Depends(get_current_user),
):
    """Remove an uploaded vendor PDF."""
    global _STUB_DOCS
    before = len(_STUB_DOCS)
    _STUB_DOCS = [d for d in _STUB_DOCS if d.id != doc_id]
    if len(_STUB_DOCS) == before:
        raise HTTPException(status_code=404, detail="Document not found.")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _guess_vendor(filename: str) -> Optional[str]:
    """Naive vendor detection from filename."""
    lower = filename.lower()
    vendor_keywords = {
        "Mimecast":      ["mimecast"],
        "Barracuda":     ["barracuda"],
        "Proofpoint":    ["proofpoint"],
        "Cisco":         ["cisco", "ironport"],
        "Sophos":        ["sophos"],
        "Broadcom":      ["broadcom", "symantec", "messagelabs"],
        "Trellix":       ["trellix", "fireeye"],
        "Trend Micro":   ["trendmicro", "trend-micro", "trend_micro"],
        "Forcepoint":    ["forcepoint"],
        "Check Point":   ["checkpoint", "check-point"],
        "Hornetsecurity":["hornetsecurity", "spamexperts"],
        "Microsoft":     ["microsoft", "defender", "m365"],
        "Google":        ["google", "workspace", "gws"],
    }
    for vendor, keywords in vendor_keywords.items():
        if any(k in lower for k in keywords):
            return vendor
    return None
