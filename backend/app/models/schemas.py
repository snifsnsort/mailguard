from pydantic import BaseModel, Field
from typing import Optional, List, Any
from datetime import datetime
from enum import Enum


# ── Tenant ────────────────────────────────────────────────────────────────────

class TenantCreate(BaseModel):
    display_name:  str        = Field(..., example="Contoso Ltd")
    tenant_id:     str        = Field(..., example="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
    domain:        str        = Field(..., example="contoso.com")
    extra_domains: List[str]  = Field(default_factory=list, example=["contoso.co.uk"])
    client_id:     str        = Field(..., example="yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy")
    client_secret: str        = Field(..., example="your-client-secret")


class TenantOut(BaseModel):
    id:            str
    display_name:  str
    domain:        str
    extra_domains: List[str]  = []
    tenant_id:     Optional[str] = None
    client_id:     Optional[str] = None
    has_m365:      bool = False
    has_gws:       bool = False
    is_active:     bool
    created_at:    datetime
    last_scan_at:  Optional[datetime]

    class Config:
        from_attributes = True


# ── Findings ──────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    critical = "critical"
    warning  = "warning"
    pass_    = "pass"
    info     = "info"


class FindingResult(BaseModel):
    check_id:       str
    name:           str
    category:       str
    severity:       Severity
    status:         str          # fail | warn | pass
    description:    str
    current_value:  Any
    expected_value: Any
    remediation:    List[str]
    reference_url:  str
    benchmark:      str
    # Set for domain-scoped checks (SPF, DKIM, DMARC, MX, lookalike).
    # None for tenant-wide checks (MFA, legacy auth, Safe Links policy, etc.)
    domain:         Optional[str] = None


# ── Scan ──────────────────────────────────────────────────────────────────────

class ScanOut(BaseModel):
    id:                str
    tenant_id:         str
    status:            str
    score:             Optional[int]
    grade:             Optional[str]
    findings:          List[FindingResult]
    domains_scanned:   List[str]  = []
    penalty_breakdown: List[Any]  = []   # [{check_id, name, status, penalty_applied, max_penalty}]
    error:             Optional[str]
    started_at:        datetime
    finished_at:       Optional[datetime]

    class Config:
        from_attributes = True


class ScanSummary(BaseModel):
    id:          str
    status:      str
    score:       Optional[int]
    grade:       Optional[str]
    started_at:  datetime
    finished_at: Optional[datetime]
    critical:    int = 0
    warnings:    int = 0
    passing:     int = 0

    class Config:
        from_attributes = True
