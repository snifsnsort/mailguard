from pydantic import BaseModel, Field
from typing import Optional, List, Any, Dict
from datetime import datetime
from enum import Enum


class TenantCreate(BaseModel):
    display_name: str = Field(..., example="Contoso Ltd")
    tenant_id: str = Field(..., example="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
    domain: str = Field(..., example="contoso.com")
    extra_domains: List[str] = Field(default_factory=list, example=["contoso.co.uk"])
    client_id: str = Field(..., example="yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy")
    client_secret: str = Field(..., example="your-client-secret")


class TenantOut(BaseModel):
    id: str
    display_name: str
    domain: str
    extra_domains: List[str] = Field(default_factory=list)
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    has_m365: bool = False
    has_gws: bool = False
    is_active: bool
    created_at: datetime
    last_scan_at: Optional[datetime]

    class Config:
        from_attributes = True


class Severity(str, Enum):
    critical = "critical"
    warning = "warning"
    pass_ = "pass"
    info = "info"


class FindingResult(BaseModel):
    check_id: str
    name: str
    category: str
    severity: Severity
    status: str
    description: str
    current_value: Any
    expected_value: Any
    remediation: List[str]
    reference_url: str
    benchmark: str
    domain: Optional[str] = None


class BenchmarkFinding(FindingResult):
    pass


class BenchmarkSummary(BaseModel):
    passed: int = 0
    failed: int = 0
    warning: int = 0
    not_applicable: int = 0
    not_implemented: int = 0


class BenchmarkRunResult(BaseModel):
    benchmark_key: str
    benchmark_name: str
    execution_status: str
    score: Optional[int] = None
    max_score: Optional[int] = None
    grade: Optional[str] = None
    summary: BenchmarkSummary = Field(default_factory=BenchmarkSummary)
    findings: List[BenchmarkFinding] = Field(default_factory=list)
    started_at: datetime
    completed_at: Optional[datetime] = None
    error: Optional[str] = None


class ScanOut(BaseModel):
    id: str
    tenant_id: str
    status: str
    score: Optional[int]
    grade: Optional[str]
    findings: List[FindingResult] = Field(default_factory=list)
    benchmark_results: List[BenchmarkRunResult] = Field(default_factory=list)
    benchmark_findings: Dict[str, List[BenchmarkFinding]] = Field(default_factory=dict)
    domains_scanned: List[str] = Field(default_factory=list)
    penalty_breakdown: List[Any] = Field(default_factory=list)
    error: Optional[str]
    started_at: datetime
    finished_at: Optional[datetime]

    class Config:
        from_attributes = True


class ScanSummary(BaseModel):
    id: str
    status: str
    score: Optional[int]
    grade: Optional[str]
    started_at: datetime
    finished_at: Optional[datetime]
    critical: int = 0
    warnings: int = 0
    passing: int = 0

    class Config:
        from_attributes = True


class ScanScheduleUpsert(BaseModel):
    frequency: str
    time_of_day: str
    timezone: str
    weekdays: List[str] = Field(default_factory=list)
    day_of_month: Optional[int] = None
    is_active: bool = True


class ScanScheduleOut(BaseModel):
    id: str
    tenant_id: str
    frequency: str
    time_of_day: str
    timezone: str
    weekdays: List[str] = Field(default_factory=list)
    day_of_month: Optional[int] = None
    is_active: bool
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
