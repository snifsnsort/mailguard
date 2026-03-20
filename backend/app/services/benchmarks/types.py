from dataclasses import dataclass, field
from typing import Any, Dict, List

from app.models.schemas import FindingResult


@dataclass
class ScanContext:
    tenant_id: str
    primary_domain: str
    domains: List[str] = field(default_factory=list)
    platform: str = ""
    findings: List[FindingResult] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
