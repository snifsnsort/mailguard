# scan_result.py
#
# Defines the output contract for a completed scan family run.
# The orchestrator collects ScanResults from each family.

from dataclasses import dataclass, field
from typing import List
from .finding import Finding

@dataclass
class ScanResult:
    scan_id: str
    tenant_id: str
    family: str                      # Which scan family produced this result
    findings: List[Finding] = field(default_factory=list)
    score: int = 0                   # 0-100, higher = more exposed / worse posture
    status: str = "pending"          # "pending", "running", "complete", "failed"
    timestamp: str = ""
    evidence: dict = field(default_factory=dict)  # Executive summary and raw signals