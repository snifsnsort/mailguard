# scan_request.py
#
# Defines the input contract for a V2 scan.
# All scan family modules receive a ScanRequest.

from dataclasses import dataclass, field

@dataclass
class ScanRequest:
    domain: str
    platform: str                    # "microsoft365" or "google_workspace"
    tenant_id: str = ""              # May be empty before discovery
    families: list = field(default_factory=list)  # Empty = all registered families