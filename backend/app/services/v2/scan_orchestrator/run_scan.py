# run_scan.py
#
# Entry point for V2 scan execution.
# Called by API layer. Delegates to the ScanOrchestrator.
#
# Flow: API endpoint → run_scan() → ScanOrchestrator → scan module → ScanResult

from app.models.v2.scan_request import ScanRequest
from app.models.v2.scan_result import ScanResult
from app.services.v2.scan_orchestrator.orchestrator import ScanOrchestrator

_orchestrator = ScanOrchestrator()


async def run_scan(scan_request: ScanRequest) -> ScanResult:
    """
    Entry point for V2 scan execution.
    Called by API endpoints.
    """
    return await _orchestrator.run(scan_request)