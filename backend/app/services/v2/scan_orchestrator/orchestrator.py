# orchestrator.py
#
# Coordinates scan execution for a given ScanRequest.
# Dispatches to the registered module for the requested family and platform.

import uuid
import datetime

from app.models.v2.scan_request import ScanRequest
from app.models.v2.scan_result import ScanResult
from app.services.v2.scan_orchestrator.module_registry import get_module
from app.services.v2.scan_orchestrator.scan_families import ALL_FAMILIES


class ScanOrchestrator:
    """
    Routes a ScanRequest to the appropriate registered module and returns a ScanResult.
    """

    async def run(self, request: ScanRequest) -> ScanResult:
        # Determine which families to run — default to all in request, or derive from request
        families = request.families if request.families else self._infer_families(request)

        if not families:
            return self._error_result(request, "No scan families specified or registered for this request.")

        # For this slice: run the first requested family only
        # Multi-family orchestration is a future improvement
        family = families[0]

        module_cls = get_module(family, request.platform)
        if module_cls is None:
            return self._error_result(
                request,
                f"No module registered for family='{family}' platform='{request.platform}'. "
                "This combination may not be implemented yet."
            )

        module   = module_cls(request.domain)
        result   = await module.run(request)
        return result

    def _infer_families(self, request: ScanRequest) -> list:
        # If no families specified, return empty — caller must be explicit
        return []

    def _error_result(self, request: ScanRequest, message: str) -> ScanResult:
        return ScanResult(
            scan_id=str(uuid.uuid4()),
            tenant_id=request.tenant_id or request.domain,
            family="unknown",
            findings=[],
            score=0,
            status="failed",
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            evidence={"error": message, "domain": request.domain},
        )