# run_scan.py
#
# TRANSITIONAL — direct-execution entry point used by the legacy V2 family
# GET endpoints in router.py. This path does NOT go through job creation or
# task persistence. It exists only to keep the existing direct-scan endpoints
# functional while pages are migrated to the jobs API.
#
# When all pages have migrated to the orchestrated jobs API, the direct-scan
# GET endpoints in router.py will be retired and this file will be deleted.

from app.models.v2.scan_request import ScanRequest
from app.models.v2.scan_result import ScanResult
from app.services.v2.scan_orchestrator.module_registry import get_module


async def run_scan(scan_request: ScanRequest) -> ScanResult:
    """
    Entry point for direct (non-orchestrated) V2 scan execution.

    Dispatches to the registered module for the first requested family.
    Returns a ScanResult dataclass. Does not create job or task records.
    """
    families = scan_request.families or []
    if not families:
        raise NotImplementedError("No scan families specified.")

    family = families[0]
    module_cls = get_module(family, scan_request.platform)

    if module_cls is None:
        # Also try global fallback
        module_cls = get_module(family, "global")

    if module_cls is None:
        raise NotImplementedError(
            f"No module registered for family='{family}' "
            f"platform='{scan_request.platform}'. "
            "This combination may not be implemented yet."
        )

    module = module_cls(scan_request.domain)
    return await module.run(scan_request)
