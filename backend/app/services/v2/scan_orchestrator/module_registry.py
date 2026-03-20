# module_registry.py
#
# TRANSITIONAL — direct-execution compatibility only.
# This registry serves the legacy run_scan() path used by the direct V2 family
# GET endpoints. It is NOT the authoritative registry for orchestrated jobs.
# The orchestration-facing registry is task_registry.py.
#
# When the direct-execution GET endpoints are retired, this file will be deleted.
#
# M365TenantDiscovery and MXAnalyzer are imported lazily to avoid crashing the
# app at startup when those modules have not yet been committed to the repo.

from app.services.v2.authentication import AuthHealthAnalyzer


def _lazy_import(module_path: str, class_name: str):
    """Import a class lazily; return None if the module is not yet available."""
    try:
        import importlib
        mod = importlib.import_module(module_path)
        return getattr(mod, class_name)
    except (ModuleNotFoundError, AttributeError):
        return None


_MXAnalyzer          = _lazy_import("app.services.v2.exposure.mx_analysis", "MXAnalyzer")
_M365TenantDiscovery = _lazy_import("app.services.v2.public_intel.microsoft365", "M365TenantDiscovery")

REGISTERED_MODULES: dict = {}

if _M365TenantDiscovery:
    REGISTERED_MODULES[("public_intel", "microsoft365")] = _M365TenantDiscovery

if _MXAnalyzer:
    REGISTERED_MODULES[("exposure", "microsoft365")] = _MXAnalyzer

# Authentication health is DNS-based and platform-agnostic
REGISTERED_MODULES.update({
    ("authentication", "global"):            AuthHealthAnalyzer,
    ("authentication", "microsoft365"):      AuthHealthAnalyzer,
    ("authentication", "google_workspace"):  AuthHealthAnalyzer,
})


def get_module(family: str, platform: str):
    """
    Returns the registered module class for the given family/platform pair.
    Returns None if no module is registered.
    """
    return REGISTERED_MODULES.get((family, platform))
