# module_registry.py
#
# Scan modules register themselves here.
# Key: (family, platform) tuple
# Value: module class with an async run(request) -> ScanResult method
from app.services.v2.public_intel.microsoft365 import M365TenantDiscovery
from app.services.v2.exposure.mx_analysis import MXAnalyzer
from app.services.v2.authentication import AuthHealthAnalyzer

REGISTERED_MODULES: dict = {
    ("public_intel",    "microsoft365"): M365TenantDiscovery,
    ("exposure",        "microsoft365"): MXAnalyzer,
    # Authentication health is DNS-based and platform-agnostic
    ("authentication",  "global"):       AuthHealthAnalyzer,
    ("authentication",  "microsoft365"): AuthHealthAnalyzer,
    ("authentication",  "google_workspace"): AuthHealthAnalyzer,
    # Stubs — register as modules are implemented
    # ("public_intel", "google_workspace"): GWSTenantDiscovery,
    # ("posture",       "microsoft365"):    M365PostureScanner,
    # ("lookalike",     "global"):          LookalikeScanner,
}

def get_module(family: str, platform: str):
    """
    Returns the registered module class for the given family/platform pair.
    Returns None if no module is registered.
    """
    return REGISTERED_MODULES.get((family, platform))
