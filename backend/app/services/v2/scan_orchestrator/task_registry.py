# task_registry.py
#
# Orchestration-facing registry. Single source of truth for:
#   FAMILY_TASKS      — which task types belong to each scan family
#   TASK_SCANNER_MAP  — (task_type, platform) → scanner class
#
# To add a new family: add one FAMILY_TASKS entry + one TASK_SCANNER_MAP
# entry per task. No other files need to change.
#
# Platform resolution order:
#   1. Exact (task_type, platform)
#   2. Fallback (task_type, "global")
#   3. Neither → controlled task failure

from app.services.v2.authentication import AuthHealthAnalyzer
from app.services.v2.mail_routing.inbound_path_analyzer import InboundPathAnalyzer
from app.services.v2.mail_routing.connector_posture_analyzer import ConnectorPostureAnalyzer
from app.services.v2.mail_routing.direct_send_analyzer import DirectSendAnalyzer
from app.services.v2.tls_posture.mta_sts_analyzer import MtaStsAnalyzer, TlsrptAnalyzer
from app.services.v2.tls_posture.starttls_analyzer import (
    StarttlsAnalyzer, TlsConflictAnalyzer, DaneTlsaAnalyzer
)

# Lazy import for MXAnalyzer — not yet committed to repo
def _lazy(module_path: str, class_name: str):
    try:
        import importlib
        return getattr(importlib.import_module(module_path), class_name)
    except (ModuleNotFoundError, AttributeError):
        return None

_MXAnalyzer = _lazy("app.services.v2.exposure.mx_analysis", "MXAnalyzer")

# ---------------------------------------------------------------------------
# Family → task list
# ---------------------------------------------------------------------------

FAMILY_TASKS: dict[str, list[str]] = {

    # ── dns_posture ───────────────────────────────────────────────────────────
    "dns_posture": [
        "mx_health",
        "authentication_status",
        # "lookalike_scan",  # deferred — scanner not yet implemented
    ],

    # ── mail_routing_topology ─────────────────────────────────────────────────
    "mail_routing_topology": [
        "inbound_path_mapping",   # DNS-based: MX resolution, provider classification, path map
        "connector_posture",      # Tenant-authenticated: inbound/outbound connectors, transport rules
        "direct_send_check",      # Tenant-authenticated: SMTP AUTH, anonymous connectors, direct send
    ],

    # ── tls_posture ───────────────────────────────────────────────────────────
    "tls_posture": [
        "mta_sts_check",          # DNS + HTTPS: MTA-STS TXT record + policy file verification
        "tlsrpt_check",           # DNS: TLSRPT reporting record
        "starttls_probe",         # TCP: STARTTLS negotiation + cert inspection on each MX
        "tls_conflict_analysis",  # Cross-check: MTA-STS policy vs MX vs STARTTLS results
        "dane_tlsa_check",        # DNS: TLSA presence (full validation deferred — DNSSEC required)
    ],

    # ── Future families ───────────────────────────────────────────────────────
    # "smtp_bypass": [
    #     "direct_to_mx_exposure",
    #     "secondary_mx_bypass",
    #     "insecure_routing_path",
    #     "mailflow_gap_detection",
    # ],
    # "domain_reputation": [
    #     "blocklist_presence",
    #     "passive_reputation_signals",
    #     "age_and_registration_risk",
    # ],
    # "infrastructure_exposure": [
    #     "exposed_mail_hosts",
    #     "open_ports_mail_stack",
    #     "provider_fingerprint",
    # ],
}

# ---------------------------------------------------------------------------
# (task_type, platform) → scanner class
# ---------------------------------------------------------------------------

TASK_SCANNER_MAP: dict[tuple[str, str], type] = {

    # ── dns_posture tasks ─────────────────────────────────────────────────────
    **({
        ("mx_health", "global"):       _MXAnalyzer,
        ("mx_health", "microsoft365"): _MXAnalyzer,
    } if _MXAnalyzer else {}),

    ("authentication_status", "global"):             AuthHealthAnalyzer,
    ("authentication_status", "microsoft365"):       AuthHealthAnalyzer,
    ("authentication_status", "google_workspace"):   AuthHealthAnalyzer,

    # ── mail_routing_topology tasks ───────────────────────────────────────────
    ("inbound_path_mapping", "global"):              InboundPathAnalyzer,
    ("inbound_path_mapping", "microsoft365"):        InboundPathAnalyzer,
    ("inbound_path_mapping", "google_workspace"):    InboundPathAnalyzer,

    ("connector_posture", "global"):                 ConnectorPostureAnalyzer,
    ("connector_posture", "microsoft365"):           ConnectorPostureAnalyzer,

    ("direct_send_check", "global"):                 DirectSendAnalyzer,
    ("direct_send_check", "microsoft365"):           DirectSendAnalyzer,

    # ── tls_posture tasks ─────────────────────────────────────────────────────
    ("mta_sts_check", "global"):                     MtaStsAnalyzer,
    ("mta_sts_check", "microsoft365"):               MtaStsAnalyzer,
    ("mta_sts_check", "google_workspace"):           MtaStsAnalyzer,

    ("tlsrpt_check", "global"):                      TlsrptAnalyzer,
    ("tlsrpt_check", "microsoft365"):                TlsrptAnalyzer,
    ("tlsrpt_check", "google_workspace"):            TlsrptAnalyzer,

    ("starttls_probe", "global"):                    StarttlsAnalyzer,
    ("starttls_probe", "microsoft365"):              StarttlsAnalyzer,
    ("starttls_probe", "google_workspace"):          StarttlsAnalyzer,

    ("tls_conflict_analysis", "global"):             TlsConflictAnalyzer,
    ("tls_conflict_analysis", "microsoft365"):       TlsConflictAnalyzer,
    ("tls_conflict_analysis", "google_workspace"):   TlsConflictAnalyzer,

    ("dane_tlsa_check", "global"):                   DaneTlsaAnalyzer,
    ("dane_tlsa_check", "microsoft365"):             DaneTlsaAnalyzer,
    ("dane_tlsa_check", "google_workspace"):         DaneTlsaAnalyzer,
}


def resolve_scanner(task_type: str, platform: str):
    """
    Return the scanner class for (task_type, platform).
    Resolution: exact match → global fallback → None.
    """
    scanner = TASK_SCANNER_MAP.get((task_type, platform))
    if scanner is None and platform != "global":
        scanner = TASK_SCANNER_MAP.get((task_type, "global"))
    return scanner


def get_family_tasks(family: str) -> list[str]:
    """Return task list for a family, or [] if unregistered."""
    return FAMILY_TASKS.get(family, [])
