"""
mx_analyzer.py — MailGuard V2 Exposure / MX Analysis

Improvements in this version:
  1. Score transparency — score_factors list returned in evidence
  2. Severity levels — info / medium / high per finding type
  3. Security-focused risk descriptions — real attack scenario language
  4. Expanded findings — multiple SEGs, excessive MX records
  5. Scan metadata — scan_type, resolver, duration_ms, module_version
  6. Structured routing_analysis block in evidence
  7. recommended_action populated on every Finding
  8. Standardized Finding schema (id, title, severity, description, recommended_action, evidence)

Findings emitted:
  exposure-mx-mx-records-{domain}       — INFO   resolved record summary
  exposure-mx-{routing_type}-{domain}   — varies routing posture
  exposure-mx-multi-seg-{domain}        — MEDIUM multiple SEGs detected
  exposure-mx-excessive-mx-{domain}     — INFO   >5 MX records
  exposure-mx-unresolvable-{host}       — HIGH   NXDOMAIN MX host
  exposure-mx-resolution-error-{host}   — MEDIUM DNS error on MX host
  exposure-mx-gslb-{host}               — INFO   multiple IPs (GSLB)
"""

import uuid
import time
import logging
from datetime import datetime, timezone
from typing import Any

import dns.resolver
import dns.exception

from app.models.v2.scan_request import ScanRequest
from app.models.v2.scan_result import ScanResult
from app.models.v2.finding import Finding

logger = logging.getLogger(__name__)

MODULE_VERSION = "v2.1"

# ---------------------------------------------------------------------------
# Provider classification
# ---------------------------------------------------------------------------

PROVIDER_PATTERNS: list[tuple[str, str]] = [
    ("pphosted.com",                "Proofpoint"),
    ("ppe-hosted.com",              "Proofpoint"),
    ("proofpoint.com",              "Proofpoint"),
    ("mail.protection.outlook.com", "Microsoft EOP"),
    ("outlook.com",                 "Microsoft EOP"),
    ("mimecast.com",                "Mimecast"),
    ("messagelabs.com",             "Symantec/Broadcom"),
    ("barracudanetworks.com",       "Barracuda"),
    ("sophos.com",                  "Sophos"),
    ("hydra.sophos.com",            "Sophos"),
    ("hornetsecurity.com",          "Hornetsecurity"),
    ("spamh.com",                   "SpamHero"),
    ("emailsrvr.com",               "Rackspace"),
    ("google.com",                  "Google Workspace"),
    ("googlemail.com",              "Google Workspace"),
]

# Providers that are Secure Email Gateways (not Microsoft EOP itself)
SEG_PROVIDERS = {
    "Proofpoint", "Mimecast", "Symantec/Broadcom", "Barracuda",
    "Sophos", "Hornetsecurity", "SpamHero",
}

ROUTING_SEVERITY = {
    "direct_m365": "low",
    "seg_present":  "info",
    "mixed":        "medium",
    "unknown":      "low",
    "no_mx":        "info",
}

ROUTING_SCORE = {
    "direct_m365": 30,
    "seg_present":  10,
    "mixed":        40,
    "unknown":      20,
    "no_mx":        0,
}

# Health score deductions — start at 100, subtract per check.
# These are MX-specific health checks, independent of the exposure score.
HEALTH_DEDUCTIONS = {
    "direct_m365":       25,   # No external SEG — meaningful configuration gap
    "mixed":             40,   # Multiple providers — routing architecture risk
    "unknown":           20,   # Cannot assess architecture
    "no_mx":              0,   # Not a health issue per se (domain may not need email)
    "seg_present":        0,   # Healthy — no deduction
    "unresolvable_host": 20,   # Per host — dangling record
    "multi_seg":         15,   # Multiple SEGs — inconsistent filtering
    "excessive_mx":      10,   # >5 records — complexity risk
}


def _classify_provider(host: str) -> str:
    h = host.lower().rstrip(".")
    for pattern, name in PROVIDER_PATTERNS:
        if h.endswith(pattern):
            return name
    return "Unknown"


# ---------------------------------------------------------------------------
# IP resolution helper
# ---------------------------------------------------------------------------

def _resolve_host_ips(host: str) -> dict[str, Any]:
    ips: list[str] = []
    error: str | None = None

    for rdtype in ("A", "AAAA"):
        try:
            answers = dns.resolver.resolve(host, rdtype)
            ips.extend(str(r) for r in answers)
        except dns.resolver.NXDOMAIN:
            error = "NXDOMAIN — hostname does not exist"
            break
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NoNameservers:
            error = "No nameservers available"
            break
        except dns.exception.Timeout:
            error = "DNS resolution timed out"
            break
        except Exception as exc:
            error = f"Unexpected DNS error: {exc}"
            break

    if error and "NXDOMAIN" in error:
        ips = []

    return {
        "ips":      ips,
        "resolved": len(ips) > 0,
        "error":    error,
        "multi_ip": len(ips) > 1,
    }


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

class MXAnalyzer:

    def __init__(self, domain: str):
        self.domain = domain

    async def run(self, request: ScanRequest) -> ScanResult:
        domain    = request.domain
        scan_id   = str(uuid.uuid4())
        findings: list[Finding] = []
        scan_start = time.monotonic()

        # ── Step 1: Resolve MX records ──────────────────────────────────────
        raw_mx: list[dict] = []
        try:
            answers = dns.resolver.resolve(domain, "MX")
            raw_mx = sorted(
                [{"priority": int(r.preference), "host": str(r.exchange).rstrip(".")}
                 for r in answers],
                key=lambda x: x["priority"],
            )
        except dns.resolver.NXDOMAIN:
            findings.append(Finding(
                id=f"exposure-mx-nxdomain-{domain}",
                category="exposure",
                severity="info",
                title="Domain does not exist (NXDOMAIN)",
                description=f"DNS returned NXDOMAIN for {domain}. The domain may not exist or may not be publicly resolvable.",
                recommended_action="Verify the domain name is correct and publicly registered.",
                evidence={"domain": domain},
            ))
        except dns.resolver.NoAnswer:
            pass
        except dns.exception.Timeout:
            findings.append(Finding(
                id=f"exposure-mx-timeout-{domain}",
                category="exposure",
                severity="medium",
                title="MX resolution timed out",
                description=f"DNS query for MX records on {domain} timed out. The domain's nameservers may be slow or unreachable.",
                recommended_action="Check DNS infrastructure for the domain and retry the scan.",
                evidence={"domain": domain},
            ))
        except Exception as exc:
            logger.warning("MX resolution error for %s: %s", domain, exc)

        # ── Step 2: Second-pass — resolve each MX hostname to IPs ───────────
        enriched_mx: list[dict] = []
        unresolvable_hosts: list[str] = []

        for record in raw_mx:
            host       = record["host"]
            resolution = _resolve_host_ips(host)
            provider   = _classify_provider(host)

            enriched = {
                **record,
                "provider":      provider,
                "ips":           resolution["ips"],
                "resolved":      resolution["resolved"],
                "multi_ip":      resolution["multi_ip"],
                "resolve_error": resolution["error"],
            }
            enriched_mx.append(enriched)

            if not resolution["resolved"]:
                unresolvable_hosts.append(host)
                is_nxdomain = resolution["error"] and "NXDOMAIN" in resolution["error"]
                severity = "high" if is_nxdomain else "medium"

                if is_nxdomain:
                    description = (
                        f"The MX record for {domain} points to {host}, but this hostname does not exist "
                        "in DNS (NXDOMAIN). A dangling MX record can indicate a misconfiguration or a "
                        "potential host takeover opportunity — an attacker may be able to register this "
                        "hostname and intercept email delivery to this domain."
                    )
                    recommended_action = (
                        "Remove this MX record immediately or update it to point to a valid hostname. "
                        "A dangling MX record is a potential host takeover risk that should be remediated urgently."
                    )
                else:
                    description = (
                        f"The MX record for {domain} points to {host}, but DNS resolution failed "
                        f"({resolution['error']}). Email delivery to this host will fail, potentially "
                        "causing fallback to lower-priority MX records that may have weaker filtering controls."
                    )
                    recommended_action = (
                        "Investigate DNS resolution for this MX host. A persistent failure may indicate a "
                        "decommissioned mail server that should be removed from DNS."
                    )

                findings.append(Finding(
                    id=f"exposure-mx-unresolvable-{host.replace('.', '-')}",
                    category="exposure",
                    severity=severity,
                    title=f"MX host does not resolve: {host}",
                    description=description,
                    recommended_action=recommended_action,
                    evidence={
                        "host":          host,
                        "priority":      record["priority"],
                        "provider":      provider,
                        "resolve_error": resolution["error"],
                        "ips":           [],
                    },
                ))
            elif resolution["multi_ip"]:
                findings.append(Finding(
                    id=f"exposure-mx-gslb-{host.replace('.', '-')}",
                    category="exposure",
                    severity="info",
                    title=f"MX host resolves to multiple IPs (GSLB/anycast): {host}",
                    description=(
                        f"{host} resolved to {len(resolution['ips'])} addresses "
                        f"({', '.join(resolution['ips'][:3])}{'...' if len(resolution['ips']) > 3 else ''}). "
                        "This is expected for global server load balancing (GSLB) or anycast deployments, "
                        "but IP-based allowlisting for this host will be unreliable and may break mail flow."
                    ),
                    recommended_action=(
                        "Do not use IP-based allowlisting for this host. "
                        "Reference the provider's hostname or domain in filtering rules, not individual IPs."
                    ),
                    evidence={
                        "host":     host,
                        "provider": provider,
                        "ips":      resolution["ips"],
                    },
                ))

        # ── Step 3: Classify routing posture ────────────────────────────────
        providers = list({r["provider"] for r in enriched_mx})
        seg_providers_present = [p for p in providers if p in SEG_PROVIDERS]
        eop_present           = "Microsoft EOP" in providers

        if not enriched_mx:
            routing_type = "no_mx"
        elif len(providers) == 1 and providers[0] == "Microsoft EOP":
            routing_type = "direct_m365"
        elif eop_present and len(providers) > 1:
            routing_type = "mixed"
        elif providers and providers != ["Unknown"]:
            routing_type = "seg_present"
        else:
            routing_type = "unknown"

        # ── Step 4: Routing posture finding ─────────────────────────────────
        if enriched_mx:
            base_score = ROUTING_SCORE.get(routing_type, 20)

            descriptions = {
                "direct_m365": (
                    f"{domain} routes inbound mail directly to Microsoft 365 (Exchange Online Protection) "
                    "without an external Secure Email Gateway (SEG). "
                    "Attackers can attempt direct-to-EOP delivery to bypass controls enforced by a SEG — "
                    "for example, sending mail directly to the EOP MX endpoint from IPs not covered by "
                    "an SEG's allowlist policy."
                ),
                "seg_present": (
                    f"{domain} routes inbound mail through "
                    f"{', '.join(seg_providers_present) if seg_providers_present else 'a security gateway'} "
                    "before reaching Microsoft 365. This is the preferred configuration. "
                    "Verify that EOP connector policies reject mail not originating from the gateway — "
                    "otherwise the direct-to-EOP bypass path may still be available to attackers."
                ),
                "mixed": (
                    f"{domain} has MX records pointing to multiple providers: {', '.join(providers)}. "
                    "When multiple providers are configured, senders may deliver mail to a secondary MX "
                    "record that bypasses the primary security gateway. "
                    "Some attack tools deliberately target lower-priority MX records to avoid filtering "
                    "controls applied at the primary gateway."
                ),
                "unknown": (
                    f"The MX provider for {domain} could not be classified against known providers. "
                    "Manual review of the MX configuration is recommended to confirm the intended "
                    "mail routing architecture."
                ),
            }

            routing_recommended = {
                "direct_m365": (
                    "Consider routing inbound mail through a Secure Email Gateway (SEG) before Microsoft EOP. "
                    "Configure EOP connector policies to reject mail not originating from the SEG's IP ranges."
                ),
                "seg_present": (
                    "Confirm that Microsoft EOP connector policies accept mail only from the SEG's IP ranges, "
                    "blocking direct-to-EOP delivery attempts from external sources."
                ),
                "mixed": (
                    "Review all MX records and confirm only intended gateways are configured. "
                    "Remove stale entries and ensure all MX paths route through your security gateway."
                ),
                "unknown": (
                    "Manually classify the MX provider and confirm the intended routing architecture. "
                    "Update provider patterns in the analyzer if this is a known gateway."
                ),
            }

            findings.insert(0, Finding(
                id=f"exposure-mx-{routing_type}-{domain}",
                category="exposure",
                severity=ROUTING_SEVERITY[routing_type],
                title={
                    "direct_m365": "MX records point directly to Microsoft EOP — no external SEG",
                    "seg_present":  "MX records routed through Secure Email Gateway",
                    "mixed":        "Mixed MX configuration detected",
                    "unknown":      "MX provider unknown",
                }.get(routing_type, "MX routing classified"),
                description=descriptions.get(routing_type, ""),
                recommended_action=routing_recommended.get(routing_type, ""),
                evidence={
                    "mx_records":   enriched_mx,
                    "routing_type": routing_type,
                    "providers":    providers,
                },
            ))

        # ── Step 5: Additional detection findings ────────────────────────────

        # Multiple SEGs
        if len(seg_providers_present) >= 2:
            findings.append(Finding(
                id=f"exposure-mx-multi-seg-{domain}",
                category="exposure",
                severity="medium",
                title=f"Multiple Secure Email Gateways configured: {', '.join(seg_providers_present)}",
                description=(
                    f"{domain} has MX records pointing to multiple Secure Email Gateways: "
                    f"{', '.join(seg_providers_present)}. "
                    "Mail may flow through different gateways depending on the sender, resulting in "
                    "inconsistent filtering policies. This can create gaps where some senders bypass "
                    "controls applied by one gateway that the other does not enforce."
                ),
                recommended_action=(
                    "Consolidate inbound mail routing to a single primary SEG. "
                    "If redundancy is required, ensure both gateways share identical filtering policies "
                    "and forward logs to a unified SIEM."
                ),
                evidence={
                    "seg_providers": seg_providers_present,
                    "all_providers": providers,
                },
            ))

        # Excessive MX records (>5)
        if len(enriched_mx) > 5:
            findings.append(Finding(
                id=f"exposure-mx-excessive-mx-{domain}",
                category="exposure",
                severity="info",
                title=f"Excessive MX records: {len(enriched_mx)} records configured",
                description=(
                    f"{domain} has {len(enriched_mx)} MX records. "
                    "Large MX record sets increase routing complexity, make troubleshooting harder, "
                    "and may include stale entries pointing to decommissioned infrastructure. "
                    "Stale MX records can create host takeover opportunities or unintended mail routing paths."
                ),
                recommended_action=(
                    "Audit the full MX record set and remove any stale, decommissioned, or unintended entries. "
                    "Maintain only the MX records required for your intended mail routing architecture."
                ),
                evidence={
                    "record_count": len(enriched_mx),
                    "mx_records":   enriched_mx,
                },
            ))

        # Lead summary finding
        if enriched_mx:
            findings.insert(0, Finding(
                id=f"exposure-mx-mx-records-{domain}",
                category="exposure",
                severity="info",
                title=f"MX records resolved ({len(enriched_mx)} record{'s' if len(enriched_mx) != 1 else ''})",
                description=(
                    f"{domain} has {len(enriched_mx)} MX record(s). "
                    f"Detected provider(s): {', '.join(providers) if providers else 'None'}."
                    + (f" {len(unresolvable_hosts)} host(s) could not be resolved to an IP."
                       if unresolvable_hosts else "")
                ),
                recommended_action=(
                    "Verify the full MX record set matches your intended mail routing architecture. "
                    "Investigate any unexpected or unrecognized providers."
                ),
                evidence={
                    "mx_records":        enriched_mx,
                    "providers":         providers,
                    "unresolvable_hosts": unresolvable_hosts,
                },
            ))
        else:
            findings.append(Finding(
                id=f"exposure-mx-no-mx-{domain}",
                category="exposure",
                severity="info",
                title="No MX records found",
                description=(
                    f"No MX records were returned for {domain}. "
                    "The domain cannot receive email, or MX records are not publicly published."
                ),
                recommended_action=(
                    "If this domain is intended to receive email, add MX records pointing to your mail gateway. "
                    "If email is not used, add a null MX record (RFC 7505) to explicitly signal no mail acceptance."
                ),
                evidence={"domain": domain},
            ))

        # ── Step 6: Compute scores ───────────────────────────────────────────

        # Legacy exposure score (kept for API backward compatibility)
        score = ROUTING_SCORE.get(routing_type, 20)
        if unresolvable_hosts:
            score = min(100, score + 20 * len(unresolvable_hosts))
        if len(seg_providers_present) >= 2:
            score = min(100, score + 15)
        if len(enriched_mx) > 5:
            score = min(100, score + 10)

        # Health score — first-class MX health metric.
        # Starts at 100 and deducts per check. Each deduction is independent.
        # Higher health score = healthier configuration.
        health_score = 100
        health_deductions: list[str] = []

        routing_deduction = HEALTH_DEDUCTIONS.get(routing_type, 0)
        if routing_deduction > 0:
            health_score -= routing_deduction
            label = {
                "direct_m365": "No external Secure Email Gateway detected",
                "mixed":        "Mixed MX provider configuration",
                "unknown":      "MX provider could not be classified",
            }.get(routing_type, f"Routing: {routing_type.replace('_', ' ')}")
            health_deductions.append(f"{label} (-{routing_deduction})")

        for host in unresolvable_hosts:
            d = HEALTH_DEDUCTIONS["unresolvable_host"]
            health_score -= d
            health_deductions.append(f"Unresolvable MX host: {host} (-{d})")

        if len(seg_providers_present) >= 2:
            d = HEALTH_DEDUCTIONS["multi_seg"]
            health_score -= d
            health_deductions.append(f"Multiple SEGs configured: {', '.join(seg_providers_present)} (-{d})")

        if len(enriched_mx) > 5:
            d = HEALTH_DEDUCTIONS["excessive_mx"]
            health_score -= d
            health_deductions.append(f"Excessive MX records ({len(enriched_mx)} records) (-{d})")

        health_score = max(0, health_score)

        # ── Step 7: Scan metadata ────────────────────────────────────────────
        scan_duration_ms = round((time.monotonic() - scan_start) * 1000)
        scan_metadata = {
            "scan_type":        "mx_exposure",
            "resolver":         "public_dns",
            "scan_duration_ms": scan_duration_ms,
            "module_version":   MODULE_VERSION,
        }

        # ── Step 8: Structured routing analysis ─────────────────────────────
        routing_analysis = {
            "architecture":  routing_type,
            "providers":     providers,
            "seg_present":   len(seg_providers_present) > 0,
            "seg_providers": seg_providers_present,
            "gateway_count": len(seg_providers_present),
            "eop_present":   eop_present,
        }

        return ScanResult(
            scan_id=scan_id,
            tenant_id=domain,
            family="exposure",
            findings=findings,
            score=score,
            status="complete",
            timestamp=datetime.now(timezone.utc).isoformat(),
            evidence={
                "domain":             domain,
                "mx_records":         enriched_mx,
                "providers":          providers,
                "routing_type":       routing_type,
                "provider_count":     len(providers),
                "unresolvable_hosts": unresolvable_hosts,
                "health_score":       health_score,
                "health_deductions":  health_deductions,
                "routing_analysis":   routing_analysis,
                "scan_metadata":      scan_metadata,
            },
        )
