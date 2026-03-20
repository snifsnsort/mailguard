# inbound_path_analyzer.py
#
# InboundPathAnalyzer — task: inbound_path_mapping
#
# DNS-based. Resolves MX records, classifies each hop in the inbound
# delivery chain, and produces a structured path map with findings.
#
# No tenant credentials required — runs against any domain.

import uuid
import asyncio
from datetime import datetime, timezone
from typing import List, Optional
import dns.asyncresolver

from app.models.v2.scan_request import ScanRequest
from app.models.v2.scan_result import ScanResult
from app.models.v2.finding import Finding

# ── Provider fingerprints ─────────────────────────────────────────────────────

PROVIDER_PATTERNS = {
    "Proofpoint":       ["pphosted.com", "proofpoint.com", "ppe-hosted.com"],
    "Mimecast":         ["mimecast.com"],
    "Microsoft EOP":    ["mail.protection.outlook.com", "eo.outlook.com"],
    "Google Workspace": ["aspmx.l.google.com", "googlemail.com", "smtp.google.com"],
    "Barracuda":        ["barracudanetworks.com", "cudamail.com"],
    "Cisco IronPort":   ["ironport.com", "sma.cisco.com"],
    "Sophos":           ["sophos.com", "reflexion.net"],
    "Forcepoint":       ["forcepoint.com", "websense.com"],
    "SpamTitan":        ["spamtitan.com"],
    "Cloudflare":       ["cloudflare.net", "cloudflare.com"],
}

SEG_PROVIDERS = {"Proofpoint", "Mimecast", "Barracuda", "Cisco IronPort",
                 "Sophos", "Forcepoint", "SpamTitan"}

PLATFORM_PROVIDERS = {"Microsoft EOP", "Google Workspace"}


def _classify_host(host: str) -> Optional[str]:
    host_lower = host.lower()
    for provider, patterns in PROVIDER_PATTERNS.items():
        if any(p in host_lower for p in patterns):
            return provider
    return None


def _classify_routing(providers: List[str]) -> dict:
    """
    Classify the routing architecture based on detected providers.
    Returns routing_type and a human-readable description.
    """
    seg_found      = [p for p in providers if p in SEG_PROVIDERS]
    platform_found = [p for p in providers if p in PLATFORM_PROVIDERS]

    if seg_found and platform_found:
        return {
            "routing_type": "seg_gateway",
            "description":  f"Mail flows through {', '.join(seg_found)} before reaching {', '.join(platform_found)}. "
                            f"SEG provides pre-delivery filtering.",
        }
    if platform_found and not seg_found:
        return {
            "routing_type": "direct_to_platform",
            "description":  f"Mail delivers directly to {', '.join(platform_found)} with no intermediate gateway detected.",
        }
    if seg_found and not platform_found:
        return {
            "routing_type": "seg_only",
            "description":  f"Mail routed through {', '.join(seg_found)}. Final delivery platform not identified via MX.",
        }
    return {
        "routing_type": "unknown",
        "description":  "Could not classify routing architecture from MX records alone.",
    }


class InboundPathAnalyzer:

    def __init__(self, domain: str):
        self.domain = domain

    async def run(self, request: ScanRequest) -> ScanResult:
        t0       = datetime.now(timezone.utc)
        findings: List[Finding] = []
        mx_hops  = []
        providers_seen = []

        # ── Resolve MX records ────────────────────────────────────────────────
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 8
            answers = await resolver.resolve(self.domain, "MX")
            mx_records = sorted(
                [(r.preference, str(r.exchange).rstrip(".")) for r in answers],
                key=lambda x: x[0],
            )
        except Exception as e:
            findings.append(Finding(
                id=f"routing-no-mx-{self.domain}",
                category="mail_routing",
                severity="critical",
                title="No MX records found",
                description=f"No MX records could be resolved for {self.domain}. "
                            f"This means the domain cannot receive email, or DNS resolution failed. "
                            f"Error: {e}",
                recommended_action="Verify MX records exist and are correctly published in DNS.",
                evidence={"impact": "Domain cannot receive inbound email."},
            ))
            return self._result(findings, {}, t0)

        # ── Classify each MX hop ──────────────────────────────────────────────
        for priority, host in mx_records:
            provider = _classify_host(host)
            hop = {
                "priority": priority,
                "host":     host,
                "provider": provider or "Unknown",
                "role":     "seg" if provider in SEG_PROVIDERS else
                            "platform" if provider in PLATFORM_PROVIDERS else
                            "unknown",
            }

            # Attempt A-record resolution
            try:
                a_ans = await dns.asyncresolver.resolve(host, "A")
                hop["ips"] = [str(r) for r in a_ans]
                hop["resolved"] = True
            except Exception:
                hop["ips"] = []
                hop["resolved"] = False
                findings.append(Finding(
                    id=f"routing-mx-unresolvable-{host.replace('.', '-')}",
                    category="mail_routing",
                    severity="high",
                    title=f"MX host does not resolve: {host}",
                    description=f"The MX record {host} (priority {priority}) for {self.domain} "
                                f"has no A record and cannot be reached. Mail destined for this "
                                f"MX entry will be undeliverable.",
                    recommended_action=f"Remove or correct the MX record pointing to {host}. "
                                       f"Verify the host is operational and DNS is correct.",
                    evidence={
                        "impact": "Mail routed to this MX host will bounce or be deferred.",
                        "host": host,
                        "priority": priority,
                    },
                ))

            if provider and provider not in providers_seen:
                providers_seen.append(provider)
            mx_hops.append(hop)

        # ── Routing classification ────────────────────────────────────────────
        routing = _classify_routing(providers_seen)

        # ── Findings: direct-to-platform without SEG ─────────────────────────
        if routing["routing_type"] == "direct_to_platform":
            findings.append(Finding(
                id=f"routing-no-seg-{self.domain}",
                category="mail_routing",
                severity="medium",
                title="No email security gateway detected in inbound path",
                description=f"Mail for {self.domain} delivers directly to the mail platform "
                            f"({', '.join(p for p in providers_seen if p in PLATFORM_PROVIDERS)}) "
                            f"without an intermediate SEG. Built-in platform filtering (EOP/Defender) "
                            f"is still active, but no additional pre-delivery gateway layer is present.",
                recommended_action="Consider deploying a Secure Email Gateway (Proofpoint, Mimecast, etc.) "
                                   "for additional pre-delivery filtering, sandboxing, and inbound policy enforcement.",
                evidence={
                    "impact": "Inbound mail relies solely on platform-native filtering with no independent gateway layer.",
                    "providers": providers_seen,
                },
            ))

        # ── Findings: mixed providers at same priority ────────────────────────
        by_priority: dict = {}
        for hop in mx_hops:
            by_priority.setdefault(hop["priority"], []).append(hop)

        for prio, hops in by_priority.items():
            hop_providers = [h["provider"] for h in hops if h["provider"] != "Unknown"]
            unique = set(hop_providers)
            if len(unique) > 1:
                findings.append(Finding(
                    id=f"routing-mixed-priority-{prio}-{self.domain}",
                    category="mail_routing",
                    severity="medium",
                    title=f"Multiple different providers at MX priority {prio}",
                    description=f"MX records at priority {prio} for {self.domain} point to hosts "
                                f"from different providers: {', '.join(unique)}. "
                                f"This creates inconsistent filtering — some messages may bypass "
                                f"one provider's controls depending on which MX is selected by the sending server.",
                    recommended_action="Ensure all MX records at the same priority level route through "
                                       "the same provider. Use different priority tiers to distinguish "
                                       "primary from failover paths.",
                    evidence={
                        "impact": "Inconsistent filtering — inbound mail policy may not apply uniformly.",
                        "priority": prio,
                        "providers_at_priority": list(unique),
                    },
                ))

        duration_ms = int((datetime.now(timezone.utc) - t0).total_seconds() * 1000)

        evidence = {
            "domain":          self.domain,
            "mx_hops":         mx_hops,
            "providers":       providers_seen,
            "routing_type":    routing["routing_type"],
            "routing_description": routing["description"],
            "hop_count":       len(mx_hops),
            "scan_duration_ms": duration_ms,
        }

        return self._result(findings, evidence, t0)

    def _result(self, findings, evidence, t0) -> ScanResult:
        return ScanResult(
            scan_id=str(uuid.uuid4()),
            tenant_id="",
            family="mail_routing_topology",
            findings=findings,
            score=min(100, len([f for f in findings if f.severity in ("critical","high")]) * 20),
            status="completed",
            timestamp=t0.isoformat(),
            evidence=evidence,
        )
