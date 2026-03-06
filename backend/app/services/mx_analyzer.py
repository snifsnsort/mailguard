"""
MX Gateway Detection
Inspects MX records to identify email security gateways and assess
bypass risks from split MX configurations.
"""
import asyncio
import dns.resolver
import dns.asyncresolver
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field

# Known SEG (Secure Email Gateway) fingerprints mapped to vendor name
SEG_FINGERPRINTS: Dict[str, str] = {
    # Proofpoint
    "pphosted.com":              "Proofpoint",
    "ppe-hosted.com":            "Proofpoint Essentials",
    "proofpoint.com":            "Proofpoint",
    # Mimecast
    "mimecast.com":              "Mimecast",
    # Barracuda
    "barracudanetworks.com":     "Barracuda",
    "cudamail.com":              "Barracuda",
    # Cisco / IronPort
    "iphmx.com":                 "Cisco Email Security",
    "ironport.com":              "Cisco IronPort",
    "ess.cisco.com":             "Cisco Email Security",
    "cisco.com":                 "Cisco IronPort",
    # Sophos
    "sophos.com":                "Sophos",
    "reflexion.net":             "Sophos (Reflexion)",
    # Forcepoint
    "forcepoint.com":            "Forcepoint",
    "mailcontrol.com":           "Forcepoint",
    # Check Point
    "checkpoint.com":            "Check Point",
    "mail.checkpoint.com":       "Check Point",
    # Broadcom / Symantec / MessageLabs
    "messagelabs.com":           "Broadcom (MessageLabs)",
    "symanteccloud.com":         "Broadcom (Symantec)",
    # Fortinet FortiMail
    "fortimail.com":             "Fortinet FortiMail",
    "fortinet.com":              "Fortinet FortiMail",
    # FireEye / Trellix
    "fireeye.com":               "Trellix (FireEye)",
    # Abnormal Security (API-based, won't appear in MX but included for completeness)
    "abnormalsecurity.com":      "Abnormal Security",
    # Trend Micro
    "trendmicro.com":            "Trend Micro",
    "tmase.net":                 "Trend Micro",
    "in.trend-net.net":          "Trend Micro",
    # SpamExperts / Hornetsecurity
    "antispamcloud.com":         "SpamExperts / Hornetsecurity",
    "spamexperts.com":           "SpamExperts",
    "hornetsecurity.com":        "Hornetsecurity",
    # Egress
    "egress.com":                "Egress",
    # Trustifi
    "trustifi.com":              "Trustifi",
    # Microsoft native
    "protection.outlook.com":    "Microsoft EOP",
    "mail.protection.outlook.com": "Microsoft EOP",
    "onmicrosoft.com":           "Microsoft EOP (fallback)",
    # Google Workspace
    "google.com":                "Google Workspace",
    "googlemail.com":            "Google Workspace",
    "aspmx.l.google.com":        "Google Workspace",
    "smtp.google.com":           "Google Workspace",
}

# ── Per-vendor check context ──────────────────────────────────────────────────
# For each SEG vendor, maps check_id → (downgrade_severity, note)
# downgrade_severity: if True, a "fail" is softened to "warn" (not a gap, just
# a different architecture choice). The note is appended to the finding description.
# Only applies when the SEG is the *exclusive* inbound path (no split-MX).

SEG_CHECK_CONTEXT: dict[str, dict[str, tuple[bool, str]]] = {
    "Proofpoint": {
        # Source: Proofpoint Microsoft 365 Integration Guide v4.10 (August 2025)
        # Compatibility matrix (p.28): MSDO Safe Links (Email) + TAP URL Defense = NO
        # Guide (p.9, Step 4): Safe Links URL rewriting CANNOT run concurrently with
        # Proofpoint URL Defense — bypass via transport rule X-MS-Exchange-Organization-
        # SkipSafeLinksProcessing=1 for all mail from Proofpoint IPs.
        "safe_links_assigned": (
            True,
            "[Proofpoint v4.10, p.9] Safe Links URL rewriting MUST be bypassed for email "
            "when Proofpoint TAP URL Defense is active — running both causes double-rewriting "
            "and broken links. The guide prescribes a transport rule setting "
            "X-MS-Exchange-Organization-SkipSafeLinksProcessing=1 for all mail from "
            "Proofpoint IPs. Safe Links for OneDrive, SharePoint, and Teams (non-email) "
            "can remain enabled — no conflict per compatibility matrix (p.28).",
        ),
        # Compatibility matrix (p.28): MSDO Safe Attachments (Email) + TAP = YES concurrent
        # Guide (p.31): "Safe Attachments will only analyze messages already deemed clean by
        # Proofpoint." Running both is valid defence-in-depth (second-pass detonation).
        "safe_attachments_mode": (
            False,
            "[Proofpoint v4.10, p.31] Safe Attachments for email CAN run concurrently with "
            "Proofpoint TAP Attachment Defense per the official compatibility matrix. "
            "It acts as a second-pass detonation layer on attachments Proofpoint deemed clean. "
            "Disabling it is an architectural choice (reduces latency); keeping it enabled "
            "is valid defence-in-depth. The guide notes Microsoft detonation adds latency.",
        ),
        # Compatibility matrix (p.28): EOP Anti-Phishing + PPS = 'Yes, with limitations'
        # Guide (p.30): "There should be no need to disable or bypass anti-phishing protection."
        "antiphishing_impersonation": (
            False,
            "[Proofpoint v4.10, p.30] EOP Anti-Phishing should remain ENABLED alongside "
            "Proofpoint — the guide explicitly states 'there should be no need to disable or "
            "bypass anti-phishing protection within EOP.' Proofpoint BEC/impersonation "
            "(Nexus People Risk Explorer, Advanced BEC Defense) complements, not replaces, "
            "Microsoft's engine. Both should be active for layered protection.",
        ),
        # Guide (p.22-23, Outbound): EOP outbound spam policies apply independently.
        # SPF must include Proofpoint Protection Server IPs for outbound mail routing.
        "antispam_outbound": (
            False,
            "[Proofpoint v4.10, p.22-23] EOP outbound spam policies apply independently "
            "of Proofpoint inbound filtering and must remain configured. For outbound mail "
            "routed through Proofpoint, SPF records must include Proofpoint Protection Server "
            "IPs. Validate using Proofpoint's DMARC/SPF wizard. "
            "Outbound spam policy should NOT be bypassed.",
        ),
        # Guide (p.8, Step 2, Option 1 + 2): Adding Proofpoint IPs to Connection Filter
        # IP Allow List is required. Guide recommends BOTH Option 1 (IP allow list) AND
        # Option 2 (transport rule SCL=-1). Confirm via IPV:CAL header in inbound mail.
        "connection_filter_allow_list": (
            False,
            "[Proofpoint v4.10, p.8, Step 2] Adding Proofpoint IPs to the EOP Connection "
            "Filter IP Allow List is REQUIRED per the integration guide to allow messages "
            "to bypass EOP spam scanning (confirmed by IPV:CAL header on inbound mail). "
            "The guide recommends BOTH Option 1 (IP allow list) AND Option 2 (transport "
            "rule SCL=-1 bypass) in production. Scope strictly to Proofpoint egress IPs — "
            "overly broad entries expose EOP spam bypass to unauthorised senders.",
        ),
        # Guide (p.10-16): Preventing EOP Direct Delivery bypass is the #1 Proofpoint
        # integration risk. Method 6A (connector reject) is recommended; 6D discouraged.
        "mx_bypass_risk": (
            False,
            "[Proofpoint v4.10, p.10-16] Preventing EOP direct-delivery bypass is critical. "
            "Attackers send directly to <tenant>.mail.protection.outlook.com, skipping "
            "Proofpoint entirely. Recommended: Method 6A — a 'Block Direct Delivery' EOP "
            "Connector (Partner org, wildcard domain *, reject if source IP not in Proofpoint "
            "IP list). Also configure an 'Audit Direct Delivery' transport rule tagging "
            "bypassed mail with X-EOP-DirectDelivery=True for detection. "
            "Method 6D (do nothing) is flagged as actively exploited by attackers (p.16).",
        ),
    },
    "Proofpoint Essentials": {
        "safe_links_assigned": (
            True,
            "Proofpoint Essentials includes URL rewriting and click-time protection. "
            "Safe Links duplication is expected. Confirm URL Defence is enabled in the "
            "Essentials console.",
        ),
        "safe_attachments_mode": (
            True,
            "Proofpoint Essentials performs attachment scanning at the gateway. "
            "Safe Attachments duplication is expected.",
        ),
        "antiphishing_impersonation": (
            False,
            "Proofpoint Essentials impersonation protection is less comprehensive than "
            "the enterprise TAP product. Consider enabling Microsoft impersonation "
            "protection as a secondary layer.",
        ),
    },
    "Mimecast": {
        "safe_links_assigned": (
            True,
            "Mimecast Targeted Threat Protection (TTP) — URL Protect rewrites links and "
            "performs real-time scanning. Safe Links is architecturally redundant. "
            "Verify Mimecast TTP URL Protect is licensed and enabled for all users.",
        ),
        "safe_attachments_mode": (
            True,
            "Mimecast TTP — Attachment Protect performs pre-delivery sandboxing and "
            "safe-file conversion. Safe Attachments duplication is expected. "
            "Confirm Attachment Protect is active (not just anti-virus).",
        ),
        "antiphishing_impersonation": (
            True,
            "Mimecast Impersonation Protect detects display-name spoofing and "
            "look-alike domains at the gateway. Microsoft impersonation protection "
            "may be intentionally disabled. Verify Mimecast Impersonation Protect "
            "policy is applied to all inbound mail.",
        ),
        "antispam_outbound": (
            False,
            "Mimecast typically handles inbound mail only. Exchange Online outbound "
            "spam policies apply independently and should still be configured.",
        ),
    },
    "Barracuda": {
        "safe_links_assigned": (
            True,
            "Barracuda Email Protection includes Advanced Threat Protection (ATP) with "
            "URL sandboxing. Safe Links may be intentionally absent. Verify Barracuda "
            "ATP is enabled and click-protection is active.",
        ),
        "safe_attachments_mode": (
            True,
            "Barracuda ATP performs attachment sandboxing at the gateway. Safe "
            "Attachments duplication is expected. Confirm ATP sandbox is active, "
            "not just reputation/AV scanning.",
        ),
        "antiphishing_impersonation": (
            False,
            "Barracuda's impersonation protection is limited compared to Proofpoint "
            "or Mimecast. Microsoft anti-phishing impersonation protection is recommended "
            "as a complementary layer even with Barracuda in place.",
        ),
    },
    "Cisco IronPort": {
        "safe_links_assigned": (
            True,
            "Cisco Secure Email performs URL filtering and reputation scoring at the "
            "gateway. Safe Links duplication is expected. Verify Cisco URL Analysis "
            "and Outbreak Filters are enabled.",
        ),
        "safe_attachments_mode": (
            True,
            "Cisco Secure Email with Advanced Malware Protection (AMP) provides "
            "attachment sandboxing. Safe Attachments duplication is expected. "
            "Confirm AMP for Email is licensed and active.",
        ),
        "antiphishing_impersonation": (
            False,
            "Cisco Secure Email impersonation detection is policy-based. Microsoft "
            "impersonation protection (mailbox intelligence + user/domain lists) "
            "provides complementary coverage and is recommended.",
        ),
    },
    "Cisco Email Security": {
        "safe_links_assigned": (
            True,
            "Cisco Email Security Appliance (ESA) performs URL filtering at the gateway. "
            "Safe Links duplication is expected.",
        ),
        "safe_attachments_mode": (
            True,
            "Cisco ESA with AMP performs attachment analysis. Safe Attachments "
            "duplication is expected.",
        ),
        "antiphishing_impersonation": (
            False,
            "Consider enabling Microsoft impersonation protection as a complementary layer.",
        ),
    },
    "Sophos": {
        "safe_links_assigned": (
            True,
            "Sophos Email Security includes Time-of-Click URL protection. Safe Links "
            "duplication is expected. Verify Sophos impersonation and URL protection "
            "policies are applied to all users.",
        ),
        "safe_attachments_mode": (
            True,
            "Sophos Email performs sandboxed file analysis via Sophos Sandstorm. "
            "Safe Attachments duplication is expected. Confirm Sandstorm is licensed.",
        ),
        "antiphishing_impersonation": (
            False,
            "Sophos impersonation detection focuses on display-name spoofing. "
            "Microsoft targeted user/domain protection adds depth for VIP impersonation.",
        ),
    },
    "Sophos (Reflexion)": {
        "safe_links_assigned": (
            True,
            "Sophos (Reflexion) handles URL protection at the gateway. "
            "Safe Links duplication is expected.",
        ),
        "safe_attachments_mode": (
            True,
            "Sophos (Reflexion) performs attachment scanning. Safe Attachments "
            "duplication is expected.",
        ),
        "antiphishing_impersonation": (
            False,
            "Enable Microsoft impersonation protection for VIP/executive coverage.",
        ),
    },
    "Broadcom (MessageLabs)": {
        "safe_links_assigned": (
            True,
            "Broadcom Email Security.cloud (MessageLabs) includes URL scanning and "
            "click-time protection. Safe Links duplication is expected.",
        ),
        "safe_attachments_mode": (
            True,
            "Broadcom Email Security.cloud performs attachment analysis. Safe Attachments "
            "duplication is expected.",
        ),
        "antiphishing_impersonation": (
            False,
            "Broadcom impersonation controls are reputation-based. Microsoft targeted "
            "impersonation protection is recommended for executive protection.",
        ),
    },
    "Broadcom (Symantec)": {
        "safe_links_assigned": (
            True,
            "Broadcom/Symantec Email Security.cloud handles URL protection. "
            "Safe Links duplication is expected.",
        ),
        "safe_attachments_mode": (
            True,
            "Symantec Email Security.cloud performs attachment sandboxing. "
            "Safe Attachments duplication is expected.",
        ),
        "antiphishing_impersonation": (
            False,
            "Enable Microsoft impersonation protection for targeted executive/VIP coverage.",
        ),
    },
    "Trellix (FireEye)": {
        "safe_links_assigned": (
            True,
            "Trellix Email Security performs URL detonation via its MVX sandbox. "
            "Safe Links duplication is expected. Confirm Trellix URL analysis is active.",
        ),
        "safe_attachments_mode": (
            True,
            "Trellix MVX sandbox provides comprehensive attachment detonation. "
            "Safe Attachments duplication is expected.",
        ),
        "antiphishing_impersonation": (
            False,
            "Trellix focuses on malware/exploit detection. Microsoft impersonation "
            "protection (BEC/VIP spoofing) is complementary and recommended.",
        ),
    },
    "Abnormal Security": {
        # Abnormal sits post-delivery via API — MX still goes through Microsoft EOP.
        # It does NOT replace Safe Links / Safe Attachments; it augments them.
        "safe_links_assigned": (
            False,
            "Abnormal Security is an API-based solution that analyzes mail after "
            "Microsoft EOP delivery — it does NOT replace Safe Links. Safe Links "
            "should still be configured.",
        ),
        "safe_attachments_mode": (
            False,
            "Abnormal Security operates post-delivery and does not replace Safe "
            "Attachments sandbox detonation. Safe Attachments should still be configured.",
        ),
        "antiphishing_impersonation": (
            False,
            "Abnormal Security provides strong BEC/impersonation detection but "
            "operates alongside Microsoft — both should be active.",
        ),
    },
    "Trend Micro": {
        "safe_links_assigned": (
            True,
            "Trend Micro Email Security performs URL filtering and rewriting. "
            "Safe Links duplication is expected. Verify Writing Protection and "
            "URL scanning are enabled in the Trend Micro console.",
        ),
        "safe_attachments_mode": (
            True,
            "Trend Micro Email Security with File Password Analysis performs attachment "
            "sandboxing. Safe Attachments duplication is expected.",
        ),
        "antiphishing_impersonation": (
            False,
            "Enable Microsoft impersonation protection for executive/VIP targeted protection.",
        ),
    },
    "SpamExperts / Hornetsecurity": {
        "safe_links_assigned": (
            True,
            "Hornetsecurity / SpamExperts provides URL filtering. "
            "Safe Links duplication is expected.",
        ),
        "safe_attachments_mode": (
            True,
            "Hornetsecurity Advanced Threat Protection performs attachment analysis. "
            "Safe Attachments duplication is expected if ATP is licensed.",
        ),
        "antiphishing_impersonation": (
            False,
            "Enable Microsoft impersonation protection alongside Hornetsecurity.",
        ),
    },
    "Forcepoint": {
        "safe_links_assigned": (
            True,
            "Forcepoint Email Security performs URL filtering and click-time protection. "
            "Safe Links duplication is expected.",
        ),
        "safe_attachments_mode": (
            True,
            "Forcepoint Email Security performs attachment sandboxing via MetaDefender. "
            "Safe Attachments duplication is expected.",
        ),
        "antiphishing_impersonation": (
            False,
            "Enable Microsoft impersonation protection for targeted VIP coverage.",
        ),
    },
    "Check Point": {
        "safe_links_assigned": (
            True,
            "Check Point Harmony Email & Collaboration performs URL sandboxing. "
            "Safe Links duplication is expected.",
        ),
        "safe_attachments_mode": (
            True,
            "Check Point Harmony performs attachment detonation. Safe Attachments "
            "duplication is expected.",
        ),
        "antiphishing_impersonation": (
            False,
            "Enable Microsoft impersonation protection as a complementary layer.",
        ),
    },
}

# Checks that are redundant when a SEG handles that function (legacy — kept for
# backward compatibility; SEG_CHECK_CONTEXT is the authoritative source now)
SEG_REDUNDANT_CHECKS: dict[str, list[str]] = {
    vendor: [cid for cid, (downgrade, _) in checks.items() if downgrade]
    for vendor, checks in SEG_CHECK_CONTEXT.items()
}

MICROSOFT_MX_SUFFIXES = [
    "protection.outlook.com",
    "mail.protection.outlook.com",
    "onmicrosoft.com",
]

GOOGLE_MX_SUFFIXES = [
    "google.com",
    "googlemail.com",
    "aspmx.l.google.com",
    "smtp.google.com",
]

# Routing type classification
ROUTING_CLEAN    = "clean"          # Single vendor, all records consistent
ROUTING_SPLIT    = "split"          # SEG + Microsoft EOP (bypass risk)
ROUTING_MULTI_SEG = "multi_seg"     # Multiple different SEG vendors
ROUTING_INCONSISTENT = "inconsistent"  # Mix of unrelated providers (e.g. EOP + Google)
ROUTING_UNKNOWN  = "unknown"        # No recognizable vendors
ROUTING_ERRORS   = "errors"         # Hosts with no A records


@dataclass
class MxRecord:
    priority: int
    host: str
    vendor: Optional[str] = None
    is_microsoft: bool = False
    is_google: bool = False
    is_seg: bool = False
    has_a_record: bool = True
    a_records: List[str] = field(default_factory=list)
    anomaly: Optional[str] = None


@dataclass
class MxAnalysis:
    raw_records: List[MxRecord] = field(default_factory=list)
    gateways: List[str] = field(default_factory=list)          # distinct SEG vendor names
    has_seg: bool = False
    has_microsoft: bool = False
    has_google: bool = False
    split_mx: bool = False                                      # SEG + Microsoft EOP
    multi_seg_conflict: bool = False                            # Multiple different SEG vendors
    bypass_risk: bool = False
    routing_type: str = ROUTING_UNKNOWN
    redundant_checks: List[str] = field(default_factory=list)
    summary: str = ""
    recommendations: List[str] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)
    vendor: Optional[str] = None                               # Primary vendor (if single)


def _identify_vendor(host: str) -> Optional[str]:
    host = host.lower().rstrip(".")
    for pattern, vendor in SEG_FINGERPRINTS.items():
        if host.endswith(pattern) or host == pattern:
            return vendor
    return None


def _is_microsoft(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host.endswith(s) for s in MICROSOFT_MX_SUFFIXES)


def _is_google(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host.endswith(s) or host == s for s in GOOGLE_MX_SUFFIXES)


async def _resolve_a_records(host: str) -> List[str]:
    """Resolve A records for an MX host. Returns empty list if unresolvable."""
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5
        answers = await resolver.resolve(host.rstrip("."), "A")
        return [str(r) for r in answers]
    except Exception:
        return []


async def analyze_mx(domain: str) -> MxAnalysis:
    analysis = MxAnalysis()
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 8
        answers = await resolver.resolve(domain, "MX")
        raw = []
        for rdata in answers:
            host = str(rdata.exchange).lower().rstrip(".")
            priority = int(rdata.preference)
            vendor = _identify_vendor(host)
            is_ms = _is_microsoft(host)
            is_goog = _is_google(host)
            # A host is a SEG if it's a known third-party vendor (not Microsoft or Google native)
            is_seg = bool(vendor and not is_ms and not is_goog)
            record = MxRecord(
                priority=priority,
                host=host,
                vendor=vendor,
                is_microsoft=is_ms,
                is_google=is_goog,
                is_seg=is_seg,
            )
            raw.append(record)

        # Resolve A records concurrently — detect unresolvable hosts
        a_results = await asyncio.gather(*[_resolve_a_records(r.host) for r in raw])
        for record, a_recs in zip(raw, a_results):
            record.a_records = a_recs
            record.has_a_record = bool(a_recs)
            if not record.has_a_record:
                note = (
                    f"MX host '{record.host}' has no A record — "
                    f"mail delivery to this host will fail."
                )
                record.anomaly = note
                analysis.anomalies.append(note)

        analysis.raw_records = raw

    except Exception:
        analysis.summary = "Unable to resolve MX records."
        return analysis

    # Sort by priority (lower number = higher preference)
    analysis.raw_records.sort(key=lambda r: r.priority)

    # ── Classify what vendors are present ─────────────────────────────────────
    seg_vendors    = list(dict.fromkeys(r.vendor for r in analysis.raw_records if r.is_seg and r.vendor))
    distinct_segs  = list(dict.fromkeys(seg_vendors))  # unique SEG vendor names
    has_microsoft  = any(r.is_microsoft for r in analysis.raw_records)
    has_google     = any(r.is_google for r in analysis.raw_records)

    analysis.gateways         = distinct_segs
    analysis.has_seg          = bool(distinct_segs)
    analysis.has_microsoft    = has_microsoft
    analysis.has_google       = has_google
    analysis.split_mx         = bool(distinct_segs) and has_microsoft
    analysis.multi_seg_conflict = len(distinct_segs) > 1
    analysis.bypass_risk      = analysis.split_mx
    analysis.vendor           = distinct_segs[0] if len(distinct_segs) == 1 else None

    # ── Routing type ──────────────────────────────────────────────────────────
    # Priority is irrelevant for classification — what matters is WHICH vendors appear.
    # Any mixture of incompatible providers is a misconfiguration.

    unresolvable = [r for r in analysis.raw_records if not r.has_a_record]

    if analysis.multi_seg_conflict:
        # Multiple different SEG vendors — mail will only go to the highest-priority one;
        # the others are misconfigured and create confusion / inconsistency
        analysis.routing_type = ROUTING_MULTI_SEG
    elif analysis.split_mx:
        # SEG + Microsoft EOP — bypass risk
        analysis.routing_type = ROUTING_SPLIT
    elif has_microsoft and has_google:
        # Microsoft EOP + Google Workspace — completely different mail platforms mixed
        analysis.routing_type = ROUTING_INCONSISTENT
    elif unresolvable and not analysis.has_seg and not has_microsoft and not has_google:
        analysis.routing_type = ROUTING_ERRORS
    elif len(distinct_segs) == 1 and not has_microsoft and not has_google:
        analysis.routing_type = ROUTING_CLEAN   # single SEG, consistent
    elif has_microsoft and not analysis.has_seg and not has_google:
        analysis.routing_type = ROUTING_CLEAN   # Microsoft EOP only, consistent
    elif has_google and not analysis.has_seg and not has_microsoft:
        analysis.routing_type = ROUTING_CLEAN   # Google Workspace only, consistent
    else:
        analysis.routing_type = ROUTING_UNKNOWN

    # ── Collect redundant checks ───────────────────────────────────────────────
    redundant = set()
    for vendor in distinct_segs:
        for v, checks in SEG_REDUNDANT_CHECKS.items():
            if v in vendor or vendor in v:
                redundant.update(checks)
    analysis.redundant_checks = list(redundant)

    # ── Build summary and recommendations ─────────────────────────────────────
    if analysis.routing_type == ROUTING_MULTI_SEG:
        analysis.summary = (
            f"Multiple conflicting SEG vendors detected: {', '.join(distinct_segs)}. "
            f"Mail will only flow through the highest-priority gateway — the others "
            f"are receiving no traffic but create confusion and a false security impression."
        )
        analysis.recommendations = [
            f"Choose ONE primary SEG vendor and remove all others from DNS.",
            f"Detected vendors: {', '.join(distinct_segs)}.",
            "Having multiple SEG MX records does NOT provide redundancy between vendors — "
            "each SEG has its own policy set; mixing vendors means policies are inconsistent.",
            "After consolidating, verify all mail flows through the chosen SEG before EOP.",
            "Ensure an inbound connector restricts EOP to accept mail only from the chosen SEG IPs.",
        ]

    elif analysis.routing_type == ROUTING_SPLIT:
        seg_list = ', '.join(distinct_segs)
        analysis.summary = (
            f"SEG bypass risk: {seg_list} + Microsoft EOP MX records coexist. "
            f"Attackers can skip {seg_list} entirely by sending directly to the "
            f"Microsoft EOP MX record (*.protection.outlook.com)."
        )
        analysis.recommendations = [
            f"Remove the Microsoft EOP MX record from public DNS — mail must route exclusively through {seg_list}.",
            f"In Exchange Online, create an inbound connector that only accepts mail from {seg_list} IP ranges.",
            "Enable 'Enhanced Filtering for Connectors' so EOP evaluates the original sender IP.",
            "Add a transport rule to reject mail not arriving from the SEG connector.",
        ]

    elif analysis.routing_type == ROUTING_INCONSISTENT:
        analysis.summary = (
            "Inconsistent MX records: Microsoft EOP and Google Workspace MX hosts coexist. "
            "These are mail platforms for two different services — having both is almost always a misconfiguration."
        )
        analysis.recommendations = [
            "Determine which mail platform is authoritative for this domain (Microsoft 365 or Google Workspace).",
            "Remove MX records that do not belong to the chosen platform.",
            "Having both Microsoft and Google MX records means mail may be split between two systems unpredictably.",
        ]

    elif analysis.routing_type == ROUTING_CLEAN and analysis.has_seg:
        seg_list = ', '.join(distinct_segs)
        analysis.summary = (
            f"Consistent SEG routing: {seg_list}. "
            f"All MX records point to the same gateway vendor."
        )
        analysis.recommendations = [
            f"Verify inbound connectors in Exchange Online restrict delivery to {seg_list} IPs only.",
            "Enable 'Enhanced Filtering for Connectors' in Microsoft 365 Defender.",
        ]
        if unresolvable:
            analysis.recommendations.insert(0, f"Fix unresolvable MX hosts: {', '.join(r.host for r in unresolvable)}")

    elif analysis.routing_type == ROUTING_CLEAN and has_microsoft:
        analysis.summary = "Mail flows directly through Microsoft EOP — no third-party SEG detected."
        analysis.recommendations = [
            "Ensure Microsoft Defender for Office 365 Safe Links and Safe Attachments are enabled.",
        ]

    elif analysis.routing_type == ROUTING_CLEAN and has_google:
        analysis.summary = "Mail routes through Google Workspace MX — consistent configuration."
        analysis.recommendations = [
            "Ensure Google Workspace email security settings (DMARC, DKIM, 2SV) are properly configured.",
        ]

    elif analysis.routing_type == ROUTING_ERRORS:
        analysis.summary = f"MX host(s) do not resolve: {', '.join(r.host for r in unresolvable)}. Mail delivery will fail."
        analysis.recommendations = [
            "Check DNS A records for all MX hosts.",
            "Remove or replace unresolvable MX entries immediately.",
        ]

    else:
        analysis.summary = f"Unrecognized MX configuration: {', '.join(r.host for r in analysis.raw_records)}"
        analysis.recommendations = ["Verify your MX records and mail routing path."]

    return analysis
