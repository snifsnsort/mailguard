"""
auth_analyzer.py — MailGuard V2 / Authentication Health  (v2.1)

Upgrade summary over v2.0:
  - Scoring rebuilt: SPF(30) + DMARC(35) + DKIM(25) + Cross(10) = 100
  - Provider-aware DKIM selector discovery — prioritises selectors for the
    detected sending platform before falling back to the generic list
  - MX-based provider detection — supplements SPF/DKIM signal
  - DMARC external reporting authorisation check (RFC 7489 §7.1)
  - SPF-only alignment dependency finding — DMARC p=reject/quarantine
    with no DKIM means forwarded mail will break authentication
  - Sender platform consistency analysis — catches SPF providers not
    corroborated by DKIM or MX (potential orphaned authorisations)
  - Richer finding format — every finding includes an `impact` key in
    its evidence dict for structured display in the UI

Finding id scheme: auth-{protocol}-{check}-{domain}
  auth-spf-missing-{d}                  CRITICAL
  auth-spf-multiple-{d}                 CRITICAL
  auth-spf-pass-all-{d}                 CRITICAL
  auth-spf-softfail-{d}                 MEDIUM
  auth-spf-neutral-{d}                  MEDIUM
  auth-spf-no-terminator-{d}            MEDIUM
  auth-spf-ptr-{d}                      LOW
  auth-spf-lookup-exceeded-{d}          CRITICAL
  auth-spf-lookup-warning-{d}           MEDIUM
  auth-dmarc-missing-{d}                CRITICAL
  auth-dmarc-multiple-{d}               CRITICAL
  auth-dmarc-none-{d}                   MEDIUM
  auth-dmarc-quarantine-{d}             LOW
  auth-dmarc-pct-partial-{d}            MEDIUM
  auth-dmarc-no-reporting-{d}           LOW
  auth-dmarc-weak-subdomain-{d}         MEDIUM
  auth-dmarc-ext-reporting-{d}          INFO   (new)
  auth-dkim-missing-{d}                 MEDIUM
  auth-dkim-weak-key-{sel}              CRITICAL
  auth-dkim-short-key-{sel}             LOW
  auth-cross-gap-{d}                    CRITICAL
  auth-cross-spf-only-alignment-{d}     MEDIUM  (new)
  auth-cross-no-dmarc-spf-{d}           MEDIUM
  auth-cross-no-dmarc-dkim-{d}          MEDIUM
  auth-cross-weak-triangle-{d}          MEDIUM
  auth-cross-platform-consistency-{d}   LOW     (new)
  auth-cross-provider-mismatch-{d}      LOW
  auth-summary-{d}                      INFO
"""

import asyncio
import base64
import re
import time
import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import dns.asyncresolver
import dns.resolver

from app.models.v2.scan_request import ScanRequest
from app.models.v2.scan_result import ScanResult
from app.models.v2.finding import Finding

logger = logging.getLogger(__name__)

MODULE_VERSION = "v2.1"

# ---------------------------------------------------------------------------
# Scoring model
#
# Health score = SPF_pts + DMARC_pts + DKIM_pts + Cross_pts  (max 100)
#
# Calibration:
#   SPF -all (30) + DMARC p=reject pct=100 (35) + DKIM missing (0) + Cross (6) = 71
#   Matches spec target of ~70-75 for this configuration.
# ---------------------------------------------------------------------------

SPF_SCORE = {
    "missing":             0,
    "multiple":            6,
    "+all":                5,
    "?all":               12,
    "missing_terminator": 14,
    "~all":               22,
    "-all":               30,
}
SPF_DEDUCT_LOOKUP_EXCEEDED = 3
SPF_DEDUCT_PTR             = 1

DMARC_SCORE = {
    "missing":           0,
    "multiple":          4,
    "none":              8,
    "quarantine_partial": 16,
    "quarantine_full":   22,
    "reject_partial":    27,
    "reject_full":       35,
}

DKIM_SCORE = {
    "missing":    0,
    "weak_key":   8,
    "short_key": 18,
    "present":   25,
}

CROSS_SCORE = {
    "all_three_enforcing":  10,
    "spf_dmarc_only":        6,
    "dmarc_dkim_only":       5,
    "spf_dkim_no_dmarc":     3,
    "dmarc_no_spf_dkim":     2,
    "nothing_enforcing":     0,
}

# ---------------------------------------------------------------------------
# Provider catalogues
# ---------------------------------------------------------------------------

SPF_PROVIDER_MAP: Dict[str, str] = {
    "spf.protection.outlook.com":   "Microsoft 365",
    "_spf.google.com":              "Google Workspace",
    "sendgrid.net":                 "SendGrid",
    "amazonses.com":                "Amazon SES",
    "mailgun.org":                  "Mailgun",
    "spf.mandrillapp.com":          "Mandrill (Mailchimp)",
    "spf.mailchimp.com":            "Mailchimp",
    "servers.mcsv.net":             "Mailchimp",
    "pm.mtasv.net":                 "Postmark",
    "_spf.salesforce.com":          "Salesforce",
    "spf.exacttarget.com":          "Salesforce Marketing Cloud",
    "spf.hubspot.com":              "HubSpot",
    "spf.marketo.com":              "Marketo",
    "mktomail.com":                 "Marketo",
    "spf.zohomail.com":             "Zoho Mail",
    "pphosted.com":                 "Proofpoint",
    "ppe-hosted.com":               "Proofpoint Essentials",
    "mimecast.com":                 "Mimecast",
    "barracudanetworks.com":        "Barracuda",
    "iphmx.com":                    "Cisco IronPort",
    "ess.cisco.com":                "Cisco Email Security",
    "mailcontrol.com":              "Forcepoint",
    "messagelabs.com":              "Broadcom (MessageLabs)",
    "symanteccloud.com":            "Broadcom (Symantec)",
    "sparkpostmail.com":            "SparkPost",
    "freshdesk.com":                "Freshdesk",
    "spf1.eloqua.com":              "Oracle Eloqua",
    "zendesk.com":                  "Zendesk",
    "intercom.io":                  "Intercom",
}

MX_PROVIDER_MAP: Dict[str, str] = {
    "mail.protection.outlook.com":  "Microsoft 365",
    "protection.outlook.com":       "Microsoft 365",
    "google.com":                   "Google Workspace",
    "googlemail.com":               "Google Workspace",
    "aspmx.l.google.com":           "Google Workspace",
    "pphosted.com":                 "Proofpoint",
    "ppe-hosted.com":               "Proofpoint Essentials",
    "mimecast.com":                 "Mimecast",
    "barracudanetworks.com":        "Barracuda",
    "iphmx.com":                    "Cisco IronPort",
    "messagelabs.com":              "Broadcom (MessageLabs)",
    "symanteccloud.com":            "Broadcom (Symantec)",
    "mailcontrol.com":              "Forcepoint",
    "hornetsecurity.com":           "Hornetsecurity",
    "antispamcloud.com":            "Hornetsecurity",
    "emailsrvr.com":                "Rackspace",
    "zoho.com":                     "Zoho Mail",
}

DKIM_SELECTOR_PLATFORM_MAP: Dict[str, str] = {
    "selector1":    "Microsoft 365",
    "selector2":    "Microsoft 365",
    "google":       "Google Workspace",
    "sendgrid":     "SendGrid",
    "s1":           "SendGrid",
    "s2":           "SendGrid",
    "sm":           "Mandrill",
    "pm":           "Postmark",
    "postmarkapp":  "Postmark",
    "mandrill":     "Mandrill",
    "mailgun":      "Mailgun",
    "k1":           "Mailchimp",
    "k2":           "Mailchimp",
    "mxvault":      "Mimecast",
    "proofpoint":   "Proofpoint",
    "pphosted":     "Proofpoint",
}

# Provider-specific selectors to try first (before the generic list)
PROVIDER_PRIORITY_SELECTORS: Dict[str, List[str]] = {
    "Microsoft 365":              ["selector1", "selector2"],
    "Google Workspace":           ["google", "default"],
    "Proofpoint":                 ["proofpoint", "pphosted", "selector1", "selector2"],
    "Proofpoint Essentials":      ["proofpoint", "selector1", "selector2"],
    "Mimecast":                   ["mxvault", "selector1", "selector2"],
    "SendGrid":                   ["s1", "s2", "sendgrid"],
    "Mailchimp":                  ["k1", "k2"],
    "Mandrill (Mailchimp)":       ["sm"],
    "Postmark":                   ["pm", "postmarkapp"],
    "Mailgun":                    ["mailgun"],
    "Amazon SES":                 ["mail", "email", "smtp"],
    "Salesforce":                 ["selector1", "selector2", "mail"],
    "Salesforce Marketing Cloud": ["selector1", "selector2", "mail"],
    "HubSpot":                    ["selector1", "selector2"],
    "Barracuda":                  ["selector1", "selector2"],
    "Cisco IronPort":             ["selector1", "selector2"],
    "Cisco Email Security":       ["selector1", "selector2"],
    "Forcepoint":                 ["selector1", "selector2"],
    "Broadcom (MessageLabs)":     ["selector1", "selector2"],
    "Broadcom (Symantec)":        ["selector1", "selector2"],
    "Zoho Mail":                  ["zoho", "mail", "selector1"],
    "SparkPost":                  ["scph", "selector1", "selector2"],
}

GENERIC_SELECTORS: List[str] = [
    "selector1", "selector2", "default", "google", "k1", "k2",
    "smtp", "mail", "dkim", "mta", "email", "s1", "s2", "key1", "key2",
    "mxvault", "mx", "proofpoint", "mimecast", "sm", "pm",
    "postmarkapp", "mandrill", "mailgun", "sendgrid",
]


def _build_selector_list(detected_providers: List[str]) -> List[str]:
    """Build a deduplicated, prioritised DKIM selector list."""
    ordered: List[str] = []
    for provider in detected_providers:
        for sel in PROVIDER_PRIORITY_SELECTORS.get(provider, []):
            if sel not in ordered:
                ordered.append(sel)
    for sel in GENERIC_SELECTORS:
        if sel not in ordered:
            ordered.append(sel)
    return ordered


# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------

async def _resolve_txt(name: str) -> List[str]:
    """Resolve TXT records; return empty list on any failure."""
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 4
        resolver.lifetime = 6
        answers = await resolver.resolve(name, "TXT")
        results = []
        for rdata in answers:
            txt = "".join(
                s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                for s in rdata.strings
            )
            results.append(txt)
        return results
    except Exception:
        return []


async def _resolve_mx_hosts(domain: str) -> List[str]:
    """Resolve MX records and return the list of mail host names."""
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 4
        resolver.lifetime = 6
        answers = await resolver.resolve(domain, "MX")
        return [str(r.exchange).lower().rstrip(".") for r in answers]
    except Exception:
        return []


async def _resolve_dkim(selector: str, domain: str) -> dict:
    """
    Attempt to retrieve one DKIM public key TXT record.
    Returns a result dict with: selector, fqdn, valid, record, key_type, key_bits, platform.
    """
    fqdn = f"{selector}._domainkey.{domain}"
    records = await _resolve_txt(fqdn)
    if not records:
        return {"selector": selector, "fqdn": fqdn, "valid": False}

    record = records[0]
    result: dict = {"selector": selector, "fqdn": fqdn, "valid": True, "record": record}

    kt = re.search(r'\bk=(\w+)', record)
    result["key_type"] = kt.group(1).lower() if kt else "rsa"

    p = re.search(r'\bp=([A-Za-z0-9+/=]+)', record)
    if p:
        b64 = p.group(1)
        if not b64:
            result["valid"] = False
            result["error"] = "key revoked (p= is empty)"
        else:
            try:
                key_bytes = base64.b64decode(b64 + "==")
                result["key_bits"] = len(key_bytes) * 8 // 10
            except Exception:
                pass

    result["platform"] = DKIM_SELECTOR_PLATFORM_MAP.get(selector)
    if not result["platform"]:
        rl = record.lower()
        for kw, platform in [
            ("google",   "Google Workspace"),
            ("outlook",  "Microsoft 365"),
            ("sendgrid", "SendGrid"),
            ("mailgun",  "Mailgun"),
            ("amazon",   "Amazon SES"),
        ]:
            if kw in rl:
                result["platform"] = platform
                break

    return result


async def _check_dmarc_external_reporting_auth(
    domain: str,
    reporting_addresses: List[str],
) -> List[str]:
    """
    RFC 7489 §7.1: verify external DMARC reporting authorisation.

    When rua/ruf points to an external domain, that domain must publish:
      {domain}._report._dmarc.{external-domain}  TXT  "v=DMARC1;"

    Returns a list of external domains that are NOT authorised.
    """
    unauthorised: List[str] = []
    checked: set = set()

    for addr in reporting_addresses:
        m = re.search(r'mailto:[^@]+@([\w.\-]+)', addr, re.IGNORECASE)
        if not m:
            continue
        ext_domain = m.group(1).lower()
        if ext_domain == domain or ext_domain in checked:
            continue
        domain_apex = ".".join(domain.split(".")[-2:])
        ext_apex    = ".".join(ext_domain.split(".")[-2:])
        if domain_apex == ext_apex:
            checked.add(ext_domain)
            continue
        checked.add(ext_domain)
        auth_fqdn = f"{domain}._report._dmarc.{ext_domain}"
        records   = await _resolve_txt(auth_fqdn)
        is_authorised = any(r.lower().startswith("v=dmarc1") for r in records)
        if not is_authorised:
            unauthorised.append(ext_domain)

    return unauthorised


# ---------------------------------------------------------------------------
# Internal analysis dataclasses
# ---------------------------------------------------------------------------

@dataclass
class _SpfAnalysis:
    present:      bool = False
    record:       Optional[str] = None
    policy:       Optional[str] = None
    multiple:     bool = False
    includes:     List[str] = field(default_factory=list)
    lookup_count: int = 0
    providers:    List[str] = field(default_factory=list)
    score:        int = 0
    findings:     List[Finding] = field(default_factory=list)


@dataclass
class _DmarcAnalysis:
    present:          bool = False
    record:           Optional[str] = None
    policy:           Optional[str] = None
    subdomain_policy: Optional[str] = None
    pct:              int = 100
    rua:              List[str] = field(default_factory=list)
    ruf:              List[str] = field(default_factory=list)
    aspf:             str = "r"
    adkim:            str = "r"
    multiple:         bool = False
    score:            int = 0
    findings:         List[Finding] = field(default_factory=list)


@dataclass
class _DkimAnalysis:
    selectors:         List[dict] = field(default_factory=list)
    providers:         List[str] = field(default_factory=list)
    selectors_checked: List[str] = field(default_factory=list)
    score:             int = 0
    findings:          List[Finding] = field(default_factory=list)


@dataclass
class _MxAnalysis:
    hosts:     List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Phase 2 — SPF analysis
# ---------------------------------------------------------------------------

def _extract_spf_providers(a: _SpfAnalysis, record: str) -> None:
    rl = record.lower()
    for pattern, provider in SPF_PROVIDER_MAP.items():
        if pattern in rl and provider not in a.providers:
            a.providers.append(provider)


def _analyze_spf(domain: str, txt_records: List[str]) -> _SpfAnalysis:
    a = _SpfAnalysis()
    spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]

    if not spf_records:
        a.score = SPF_SCORE["missing"]
        a.findings.append(Finding(
            id=f"auth-spf-missing-{domain}",
            category="authentication",
            severity="critical",
            title="No SPF record found",
            description=(
                f"{domain} has no SPF record. Any mail server can send email claiming "
                "to originate from this domain and pass SPF evaluation."
            ),
            recommended_action=(
                "Publish a TXT record at the domain root specifying authorised senders, "
                "e.g. v=spf1 include:spf.protection.outlook.com -all"
            ),
            evidence={
                "domain": domain,
                "impact": (
                    "Phishing campaigns using this domain as the envelope sender will not "
                    "trigger SPF failures, reducing the effectiveness of downstream filters."
                ),
            },
        ))
        return a

    if len(spf_records) > 1:
        a.present  = True
        a.record   = spf_records[0]
        a.multiple = True
        a.score    = SPF_SCORE["multiple"]
        a.findings.append(Finding(
            id=f"auth-spf-multiple-{domain}",
            category="authentication",
            severity="critical",
            title=f"Multiple SPF records detected ({len(spf_records)})",
            description=(
                f"{domain} has {len(spf_records)} SPF TXT records. RFC 7208 §3.2 permits "
                "exactly one. Multiple records cause PermError — SPF evaluation fails entirely."
            ),
            recommended_action=(
                "Merge all mechanisms into a single TXT record and delete duplicates."
            ),
            evidence={
                "records": spf_records,
                "impact": (
                    "SPF evaluation returns PermError. The domain receives no SPF "
                    "protection until the duplicate is removed."
                ),
            },
        ))
        _extract_spf_providers(a, spf_records[0])
        return a

    a.present = True
    record    = spf_records[0]
    a.record  = record

    all_m = re.search(r'([+~\-?]?)all\b', record, re.IGNORECASE)
    if all_m:
        q = all_m.group(1) or "+"
        a.policy = {"+": "+all", "~": "~all", "-": "-all", "?": "?all"}.get(q, "+all")
    else:
        a.policy = "missing"

    policy_key_map = {
        "+all": "+all", "~all": "~all", "-all": "-all",
        "?all": "?all", "missing": "missing_terminator",
    }
    a.score = SPF_SCORE.get(policy_key_map.get(a.policy, "missing_terminator"), 0)

    if a.policy == "+all":
        a.findings.append(Finding(
            id=f"auth-spf-pass-all-{domain}",
            category="authentication",
            severity="critical",
            title='SPF record uses "+all" — unrestricted spoofing permitted',
            description=(
                f'The SPF record for {domain} ends with "+all", which passes SPF for any IP. '
                "This is equivalent to no SPF protection."
            ),
            recommended_action='Replace "+all" with "-all" immediately.',
            evidence={
                "record": record,
                "impact": (
                    "Any attacker can send mail as this domain and receive a PASS SPF result. "
                    "DMARC enforcement becomes ineffective."
                ),
            },
        ))
    elif a.policy == "~all":
        a.findings.append(Finding(
            id=f"auth-spf-softfail-{domain}",
            category="authentication",
            severity="medium",
            title='SPF policy is "~all" (SoftFail) — unauthorised senders tagged, not rejected',
            description=(
                f'The SPF record for {domain} uses "~all". Unauthorised senders receive '
                "SoftFail — most servers deliver these messages normally."
            ),
            recommended_action='Upgrade to "-all" once all sending sources are confirmed.',
            evidence={
                "record": record,
                "impact": (
                    "Spoofed mail is tagged but not blocked. Without DMARC enforcement, "
                    "recipients still receive the message."
                ),
            },
        ))
    elif a.policy == "?all":
        a.findings.append(Finding(
            id=f"auth-spf-neutral-{domain}",
            category="authentication",
            severity="medium",
            title='SPF policy is "?all" (Neutral) — equivalent to no SPF policy',
            description=(
                f'The SPF record for {domain} ends with "?all". Neutral provides no '
                "guidance — treated identically to having no SPF policy."
            ),
            recommended_action='Replace "?all" with "-all".',
            evidence={
                "record": record,
                "impact": "Any sender passes SPF evaluation for this domain.",
            },
        ))
    elif a.policy == "missing":
        a.findings.append(Finding(
            id=f"auth-spf-no-terminator-{domain}",
            category="authentication",
            severity="medium",
            title='SPF record has no "all" terminator — behaviour is implementation-defined',
            description=(
                f"The SPF record for {domain} has no 'all' mechanism. "
                "RFC 7208 §5.1 defaults non-matching senders to Neutral."
            ),
            recommended_action='Append "-all" to the SPF record.',
            evidence={
                "record": record,
                "impact": "Unenforced SPF — unauthorised senders are not explicitly rejected.",
            },
        ))

    if re.search(r'\bptr\b', record, re.IGNORECASE):
        a.score = max(0, a.score - SPF_DEDUCT_PTR)
        a.findings.append(Finding(
            id=f"auth-spf-ptr-{domain}",
            category="authentication",
            severity="low",
            title='SPF record uses deprecated "ptr" mechanism',
            description=(
                "The 'ptr' mechanism is deprecated per RFC 7208 §5.5. "
                "It adds DNS lookups and is slow and unreliable."
            ),
            recommended_action="Remove 'ptr' and replace with explicit ip4:, ip6:, or include: entries.",
            evidence={
                "record": record,
                "impact": "Increases DNS lookup count; risks PermError on lookup-intensive records.",
            },
        ))

    lookup_mechs = re.findall(
        r'\b(?:include|a|mx|ptr|exists|redirect)(?::|/|\s|$)',
        record, re.IGNORECASE,
    )
    a.lookup_count = len(lookup_mechs)

    if a.lookup_count > 10:
        a.score = max(0, a.score - SPF_DEDUCT_LOOKUP_EXCEEDED)
        a.findings.append(Finding(
            id=f"auth-spf-lookup-exceeded-{domain}",
            category="authentication",
            severity="critical",
            title=f"SPF record exceeds 10 DNS lookup limit ({a.lookup_count} lookups detected)",
            description=(
                f"RFC 7208 §4.6.4 limits SPF to 10 DNS lookups. "
                f"This record requires approximately {a.lookup_count}. Receivers return PermError."
            ),
            recommended_action=(
                "Flatten SPF includes by replacing include: chains with direct ip4:/ip6: entries."
            ),
            evidence={
                "record":       record,
                "lookup_count": a.lookup_count,
                "impact": (
                    "SPF evaluation fails with PermError — the domain is treated as "
                    "having no SPF record, removing all SPF-based protection."
                ),
            },
        ))
    elif a.lookup_count >= 9:
        a.score = max(0, a.score - SPF_DEDUCT_LOOKUP_EXCEEDED)
        a.findings.append(Finding(
            id=f"auth-spf-lookup-warning-{domain}",
            category="authentication",
            severity="medium",
            title=f"SPF record approaching 10 DNS lookup limit ({a.lookup_count}/10)",
            description=(
                f"Approximately {a.lookup_count} DNS lookups required. "
                "Adding any further sender will exceed the RFC 7208 limit."
            ),
            recommended_action="Audit and flatten SPF includes before onboarding new senders.",
            evidence={
                "record":       record,
                "lookup_count": a.lookup_count,
                "impact": (
                    "One additional sender will silently break SPF evaluation for the entire domain."
                ),
            },
        ))

    a.includes = re.findall(r'include:(\S+)', record, re.IGNORECASE)
    _extract_spf_providers(a, record)
    return a


# ---------------------------------------------------------------------------
# Phase 3 — DMARC analysis
# ---------------------------------------------------------------------------

def _analyze_dmarc(domain: str, dmarc_records: List[str]) -> _DmarcAnalysis:
    a = _DmarcAnalysis()
    valid = [r for r in dmarc_records if r.lower().startswith("v=dmarc1")]

    if not valid:
        a.score = DMARC_SCORE["missing"]
        a.findings.append(Finding(
            id=f"auth-dmarc-missing-{domain}",
            category="authentication",
            severity="critical",
            title="No DMARC record found",
            description=(
                f"{domain} has no DMARC record at _dmarc.{domain}. The visible From: "
                "header used in phishing is completely unprotected regardless of SPF/DKIM."
            ),
            recommended_action=(
                f"Publish a DMARC record at _dmarc.{domain}. Start with p=none, "
                "collect aggregate reports, then advance to p=quarantine and p=reject."
            ),
            evidence={
                "domain": domain,
                "impact": (
                    "Header spoofing attacks impersonating this domain are undetected "
                    "and unblocked. SPF and DKIM alone do not protect the From: header."
                ),
            },
        ))
        return a

    if len(valid) > 1:
        a.present  = True
        a.record   = valid[0]
        a.multiple = True
        a.score    = DMARC_SCORE["multiple"]
        a.findings.append(Finding(
            id=f"auth-dmarc-multiple-{domain}",
            category="authentication",
            severity="critical",
            title=f"Multiple DMARC records found ({len(valid)})",
            description=(
                f"{domain} has {len(valid)} DMARC records. RFC 7489 §6.6.3 requires exactly "
                "one. Multiple records cause undefined behaviour — receivers may apply no policy."
            ),
            recommended_action="Delete all but one DMARC record.",
            evidence={
                "records": valid,
                "impact": (
                    "DMARC evaluation is undefined. Receiving servers may apply no policy, "
                    "negating all DMARC protection."
                ),
            },
        ))
        return a

    a.present = True
    record    = valid[0]
    a.record  = record

    pm = re.search(r'\bp=(\w+)', record, re.IGNORECASE)
    a.policy = pm.group(1).lower() if pm else "none"

    pct_m = re.search(r'\bpct=(\d+)', record, re.IGNORECASE)
    a.pct = int(pct_m.group(1)) if pct_m else 100

    if a.policy == "reject":
        a.score = DMARC_SCORE["reject_full"] if a.pct == 100 else DMARC_SCORE["reject_partial"]
    elif a.policy == "quarantine":
        a.score = DMARC_SCORE["quarantine_full"] if a.pct == 100 else DMARC_SCORE["quarantine_partial"]
    else:
        a.score = DMARC_SCORE["none"]

    if a.policy == "none":
        a.findings.append(Finding(
            id=f"auth-dmarc-none-{domain}",
            category="authentication",
            severity="medium",
            title="DMARC policy is p=none — monitoring mode only, no enforcement",
            description=(
                f"The DMARC policy for {domain} is p=none. Mail that fails authentication "
                "is delivered normally — the policy has no effect on mail flow."
            ),
            recommended_action=(
                "Review aggregate DMARC reports, then advance to p=quarantine and p=reject."
            ),
            evidence={
                "record": record,
                "impact": (
                    "Spoofed mail passes to recipients' inboxes unchallenged. "
                    "Domain impersonation in phishing campaigns is not blocked."
                ),
            },
        ))
    elif a.policy == "quarantine":
        a.findings.append(Finding(
            id=f"auth-dmarc-quarantine-{domain}",
            category="authentication",
            severity="low",
            title="DMARC policy is p=quarantine — consider upgrading to p=reject",
            description=(
                f"The DMARC policy for {domain} sends failing mail to spam. "
                "Spoofed messages still reach recipients in their spam folder."
            ),
            recommended_action="After confirming all senders pass DMARC, upgrade to p=reject.",
            evidence={
                "record": record,
                "impact": (
                    "Spoofed mail reaches recipients in spam. "
                    "Users who check spam remain exposed to phishing content."
                ),
            },
        ))

    sp = re.search(r'\bsp=(\w+)', record, re.IGNORECASE)
    a.subdomain_policy = sp.group(1).lower() if sp else a.policy
    policy_rank = {"reject": 3, "quarantine": 2, "none": 1}
    if policy_rank.get(a.subdomain_policy, 0) < policy_rank.get(a.policy, 0):
        a.findings.append(Finding(
            id=f"auth-dmarc-weak-subdomain-{domain}",
            category="authentication",
            severity="medium",
            title=f"Subdomain DMARC policy (sp={a.subdomain_policy}) is weaker than main policy (p={a.policy})",
            description=(
                f"The main policy is p={a.policy} but subdomains are governed by sp={a.subdomain_policy}. "
                "Subdomains are frequently targeted in phishing because they are overlooked."
            ),
            recommended_action=f"Set sp={a.policy} to apply the same enforcement to all subdomains.",
            evidence={
                "record": record,
                "p":  a.policy,
                "sp": a.subdomain_policy,
                "impact": (
                    f"Subdomains of {domain} have weaker protection than the apex domain "
                    "and are easier targets for impersonation."
                ),
            },
        ))

    if a.pct < 100 and a.policy != "none":
        a.findings.append(Finding(
            id=f"auth-dmarc-pct-partial-{domain}",
            category="authentication",
            severity="medium",
            title=f"DMARC pct={a.pct} — policy applies to only {a.pct}% of failing mail",
            description=(
                f"The pct tag limits enforcement to {a.pct}% of failing mail. "
                f"The remaining {100 - a.pct}% is treated one policy level lower."
            ),
            recommended_action="Set pct=100 for full enforcement.",
            evidence={
                "record": record,
                "pct":    a.pct,
                "impact": (
                    f"{100 - a.pct}% of spoofed or failing mail bypasses the declared policy. "
                    "The effective protection level is lower than the p= tag implies."
                ),
            },
        ))

    rua_m = re.search(r'\brua=([^\s;]+)', record, re.IGNORECASE)
    ruf_m = re.search(r'\bruf=([^\s;]+)', record, re.IGNORECASE)
    a.rua = [x.strip() for x in rua_m.group(1).split(",")] if rua_m else []
    a.ruf = [x.strip() for x in ruf_m.group(1).split(",")] if ruf_m else []

    if not a.rua:
        a.findings.append(Finding(
            id=f"auth-dmarc-no-reporting-{domain}",
            category="authentication",
            severity="low",
            title="No DMARC aggregate reporting address (rua=) configured",
            description=(
                f"The DMARC record for {domain} has no rua= tag. Without aggregate reports, "
                "you have no visibility into authentication failures or spoofing activity."
            ),
            recommended_action=(
                f"Add rua=mailto:dmarc@{domain} or use a third-party DMARC reporting service."
            ),
            evidence={
                "record": record,
                "impact": (
                    "No data on authentication failures is collected. "
                    "Safe advancement toward p=reject is impossible without reporting data."
                ),
            },
        ))

    aspf_m  = re.search(r'\baspf=([rs])',  record, re.IGNORECASE)
    adkim_m = re.search(r'\badkim=([rs])', record, re.IGNORECASE)
    a.aspf  = aspf_m.group(1).lower()  if aspf_m  else "r"
    a.adkim = adkim_m.group(1).lower() if adkim_m else "r"

    return a


# ---------------------------------------------------------------------------
# Phase 4 — DKIM analysis (provider-aware)
# ---------------------------------------------------------------------------

async def _analyze_dkim(
    domain: str,
    spf_providers: List[str],
    mx_providers: List[str],
) -> _DkimAnalysis:
    """Provider-aware DKIM selector discovery."""
    a = _DkimAnalysis()
    all_detected  = list(dict.fromkeys(spf_providers + mx_providers))
    selector_list = _build_selector_list(all_detected)
    a.selectors_checked = selector_list

    tasks   = [_resolve_dkim(sel, domain) for sel in selector_list]
    results = await asyncio.gather(*tasks)
    a.selectors = [r for r in results if r.get("valid")]

    if not a.selectors:
        a.score = DKIM_SCORE["missing"]
        a.findings.append(Finding(
            id=f"auth-dkim-missing-{domain}",
            category="authentication",
            severity="medium",
            title="DKIM signing not detected for this domain",
            description=(
                f"No DKIM public key records were found for {domain} after checking "
                f"{len(selector_list)} selectors (including provider-specific selectors for: "
                f"{', '.join(all_detected) if all_detected else 'no detected providers'}). "
                "Without DKIM, outbound mail cannot be cryptographically signed."
            ),
            recommended_action=(
                "Enable DKIM signing in your mail platform and publish the public key at "
                f"<selector>._domainkey.{domain}. If a non-standard selector is in use, "
                "verify it manually."
            ),
            evidence={
                "selectors_checked": selector_list,
                "providers_checked": all_detected,
                "impact": (
                    "DMARC alignment can only be achieved via SPF. Forwarded mail will "
                    "fail DMARC because SPF breaks on forwarding. DKIM provides a "
                    "resilient second alignment path that survives forwarding."
                ),
            },
        ))
        return a

    worst_tier = "present"

    for s in a.selectors:
        bits = s.get("key_bits")
        if bits is not None and bits < 1024:
            worst_tier = "weak_key"
            a.findings.append(Finding(
                id=f"auth-dkim-weak-key-{s['selector']}",
                category="authentication",
                severity="critical",
                title=f"DKIM selector '{s['selector']}' uses a cryptographically weak key (~{bits} bits)",
                description=(
                    f"The DKIM key for '{s['selector']}' on {domain} is ~{bits} bits. "
                    "RFC 6376 §3.3.3 requires minimum 1024 bits. Sub-1024 keys can be factored."
                ),
                recommended_action=f"Rotate selector '{s['selector']}' to a 2048-bit RSA key immediately.",
                evidence={
                    "selector": s["selector"],
                    "fqdn":     s["fqdn"],
                    "key_bits": bits,
                    "impact": (
                        "An attacker who factors the private key can forge valid DKIM "
                        "signatures for any mail from this domain."
                    ),
                },
            ))
        elif bits is not None and bits < 2048:
            if worst_tier == "present":
                worst_tier = "short_key"
            a.findings.append(Finding(
                id=f"auth-dkim-short-key-{s['selector']}",
                category="authentication",
                severity="low",
                title=f"DKIM selector '{s['selector']}' uses a 1024-bit key — 2048 bits recommended",
                description=(
                    f"The DKIM key for '{s['selector']}' on {domain} is ~{bits} bits. "
                    "NIST SP 800-131A recommends migrating to 2048-bit RSA."
                ),
                recommended_action="Plan a key rotation to 2048-bit RSA at the next scheduled cycle.",
                evidence={
                    "selector": s["selector"],
                    "fqdn":     s["fqdn"],
                    "key_bits": bits,
                    "impact": (
                        "1024-bit RSA is approaching practical factorability. "
                        "Proactive rotation reduces long-term key compromise risk."
                    ),
                },
            ))

    a.score = DKIM_SCORE[worst_tier]

    for s in a.selectors:
        p = s.get("platform")
        if p and p not in a.providers:
            a.providers.append(p)

    return a


# ---------------------------------------------------------------------------
# MX provider classification
# ---------------------------------------------------------------------------

def _classify_mx_providers(mx_hosts: List[str]) -> List[str]:
    providers: List[str] = []
    for host in mx_hosts:
        h = host.lower().rstrip(".")
        for pattern, provider in MX_PROVIDER_MAP.items():
            if h.endswith(pattern) and provider not in providers:
                providers.append(provider)
                break
    return providers


# ---------------------------------------------------------------------------
# Phase 5 — Cross-protocol analysis
# ---------------------------------------------------------------------------

async def _cross_analysis(
    domain: str,
    spf: _SpfAnalysis,
    dmarc: _DmarcAnalysis,
    dkim: _DkimAnalysis,
    mx: _MxAnalysis,
) -> Tuple[List[Finding], int]:
    findings: List[Finding] = []

    has_spf        = spf.present and not spf.multiple
    has_dkim       = bool(dkim.selectors)
    has_dmarc      = dmarc.present and not dmarc.multiple
    dmarc_enforced = has_dmarc and dmarc.policy in ("quarantine", "reject")

    # Authentication gap
    if has_dmarc and not has_spf and not has_dkim:
        findings.append(Finding(
            id=f"auth-cross-gap-{domain}",
            category="authentication",
            severity="critical",
            title="Authentication gap: DMARC present but neither SPF nor DKIM configured",
            description=(
                f"{domain} has DMARC but no SPF and no DKIM. DMARC requires at least one "
                "of SPF or DKIM to align. With neither, all mail fails DMARC — legitimate "
                "mail may be rejected while spoofed mail is equally affected."
            ),
            recommended_action="Configure SPF and enable DKIM signing before enforcing DMARC.",
            evidence={
                "domain": domain,
                "impact": (
                    "The DMARC record is non-functional. No alignment path is available — "
                    "the policy provides no protective or discriminating value."
                ),
            },
        ))

    # SPF-only alignment dependency (new in v2.1)
    if dmarc_enforced and has_spf and not has_dkim:
        findings.append(Finding(
            id=f"auth-cross-spf-only-alignment-{domain}",
            category="authentication",
            severity="medium",
            title=(
                f"DMARC enforcement relies solely on SPF alignment "
                f"(p={dmarc.policy}, DKIM not configured)"
            ),
            description=(
                f"DMARC for {domain} is enforcing (p={dmarc.policy}) but DKIM is absent. "
                "The only alignment path is SPF. SPF alignment breaks on mail forwarding "
                "because the envelope sender is rewritten to the forwarder's domain — "
                "legitimate forwarded mail will fail DMARC and be "
                f"{'rejected' if dmarc.policy == 'reject' else 'quarantined'}."
            ),
            recommended_action=(
                "Enable DKIM signing. DKIM signatures survive forwarding because they are "
                "carried in message headers, not the envelope. DKIM provides a resilient "
                "second alignment path."
            ),
            evidence={
                "dmarc_policy": dmarc.policy,
                "impact": (
                    "Forwarded mail from legitimate sources — mailing lists, auto-forwards, "
                    "compliance BCC archives — will fail DMARC and be blocked or quarantined."
                ),
            },
        ))

    # SPF with no DMARC
    if has_spf and not has_dmarc:
        findings.append(Finding(
            id=f"auth-cross-no-dmarc-spf-{domain}",
            category="authentication",
            severity="medium",
            title="SPF configured but no DMARC — visible From: header is unprotected",
            description=(
                f"{domain} has SPF but no DMARC. SPF validates the envelope sender, "
                "not the visible From: header. Phishing attacks spoof the From: header — "
                "SPF does not prevent this."
            ),
            recommended_action=f"Publish a DMARC record at _dmarc.{domain} starting with p=none.",
            evidence={
                "domain": domain,
                "impact": (
                    "Header spoofing attacks impersonating this domain pass SPF "
                    "and are delivered to recipients without challenge."
                ),
            },
        ))

    # DKIM with no DMARC
    if has_dkim and not has_dmarc:
        findings.append(Finding(
            id=f"auth-cross-no-dmarc-dkim-{domain}",
            category="authentication",
            severity="medium",
            title="DKIM configured but no DMARC — domain spoofing is unprotected",
            description=(
                f"{domain} has DKIM selectors but no DMARC. Without DMARC, there is no "
                "policy enforcing alignment between DKIM signing domain and the From: header."
            ),
            recommended_action=f"Publish a DMARC record at _dmarc.{domain}.",
            evidence={
                "domain": domain,
                "impact": (
                    "Spoofed mail signed by any domain passes DKIM. Without DMARC alignment "
                    "enforcement, DKIM alone does not protect the From: header."
                ),
            },
        ))

    # Weak enforcement triangle
    weak_spf = has_spf and spf.policy in ("~all", "?all", "+all", "missing")
    if weak_spf and not dmarc_enforced and not has_dkim:
        findings.append(Finding(
            id=f"auth-cross-weak-triangle-{domain}",
            category="authentication",
            severity="medium",
            title="Authentication posture: soft SPF, no DKIM, no DMARC enforcement",
            description=(
                f"{domain} has a non-enforcing SPF policy ({spf.policy}), no DKIM, and "
                "no DMARC enforcement. This combination provides a minimal barrier against spoofing."
            ),
            recommended_action=(
                "Priority: (1) deploy DMARC p=quarantine/reject, "
                "(2) harden SPF to -all, (3) enable DKIM signing."
            ),
            evidence={
                "spf_policy": spf.policy,
                "impact": (
                    "All three authentication layers are weak simultaneously. "
                    "Domain impersonation attacks face no meaningful technical barrier."
                ),
            },
        ))

    # External DMARC reporting authorisation (RFC 7489 §7.1)
    all_reporting = dmarc.rua + dmarc.ruf
    if all_reporting:
        unauthorised = await _check_dmarc_external_reporting_auth(domain, all_reporting)
        if unauthorised:
            for ext in unauthorised:
                findings.append(Finding(
                    id=f"auth-dmarc-ext-reporting-{domain}",
                    category="authentication",
                    severity="info",
                    title=f"External DMARC reporting destination may not be authorised: {ext}",
                    description=(
                        f"The DMARC record for {domain} sends reports to {ext}. "
                        f"RFC 7489 §7.1 requires {ext} to publish "
                        f"{domain}._report._dmarc.{ext} TXT 'v=DMARC1;' — this record was not found."
                    ),
                    recommended_action=(
                        f"Ask the operator of {ext} to publish: "
                        f"{domain}._report._dmarc.{ext} TXT \"v=DMARC1;\""
                    ),
                    evidence={
                        "reporting_domain": ext,
                        "required_record":  f"{domain}._report._dmarc.{ext}",
                        "impact": (
                            "Some receivers will not deliver aggregate reports to an "
                            "unauthorised external domain. You may receive incomplete DMARC data."
                        ),
                    },
                ))

    # Platform consistency (new in v2.1)
    if has_spf and spf.providers:
        all_other = set(dkim.providers) | set(mx.providers)
        spf_only  = [
            p for p in spf.providers
            if p not in all_other and p in PROVIDER_PRIORITY_SELECTORS
        ]
        if spf_only:
            findings.append(Finding(
                id=f"auth-cross-platform-consistency-{domain}",
                category="authentication",
                severity="low",
                title=(
                    "SPF authorises platform(s) with no corroborating DKIM or MX signal: "
                    + ", ".join(spf_only)
                ),
                description=(
                    f"The SPF record for {domain} authorises "
                    f"{', '.join(spf_only)}, but no DKIM selectors or MX records for "
                    f"{'this platform were' if len(spf_only) == 1 else 'these platforms were'} "
                    "detected. This may indicate an orphaned SPF entry from a past platform migration."
                ),
                recommended_action=(
                    f"Verify whether mail is still actively sent through {', '.join(spf_only)}. "
                    "If not, remove the corresponding include: from the SPF record."
                ),
                evidence={
                    "spf_only_providers": spf_only,
                    "spf_providers":      spf.providers,
                    "dkim_providers":     dkim.providers,
                    "mx_providers":       mx.providers,
                    "impact": (
                        "An orphaned SPF authorisation allows decommissioned platform IP "
                        "ranges to pass SPF for this domain indefinitely."
                    ),
                },
            ))

    # Provider mismatch: SPF vs DKIM
    if spf.providers and dkim.providers:
        spf_set  = set(spf.providers)
        dkim_set = set(dkim.providers)
        only_spf  = spf_set  - dkim_set
        only_dkim = dkim_set - spf_set
        if only_spf and only_dkim:
            findings.append(Finding(
                id=f"auth-cross-provider-mismatch-{domain}",
                category="authentication",
                severity="low",
                title="Sending infrastructure mismatch between SPF and DKIM",
                description=(
                    f"SPF authorises {', '.join(sorted(only_spf))} but DKIM keys are "
                    f"published for {', '.join(sorted(only_dkim))}."
                ),
                recommended_action=(
                    "Audit all sending platforms. Ensure each is present in both SPF and DKIM."
                ),
                evidence={
                    "spf_providers":  list(spf_set),
                    "dkim_providers": list(dkim_set),
                    "only_in_spf":    list(only_spf),
                    "only_in_dkim":   list(only_dkim),
                    "impact": (
                        "SPF-only providers lose DMARC alignment on forwarded mail. "
                        "DKIM-only providers may not be SPF-authorised."
                    ),
                },
            ))

    # Cross-protocol score
    if has_spf and has_dkim and dmarc_enforced:
        cross_score = CROSS_SCORE["all_three_enforcing"]
    elif has_spf and dmarc_enforced and not has_dkim:
        cross_score = CROSS_SCORE["spf_dmarc_only"]
    elif has_dkim and dmarc_enforced and not has_spf:
        cross_score = CROSS_SCORE["dmarc_dkim_only"]
    elif (has_spf or has_dkim) and not has_dmarc:
        cross_score = CROSS_SCORE["spf_dkim_no_dmarc"]
    elif has_dmarc and not has_spf and not has_dkim:
        cross_score = CROSS_SCORE["dmarc_no_spf_dkim"]
    else:
        cross_score = CROSS_SCORE["nothing_enforcing"]

    return findings, cross_score


# ---------------------------------------------------------------------------
# Main analyzer class
# ---------------------------------------------------------------------------

class AuthHealthAnalyzer:
    """
    MailGuard V2 Authentication Health analyzer (v2.1).

    Interface contract (matches all V2 scan modules):
      __init__(domain: str)
      async run(request: ScanRequest) -> ScanResult

    Scoring: SPF(30) + DMARC(35) + DKIM(25) + Cross-protocol(10) = 100 max
    ScanResult.score    = exposure  (higher = worse posture, V2 convention)
    evidence.health_score = 100 - exposure  (higher = healthier)
    """

    def __init__(self, domain: str):
        self.domain = domain

    async def run(self, request: ScanRequest) -> ScanResult:
        domain     = request.domain.strip().lower()
        scan_id    = str(uuid.uuid4())
        scan_start = time.monotonic()

        # Phase 1: Concurrent DNS collection (TXT + DMARC + MX simultaneously)
        txt_records, dmarc_records, mx_hosts = await asyncio.gather(
            _resolve_txt(domain),
            _resolve_txt(f"_dmarc.{domain}"),
            _resolve_mx_hosts(domain),
        )

        # Phase 2: SPF analysis
        spf = _analyze_spf(domain, txt_records)

        # Phase 3b: MX provider detection (used for provider-aware DKIM ordering)
        mx = _MxAnalysis(
            hosts=mx_hosts,
            providers=_classify_mx_providers(mx_hosts),
        )

        # Phase 4: Provider-aware DKIM discovery
        dkim = await _analyze_dkim(domain, spf.providers, mx.providers)

        # Phase 3: DMARC analysis
        dmarc = _analyze_dmarc(domain, dmarc_records)

        # Phase 5: Cross-protocol analysis
        cross_findings, cross_score = await _cross_analysis(
            domain, spf, dmarc, dkim, mx
        )

        # Phase 6: Score calculation
        health_score = min(100, spf.score + dmarc.score + dkim.score + cross_score)
        exposure     = max(0, 100 - health_score)

        grade = (
            "A" if health_score >= 90 else
            "B" if health_score >= 75 else
            "C" if health_score >= 60 else
            "D" if health_score >= 45 else "F"
        )

        # Union of all detected providers
        all_providers: List[str] = []
        for p in spf.providers + dkim.providers + mx.providers:
            if p not in all_providers:
                all_providers.append(p)

        # Aggregate findings (cross-protocol first — most actionable)
        all_findings = cross_findings + spf.findings + dmarc.findings + dkim.findings

        critical_count = sum(1 for f in all_findings if f.severity == "critical")
        high_count     = sum(1 for f in all_findings if f.severity == "high")
        summary_sev    = "critical" if critical_count else "medium" if high_count else "info"

        summary = Finding(
            id=f"auth-summary-{domain}",
            category="authentication",
            severity=summary_sev,
            title=f"Authentication Health: {domain} — Score {health_score}/100 (Grade {grade})",
            description=(
                f"Authentication posture for {domain}: "
                f"SPF {'✓' if spf.present else '✗'} ({spf.policy or 'absent'}) | "
                f"DMARC {'✓' if dmarc.present else '✗'} "
                f"({'p=' + dmarc.policy if dmarc.present else 'absent'}) | "
                f"DKIM {'✓ (' + str(len(dkim.selectors)) + ' selector' + ('s' if len(dkim.selectors) != 1 else '') + ' found)' if dkim.selectors else '✗ (not detected)'}. "
                + (
                    f"{critical_count} critical issue(s) require immediate attention."
                    if critical_count else
                    "No critical authentication issues detected."
                )
            ),
            recommended_action=(
                "Address findings in severity order. Highest-value improvements: "
                "(1) deploy DMARC p=reject, (2) enable DKIM signing, (3) harden SPF to -all."
            ),
            evidence={
                "domain":             domain,
                "health_score":       health_score,
                "grade":              grade,
                "spf_present":        spf.present,
                "dmarc_present":      dmarc.present,
                "dkim_selectors":     len(dkim.selectors),
                "detected_providers": all_providers,
            },
        )
        all_findings.insert(0, summary)

        scan_duration_ms = round((time.monotonic() - scan_start) * 1000)

        return ScanResult(
            scan_id=scan_id,
            tenant_id=domain,
            family="authentication",
            findings=all_findings,
            score=exposure,
            status="complete",
            timestamp=datetime.now(timezone.utc).isoformat(),
            evidence={
                "domain":       domain,
                "health_score": health_score,
                "grade":        grade,
                "spf": {
                    "present":       spf.present,
                    "record":        spf.record,
                    "policy":        spf.policy,
                    "multiple":      spf.multiple,
                    "lookup_count":  spf.lookup_count,
                    "includes":      spf.includes,
                    "providers":     spf.providers,
                    "score":         spf.score,
                },
                "dmarc": {
                    "present":           dmarc.present,
                    "record":            dmarc.record,
                    "policy":            dmarc.policy,
                    "subdomain_policy":  dmarc.subdomain_policy,
                    "pct":               dmarc.pct,
                    "rua":               dmarc.rua,
                    "ruf":               dmarc.ruf,
                    "aspf":              dmarc.aspf,
                    "adkim":             dmarc.adkim,
                    "multiple":          dmarc.multiple,
                    "score":             dmarc.score,
                },
                "dkim": {
                    "selectors_found":    dkim.selectors,
                    "selectors_checked":  len(dkim.selectors_checked),
                    "providers":          dkim.providers,
                    "score":              dkim.score,
                },
                "mx": {
                    "hosts":     mx.hosts,
                    "providers": mx.providers,
                },
                "detected_providers": all_providers,
                "score_breakdown": {
                    "spf":          spf.score,
                    "dmarc":        dmarc.score,
                    "dkim":         dkim.score,
                    "cross":        cross_score,
                    "health_total": health_score,
                    "exposure":     exposure,
                },
                "scan_metadata": {
                    "scan_type":         "authentication_health",
                    "module_version":    MODULE_VERSION,
                    "scan_duration_ms":  scan_duration_ms,
                    "selectors_checked": len(dkim.selectors_checked),
                },
            },
        )
