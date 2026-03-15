"""
auth_analyzer.py — MailGuard V2 / Authentication Health

Evaluates email authentication posture for a domain:
  SPF   — record presence, policy strength, DNS lookup limits, sending providers
  DMARC — policy enforcement, subdomain policy, pct, reporting addresses, alignment
  DKIM  — common selector discovery, key strength, platform identification

Scoring convention (matches V2 standard):
  score         — exposure/risk score, 0–100, HIGHER = more exposed / worse posture
  health_score  — returned inside evidence, 0–100, HIGHER = healthier configuration

Findings emitted (id scheme: auth-{protocol}-{check}-{domain}):
  auth-spf-missing-{domain}          CRITICAL  No SPF record
  auth-spf-multiple-{domain}         CRITICAL  More than one SPF record
  auth-spf-pass-all-{domain}         CRITICAL  +all qualifier
  auth-spf-softfail-{domain}         MEDIUM    ~all qualifier
  auth-spf-neutral-{domain}          MEDIUM    ?all qualifier
  auth-spf-no-terminator-{domain}    MEDIUM    No 'all' mechanism
  auth-spf-ptr-{domain}              LOW       ptr mechanism in use
  auth-spf-lookup-exceeded-{domain}  CRITICAL  >10 DNS lookups
  auth-spf-lookup-warning-{domain}   MEDIUM    9–10 DNS lookups
  auth-dmarc-missing-{domain}        CRITICAL  No DMARC record
  auth-dmarc-multiple-{domain}       CRITICAL  More than one DMARC record
  auth-dmarc-none-{domain}           MEDIUM    p=none (monitoring only)
  auth-dmarc-quarantine-{domain}     LOW       p=quarantine (not full reject)
  auth-dmarc-pct-partial-{domain}    MEDIUM    pct < 100
  auth-dmarc-no-reporting-{domain}   LOW       No rua= configured
  auth-dmarc-weak-subdomain-{domain} MEDIUM    sp= weaker than p=
  auth-dkim-missing-{domain}         MEDIUM    No selectors found
  auth-dkim-weak-key-{selector}      CRITICAL  Key < 1024 bits
  auth-dkim-short-key-{selector}     LOW       Key 1024–2047 bits
  auth-cross-gap-{domain}            CRITICAL  DMARC present but no SPF or DKIM
  auth-cross-no-dmarc-spf-{domain}   MEDIUM    SPF only, no DMARC
  auth-cross-no-dmarc-dkim-{domain}  MEDIUM    DKIM only, no DMARC
  auth-cross-weak-triangle-{domain}  MEDIUM    Weak DMARC + weak SPF + no DKIM
  auth-cross-provider-mismatch-{d}   LOW       SPF and DKIM authorise different providers
  auth-summary-{domain}              INFO      Lead finding with overview
"""

import asyncio
import base64
import re
import time
import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import dns.asyncresolver
import dns.resolver

from app.models.v2.scan_request import ScanRequest
from app.models.v2.scan_result import ScanResult
from app.models.v2.finding import Finding

logger = logging.getLogger(__name__)

MODULE_VERSION = "v2.0"

# ── DKIM selector candidates ──────────────────────────────────────────────────
DKIM_SELECTORS = [
    "selector1", "selector2", "default", "google", "k1", "k2",
    "smtp", "mail", "dkim", "s1", "s2", "email", "key1", "key2",
    "mxvault", "mx", "proofpoint", "mimecast", "sm",
    "pm", "postmarkapp", "mandrill", "mailgun", "sendgrid",
]

# ── SPF include → sending platform ───────────────────────────────────────────
SPF_PROVIDER_MAP: Dict[str, str] = {
    "spf.protection.outlook.com":  "Microsoft 365",
    "_spf.google.com":             "Google Workspace",
    "sendgrid.net":                "SendGrid",
    "amazonses.com":               "Amazon SES",
    "mailgun.org":                 "Mailgun",
    "spf.mandrillapp.com":         "Mandrill (Mailchimp)",
    "spf.mailchimp.com":           "Mailchimp",
    "servers.mcsv.net":            "Mailchimp",
    "pm.mtasv.net":                "Postmark",
    "_spf.salesforce.com":         "Salesforce",
    "spf.exacttarget.com":         "Salesforce Marketing Cloud",
    "spf.hubspot.com":             "HubSpot",
    "spf.marketo.com":             "Marketo",
    "spf.zohomail.com":            "Zoho Mail",
    "pphosted.com":                "Proofpoint",
    "ppe-hosted.com":              "Proofpoint Essentials",
    "mimecast.com":                "Mimecast",
    "barracudanetworks.com":       "Barracuda",
    "iphmx.com":                   "Cisco IronPort",
    "mailcontrol.com":             "Forcepoint",
    "messagelabs.com":             "Broadcom (MessageLabs)",
    "sparkpostmail.com":           "SparkPost",
    "mktomail.com":                "Marketo",
    "freshdesk.com":               "Freshdesk",
}

# ── DKIM selector → sending platform ─────────────────────────────────────────
DKIM_SELECTOR_PLATFORM_MAP: Dict[str, str] = {
    "selector1":   "Microsoft 365",
    "selector2":   "Microsoft 365",
    "google":      "Google Workspace",
    "sendgrid":    "SendGrid",
    "s1":          "SendGrid",
    "s2":          "SendGrid",
    "sm":          "Mandrill",
    "pm":          "Postmark",
    "postmarkapp": "Postmark",
    "mandrill":    "Mandrill",
    "mailgun":     "Mailgun",
    "k1":          "Mailchimp",
    "k2":          "Mailchimp",
    "mxvault":     "Mimecast",
    "proofpoint":  "Proofpoint",
}

# ── Exposure score contributions (higher = more exposed) ─────────────────────
EXPOSURE = {
    "spf_missing":          25,
    "spf_multiple":         20,
    "spf_plus_all":         25,
    "spf_softfail":         10,
    "spf_neutral":          10,
    "spf_no_terminator":    10,
    "spf_ptr":               5,
    "spf_lookup_exceeded":  10,
    "spf_lookup_warning":    5,
    "dmarc_missing":        30,
    "dmarc_multiple":       25,
    "dmarc_none":           15,
    "dmarc_quarantine":      5,
    "dmarc_pct_partial":     5,
    "dkim_missing":         15,
    "dkim_weak_key":        15,
    "dkim_short_key":        5,
    "cross_auth_gap":       15,
}


# ── DNS helpers ───────────────────────────────────────────────────────────────

async def _resolve_txt(name: str) -> List[str]:
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


async def _resolve_dkim(selector: str, domain: str) -> dict:
    """Attempt to retrieve one DKIM public key record. Returns a result dict."""
    fqdn = f"{selector}._domainkey.{domain}"
    records = await _resolve_txt(fqdn)
    if not records:
        return {"selector": selector, "fqdn": fqdn, "valid": False}

    record = records[0]
    result: dict = {"selector": selector, "fqdn": fqdn, "valid": True, "record": record}

    # Key type
    kt = re.search(r'\bk=(\w+)', record)
    result["key_type"] = kt.group(1).lower() if kt else "rsa"

    # Key size estimate
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

    # Platform from selector name or record content
    result["platform"] = DKIM_SELECTOR_PLATFORM_MAP.get(selector)
    if not result["platform"]:
        rl = record.lower()
        for kw, platform in [("google", "Google Workspace"), ("outlook", "Microsoft 365"),
                               ("sendgrid", "SendGrid"), ("mailgun", "Mailgun")]:
            if kw in rl:
                result["platform"] = platform
                break

    return result


# ── Internal analysis dataclasses ─────────────────────────────────────────────

@dataclass
class _SpfAnalysis:
    present: bool = False
    record: Optional[str] = None
    policy: Optional[str] = None
    multiple: bool = False
    includes: List[str] = field(default_factory=list)
    lookup_count: int = 0
    providers: List[str] = field(default_factory=list)
    exposure: int = 0
    findings: List[Finding] = field(default_factory=list)


@dataclass
class _DmarcAnalysis:
    present: bool = False
    record: Optional[str] = None
    policy: Optional[str] = None
    subdomain_policy: Optional[str] = None
    pct: int = 100
    rua: List[str] = field(default_factory=list)
    ruf: List[str] = field(default_factory=list)
    aspf: str = "r"
    adkim: str = "r"
    multiple: bool = False
    exposure: int = 0
    findings: List[Finding] = field(default_factory=list)


@dataclass
class _DkimAnalysis:
    selectors: List[dict] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    exposure: int = 0
    findings: List[Finding] = field(default_factory=list)


# ── SPF analysis ──────────────────────────────────────────────────────────────

def _analyze_spf(domain: str, txt_records: List[str]) -> _SpfAnalysis:
    a = _SpfAnalysis()
    spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]

    if not spf_records:
        a.exposure += EXPOSURE["spf_missing"]
        a.findings.append(Finding(
            id=f"auth-spf-missing-{domain}",
            category="authentication",
            severity="critical",
            title="No SPF record found",
            description=(
                f"{domain} has no SPF record. Any server on the internet can send email "
                "that appears to originate from this domain. SPF is the baseline mechanism "
                "that allows receiving servers to verify authorised sending infrastructure."
            ),
            recommended_action=(
                "Publish a TXT record at the domain root specifying authorised senders. "
                "At minimum: v=spf1 include:<your-provider> -all"
            ),
            evidence={"domain": domain, "txt_records_checked": txt_records},
        ))
        return a

    if len(spf_records) > 1:
        a.present = True
        a.record = spf_records[0]
        a.multiple = True
        a.exposure += EXPOSURE["spf_multiple"]
        a.findings.append(Finding(
            id=f"auth-spf-multiple-{domain}",
            category="authentication",
            severity="critical",
            title=f"Multiple SPF records found ({len(spf_records)})",
            description=(
                f"{domain} has {len(spf_records)} SPF TXT records. RFC 7208 requires exactly one. "
                "When multiple records are present, receiving servers will return a PermError and "
                "SPF evaluation fails — effectively providing no protection."
            ),
            recommended_action=(
                "Merge all SPF records into a single TXT record. "
                "Delete all but one and combine the mechanisms."
            ),
            evidence={"records": spf_records},
        ))
        return a

    a.present = True
    record = spf_records[0]
    a.record = record

    # Policy
    all_m = re.search(r'([+~\-?]?)all\b', record, re.IGNORECASE)
    if all_m:
        q = all_m.group(1) or "+"
        a.policy = {"+": "+all", "~": "~all", "-": "-all", "?": "?all"}.get(q, "+all")
    else:
        a.policy = "missing"

    if a.policy == "+all":
        a.exposure += EXPOSURE["spf_plus_all"]
        a.findings.append(Finding(
            id=f"auth-spf-pass-all-{domain}",
            category="authentication",
            severity="critical",
            title='SPF record uses "+all" — unrestricted spoofing allowed',
            description=(
                f'The SPF record for {domain} ends with "+all", which passes SPF for any server '
                "on the internet. This is equivalent to having no SPF protection at all and "
                "actively signals to phishing actors that spoofing this domain will pass SPF checks."
            ),
            recommended_action='Replace "+all" with "-all" to explicitly reject unauthorised senders.',
            evidence={"record": record},
        ))
    elif a.policy == "~all":
        a.exposure += EXPOSURE["spf_softfail"]
        a.findings.append(Finding(
            id=f"auth-spf-softfail-{domain}",
            category="authentication",
            severity="medium",
            title='SPF record uses "~all" (SoftFail) — unauthorised senders are tagged, not rejected',
            description=(
                f'The SPF record for {domain} ends with "~all". Unauthorised senders are tagged '
                "as SoftFail but not rejected — many mail servers accept SoftFail messages and "
                "deliver them to inboxes. Without a DMARC reject policy, this provides minimal "
                "protection against spoofing attacks."
            ),
            recommended_action='Upgrade to "-all" (HardFail) once all legitimate senders are in the SPF record.',
            evidence={"record": record},
        ))
    elif a.policy == "?all":
        a.exposure += EXPOSURE["spf_neutral"]
        a.findings.append(Finding(
            id=f"auth-spf-neutral-{domain}",
            category="authentication",
            severity="medium",
            title='SPF record uses "?all" (Neutral) — provides no spoofing protection',
            description=(
                f'The SPF record for {domain} ends with "?all". A Neutral result provides no '
                "guidance to receiving servers — it is treated the same as having no SPF policy. "
                "Any server can send as this domain without triggering an SPF failure."
            ),
            recommended_action='Replace "?all" with "-all" to enforce SPF.',
            evidence={"record": record},
        ))
    elif a.policy == "missing":
        a.exposure += EXPOSURE["spf_no_terminator"]
        a.findings.append(Finding(
            id=f"auth-spf-no-terminator-{domain}",
            category="authentication",
            severity="medium",
            title='SPF record has no "all" terminator — behaviour is undefined',
            description=(
                f"The SPF record for {domain} does not include an 'all' mechanism. Without it, "
                "receiving servers cannot determine what to do with mail from unlisted servers. "
                "Behaviour is implementation-dependent and provides unpredictable protection."
            ),
            recommended_action='Add "-all" to the end of the SPF record.',
            evidence={"record": record},
        ))

    # ptr usage
    if re.search(r'\bptr\b', record, re.IGNORECASE):
        a.exposure += EXPOSURE["spf_ptr"]
        a.findings.append(Finding(
            id=f"auth-spf-ptr-{domain}",
            category="authentication",
            severity="low",
            title='SPF record uses deprecated "ptr" mechanism',
            description=(
                "The 'ptr' mechanism is deprecated per RFC 7208 §5.5 and causes extra DNS lookups "
                "that count against the 10-lookup limit. It is slow, unreliable, and should be removed."
            ),
            recommended_action="Remove the 'ptr' mechanism and replace with 'ip4:', 'ip6:', or 'include:' as appropriate.",
            evidence={"record": record},
        ))

    # DNS lookup count
    lookup_mechs = re.findall(
        r'\b(?:include|a|mx|ptr|exists|redirect)(?::|/|\s|$)', record, re.IGNORECASE
    )
    a.lookup_count = len(lookup_mechs)
    if a.lookup_count > 10:
        a.exposure += EXPOSURE["spf_lookup_exceeded"]
        a.findings.append(Finding(
            id=f"auth-spf-lookup-exceeded-{domain}",
            category="authentication",
            severity="critical",
            title=f"SPF record exceeds 10 DNS lookup limit ({a.lookup_count} lookups)",
            description=(
                f"RFC 7208 limits SPF evaluation to 10 DNS-intensive lookups. "
                f"This record requires {a.lookup_count}. Receiving servers must return a PermError "
                "and treat the SPF result as None — providing no authentication protection."
            ),
            recommended_action=(
                "Flatten SPF includes using a tool like dmarcian's SPF Surveyor. "
                "Replace include: chains with direct ip4:/ip6: mechanisms where possible."
            ),
            evidence={"record": record, "lookup_count": a.lookup_count},
        ))
    elif a.lookup_count >= 9:
        a.exposure += EXPOSURE["spf_lookup_warning"]
        a.findings.append(Finding(
            id=f"auth-spf-lookup-warning-{domain}",
            category="authentication",
            severity="medium",
            title=f"SPF record approaching 10 DNS lookup limit ({a.lookup_count}/10)",
            description=(
                f"This SPF record currently requires {a.lookup_count} DNS lookups. "
                "Adding any further senders may push it over the RFC 7208 limit of 10, "
                "causing PermError and SPF evaluation failure."
            ),
            recommended_action="Audit and flatten SPF includes before adding new senders.",
            evidence={"record": record, "lookup_count": a.lookup_count},
        ))

    # Providers
    rl = record.lower()
    a.includes = re.findall(r'include:(\S+)', record, re.IGNORECASE)
    for pattern, provider in SPF_PROVIDER_MAP.items():
        if pattern in rl and provider not in a.providers:
            a.providers.append(provider)

    return a


# ── DMARC analysis ────────────────────────────────────────────────────────────

def _analyze_dmarc(domain: str, dmarc_records: List[str]) -> _DmarcAnalysis:
    a = _DmarcAnalysis()
    valid = [r for r in dmarc_records if r.lower().startswith("v=dmarc1")]

    if not valid:
        a.exposure += EXPOSURE["dmarc_missing"]
        a.findings.append(Finding(
            id=f"auth-dmarc-missing-{domain}",
            category="authentication",
            severity="critical",
            title="No DMARC record found",
            description=(
                f"{domain} has no DMARC record. Even if SPF and DKIM pass, there is no policy "
                "instructing receiving servers what to do with mail that fails authentication. "
                "Without DMARC, the visible From: header used in phishing is unprotected — "
                "SPF and DKIM alone do not guard against header spoofing."
            ),
            recommended_action=(
                "Publish a DMARC record at _dmarc." + domain + ". "
                "Start with p=none to collect reporting data, then advance to p=quarantine and p=reject."
            ),
            evidence={"domain": domain},
        ))
        return a

    if len(valid) > 1:
        a.present = True
        a.record = valid[0]
        a.multiple = True
        a.exposure += EXPOSURE["dmarc_multiple"]
        a.findings.append(Finding(
            id=f"auth-dmarc-multiple-{domain}",
            category="authentication",
            severity="critical",
            title=f"Multiple DMARC records found ({len(valid)})",
            description=(
                f"{domain} has {len(valid)} DMARC TXT records at _dmarc.{domain}. "
                "RFC 7489 requires exactly one. When multiple records are present, DMARC "
                "evaluation is undefined and receivers may ignore the policy entirely."
            ),
            recommended_action="Remove all but one DMARC record.",
            evidence={"records": valid},
        ))
        return a

    a.present = True
    record = valid[0]
    a.record = record

    # Policy
    pm = re.search(r'\bp=(\w+)', record, re.IGNORECASE)
    a.policy = pm.group(1).lower() if pm else "none"

    if a.policy == "none":
        a.exposure += EXPOSURE["dmarc_none"]
        a.findings.append(Finding(
            id=f"auth-dmarc-none-{domain}",
            category="authentication",
            severity="medium",
            title="DMARC policy is p=none (monitoring mode) — no enforcement",
            description=(
                f"The DMARC policy for {domain} is set to p=none. Mail that fails DMARC is "
                "delivered as normal — the policy has no effect on mail flow. "
                "Attackers can spoof this domain and recipients will receive the messages. "
                "p=none is appropriate only as a temporary phase while collecting reporting data."
            ),
            recommended_action=(
                "Review aggregate DMARC reports (rua=) to identify all legitimate sending sources, "
                "then advance to p=quarantine and ultimately p=reject."
            ),
            evidence={"record": record},
        ))
    elif a.policy == "quarantine":
        a.exposure += EXPOSURE["dmarc_quarantine"]
        a.findings.append(Finding(
            id=f"auth-dmarc-quarantine-{domain}",
            category="authentication",
            severity="low",
            title="DMARC policy is p=quarantine — consider upgrading to p=reject",
            description=(
                f"The DMARC policy for {domain} sends failing mail to spam/junk folders. "
                "This is a meaningful control, but spoofed mail still reaches recipients' mailboxes "
                "(in the spam folder). p=reject is the strongest enforcement level and ensures "
                "unauthenticated mail is dropped entirely."
            ),
            recommended_action=(
                "After confirming all legitimate senders pass DMARC, upgrade to p=reject "
                "for full protection against domain spoofing."
            ),
            evidence={"record": record},
        ))

    # Subdomain policy
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
                f"The main DMARC policy for {domain} is p={a.policy}, but subdomains are only "
                f"protected by sp={a.subdomain_policy}. Attackers can spoof subdomains of {domain} "
                "more easily than the apex domain, often to bypass email security filters that "
                "focus on exact domain matches."
            ),
            recommended_action=f"Set sp={a.policy} to apply the same enforcement to all subdomains.",
            evidence={"record": record, "p": a.policy, "sp": a.subdomain_policy},
        ))

    # pct
    pct_m = re.search(r'\bpct=(\d+)', record, re.IGNORECASE)
    a.pct = int(pct_m.group(1)) if pct_m else 100
    if a.pct < 100 and a.policy != "none":
        a.exposure += EXPOSURE["dmarc_pct_partial"]
        a.findings.append(Finding(
            id=f"auth-dmarc-pct-partial-{domain}",
            category="authentication",
            severity="medium",
            title=f"DMARC pct={a.pct} — policy applies to only {a.pct}% of failing mail",
            description=(
                f"The pct tag limits DMARC enforcement to {a.pct}% of mail that fails authentication. "
                f"The remaining {100 - a.pct}% is treated as if the policy were one level lower "
                "(quarantine → none, reject → quarantine). Attackers can still successfully "
                "deliver spoofed mail in the unenforced percentage."
            ),
            recommended_action="Set pct=100 once all legitimate senders are confirmed to pass DMARC.",
            evidence={"record": record, "pct": a.pct},
        ))

    # Reporting
    rua_m = re.search(r'\brua=([^\s;]+)', record, re.IGNORECASE)
    ruf_m = re.search(r'\bruf=([^\s;]+)', record, re.IGNORECASE)
    a.rua = [x.strip() for x in rua_m.group(1).split(",")] if rua_m else []
    a.ruf = [x.strip() for x in ruf_m.group(1).split(",")] if ruf_m else []

    if not a.rua:
        a.findings.append(Finding(
            id=f"auth-dmarc-no-reporting-{domain}",
            category="authentication",
            severity="low",
            title="No DMARC aggregate reporting address configured (rua= missing)",
            description=(
                f"The DMARC record for {domain} has no rua= tag. Without aggregate reports, "
                "you have no visibility into which sources are sending mail as your domain — "
                "including illegitimate senders. Aggregate reports are essential for advancing "
                "toward full p=reject enforcement safely."
            ),
            recommended_action=(
                "Add rua=mailto:dmarc-reports@" + domain + " or use a third-party DMARC reporting service."
            ),
            evidence={"record": record},
        ))

    # Alignment
    aspf_m  = re.search(r'\baspf=([rs])',  record, re.IGNORECASE)
    adkim_m = re.search(r'\badkim=([rs])', record, re.IGNORECASE)
    a.aspf  = aspf_m.group(1).lower()  if aspf_m  else "r"
    a.adkim = adkim_m.group(1).lower() if adkim_m else "r"

    return a


# ── DKIM analysis ─────────────────────────────────────────────────────────────

async def _analyze_dkim(domain: str) -> _DkimAnalysis:
    a = _DkimAnalysis()
    tasks = [_resolve_dkim(sel, domain) for sel in DKIM_SELECTORS]
    resolved = await asyncio.gather(*tasks)
    a.selectors = [s for s in resolved if s.get("valid")]

    if not a.selectors:
        a.exposure += EXPOSURE["dkim_missing"]
        a.findings.append(Finding(
            id=f"auth-dkim-missing-{domain}",
            category="authentication",
            severity="medium",
            title="No DKIM selectors found",
            description=(
                f"No DKIM public key records were found for {domain} after checking "
                f"{len(DKIM_SELECTORS)} common selector names. Without DKIM, outbound mail "
                "cannot be cryptographically signed — DMARC alignment via DKIM is impossible, "
                "and mail is more susceptible to in-transit modification and replay attacks."
            ),
            recommended_action=(
                "Enable DKIM signing in your mail platform and publish the public key as a TXT record. "
                "If a non-standard selector is in use, verify it manually."
            ),
            evidence={"selectors_checked": DKIM_SELECTORS},
        ))
        return a

    # Key strength findings
    for s in a.selectors:
        bits = s.get("key_bits")
        if bits is not None and bits < 1024:
            a.exposure += EXPOSURE["dkim_weak_key"]
            a.findings.append(Finding(
                id=f"auth-dkim-weak-key-{s['selector']}",
                category="authentication",
                severity="critical",
                title=f"DKIM selector '{s['selector']}' uses a weak key (~{bits} bits)",
                description=(
                    f"The DKIM key for selector '{s['selector']}' on {domain} is approximately "
                    f"{bits} bits, which is below the 1024-bit minimum required by RFC 6376. "
                    "Keys under 1024 bits can be factored, allowing attackers to forge DKIM signatures."
                ),
                recommended_action="Rotate to a 2048-bit RSA key immediately.",
                evidence={"selector": s["selector"], "fqdn": s["fqdn"], "key_bits": bits},
            ))
        elif bits is not None and bits < 2048:
            a.exposure += EXPOSURE["dkim_short_key"]
            a.findings.append(Finding(
                id=f"auth-dkim-short-key-{s['selector']}",
                category="authentication",
                severity="low",
                title=f"DKIM selector '{s['selector']}' uses a 1024-bit key — 2048 bits recommended",
                description=(
                    f"The DKIM key for selector '{s['selector']}' on {domain} is approximately "
                    f"{bits} bits. While 1024 bits is the current minimum, NIST recommends "
                    "migrating to 2048-bit keys as 1024-bit RSA is approaching practical vulnerability."
                ),
                recommended_action="Plan rotation to a 2048-bit RSA key at next key rotation cycle.",
                evidence={"selector": s["selector"], "fqdn": s["fqdn"], "key_bits": bits},
            ))

    # Providers from selectors
    for s in a.selectors:
        p = s.get("platform")
        if p and p not in a.providers:
            a.providers.append(p)

    return a


# ── Cross-protocol analysis ───────────────────────────────────────────────────

def _cross_analysis(
    domain: str,
    spf: _SpfAnalysis,
    dmarc: _DmarcAnalysis,
    dkim: _DkimAnalysis,
) -> Tuple[List[Finding], int]:
    findings: List[Finding] = []
    extra_exposure = 0

    # Authentication gap: DMARC present, but nothing to align against
    if dmarc.present and not spf.present and not dkim.selectors:
        extra_exposure += EXPOSURE["cross_auth_gap"]
        findings.append(Finding(
            id=f"auth-cross-gap-{domain}",
            category="authentication",
            severity="critical",
            title="Authentication gap: DMARC exists but neither SPF nor DKIM is configured",
            description=(
                f"{domain} has a DMARC record but no SPF record and no DKIM selectors. "
                "DMARC requires at least one of SPF or DKIM to pass and align — with neither "
                "configured, all mail from this domain will fail DMARC regardless of source. "
                "Legitimate mail may be rejected; the DMARC policy provides no practical protection."
            ),
            recommended_action=(
                "Configure SPF and enable DKIM signing before relying on DMARC enforcement."
            ),
            evidence={"domain": domain},
        ))

    # SPF only — no DMARC
    if spf.present and not dmarc.present:
        findings.append(Finding(
            id=f"auth-cross-no-dmarc-spf-{domain}",
            category="authentication",
            severity="medium",
            title="SPF configured but no DMARC — From: header spoofing is unprotected",
            description=(
                f"{domain} has an SPF record but no DMARC policy. SPF protects the envelope "
                "sender (Return-Path), not the visible From: header that users see in their "
                "mail client. Phishing attacks using display-name or header spoofing will "
                "pass SPF and reach recipients without a DMARC policy to block them."
            ),
            recommended_action=(
                "Publish a DMARC record at _dmarc." + domain + " starting with p=none "
                "to collect data, then advance to enforcement."
            ),
            evidence={"domain": domain},
        ))

    # DKIM only — no DMARC
    if dkim.selectors and not dmarc.present:
        findings.append(Finding(
            id=f"auth-cross-no-dmarc-dkim-{domain}",
            category="authentication",
            severity="medium",
            title="DKIM configured but no DMARC — domain spoofing is unprotected",
            description=(
                f"{domain} has DKIM selectors but no DMARC policy. DKIM proves message integrity "
                "but does not require alignment between the signing domain and the visible From: "
                "header. Without DMARC, spoofed mail can pass DKIM if signed by any domain "
                "and will not be acted upon by receiving servers."
            ),
            recommended_action=(
                "Publish a DMARC record at _dmarc." + domain + " to enforce DKIM alignment."
            ),
            evidence={"domain": domain},
        ))

    # Weak enforcement triangle
    weak_spf = spf.present and spf.policy in ("~all", "?all", "+all", "missing")
    no_enforcement = not dmarc.present or dmarc.policy == "none"
    if weak_spf and no_enforcement and not dkim.selectors:
        findings.append(Finding(
            id=f"auth-cross-weak-triangle-{domain}",
            category="authentication",
            severity="medium",
            title="Weak authentication posture: soft SPF, no DKIM, no DMARC enforcement",
            description=(
                f"{domain} has a non-enforcing SPF policy, no DKIM deployment, and no DMARC "
                "enforcement. This combination provides a minimal barrier against spoofing — "
                "a motivated attacker can impersonate this domain and deliver mail to recipients "
                "with no authentication mechanism blocking delivery."
            ),
            recommended_action=(
                "Upgrade SPF to -all, enable DKIM signing, and deploy DMARC with at least p=quarantine."
            ),
            evidence={"domain": domain, "spf_policy": spf.policy},
        ))

    # Provider mismatch between SPF and DKIM
    spf_set  = set(spf.providers)
    dkim_set = set(dkim.providers)
    if spf_set and dkim_set:
        only_spf  = spf_set  - dkim_set
        only_dkim = dkim_set - spf_set
        if only_spf and only_dkim:
            findings.append(Finding(
                id=f"auth-cross-provider-mismatch-{domain}",
                category="authentication",
                severity="low",
                title="Sending infrastructure mismatch between SPF and DKIM",
                description=(
                    f"SPF authorises {', '.join(sorted(only_spf))} but DKIM keys are published "
                    f"for {', '.join(sorted(only_dkim))}. This may indicate a platform migration "
                    "in progress, an orphaned configuration, or an unrecognised sending service. "
                    "Mail from a provider in only one list may fail DMARC alignment."
                ),
                recommended_action=(
                    "Audit all authorised sending sources. Ensure every mail platform is listed "
                    "in both SPF and has DKIM selectors published."
                ),
                evidence={
                    "spf_providers":  list(spf_set),
                    "dkim_providers": list(dkim_set),
                    "only_in_spf":    list(only_spf),
                    "only_in_dkim":   list(only_dkim),
                },
            ))

    return findings, extra_exposure


# ── Main analyzer class ───────────────────────────────────────────────────────

class AuthHealthAnalyzer:
    """
    V2 authentication health analyzer.
    Interface matches all other V2 scan modules:
      __init__(domain: str)
      async run(request: ScanRequest) -> ScanResult
    """

    def __init__(self, domain: str):
        self.domain = domain

    async def run(self, request: ScanRequest) -> ScanResult:
        domain     = request.domain.strip().lower()
        scan_id    = str(uuid.uuid4())
        scan_start = time.monotonic()

        # ── Phase 1: DNS collection (concurrent) ─────────────────────────────
        txt_records, dmarc_records, dkim = await asyncio.gather(
            _resolve_txt(domain),
            _resolve_txt(f"_dmarc.{domain}"),
            _analyze_dkim(domain),
        )

        # ── Phase 2–4: Per-protocol analysis ─────────────────────────────────
        spf   = _analyze_spf(domain, txt_records)
        dmarc = _analyze_dmarc(domain, dmarc_records)

        # ── Phase 5: Cross-protocol ───────────────────────────────────────────
        cross_findings, cross_exposure = _cross_analysis(domain, spf, dmarc, dkim)

        # ── Phase 6: Aggregate findings and score ─────────────────────────────
        total_exposure = min(
            100,
            spf.exposure + dmarc.exposure + dkim.exposure + cross_exposure
        )
        health_score = max(0, 100 - total_exposure)

        # Grade based on health score
        grade = (
            "A" if health_score >= 90 else
            "B" if health_score >= 75 else
            "C" if health_score >= 60 else
            "D" if health_score >= 45 else "F"
        )

        # All providers (union of SPF + DKIM)
        all_providers: List[str] = []
        for p in spf.providers + dkim.providers:
            if p not in all_providers:
                all_providers.append(p)

        # Ordered findings: cross first (most actionable), then by protocol
        all_findings = (
            cross_findings
            + spf.findings
            + dmarc.findings
            + dkim.findings
        )

        # Lead summary finding
        critical_count = sum(1 for f in all_findings if f.severity == "critical")
        high_count     = sum(1 for f in all_findings if f.severity == "high")
        summary_sev    = "critical" if critical_count else "medium" if high_count else "info"

        summary_finding = Finding(
            id=f"auth-summary-{domain}",
            category="authentication",
            severity=summary_sev,
            title=f"Authentication Health: {domain} — Score {health_score}/100 (Grade {grade})",
            description=(
                f"Authentication posture for {domain}: "
                f"SPF {'✓' if spf.present else '✗'} | "
                f"DMARC {'✓' if dmarc.present else '✗'} "
                f"{'(p=' + dmarc.policy + ')' if dmarc.present else ''} | "
                f"DKIM {'✓ (' + str(len(dkim.selectors)) + ' selector' + ('s' if len(dkim.selectors) != 1 else '') + ')' if dkim.selectors else '✗'}. "
                + (f"{critical_count} critical issue(s) require immediate attention." if critical_count else
                   "No critical authentication issues detected.")
            ),
            recommended_action=(
                "Review the findings below in severity order. "
                "Prioritise deploying DMARC p=reject as the primary goal — "
                "SPF and DKIM are prerequisites."
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

        all_findings.insert(0, summary_finding)

        # ── Scan metadata ─────────────────────────────────────────────────────
        scan_duration_ms = round((time.monotonic() - scan_start) * 1000)

        return ScanResult(
            scan_id=scan_id,
            tenant_id=domain,
            family="authentication",
            findings=all_findings,
            score=total_exposure,   # V2 convention: higher = more exposed
            status="complete",
            timestamp=datetime.now(timezone.utc).isoformat(),
            evidence={
                "domain":             domain,
                "health_score":       health_score,
                "grade":              grade,
                "spf": {
                    "present":         spf.present,
                    "record":          spf.record,
                    "policy":          spf.policy,
                    "multiple":        spf.multiple,
                    "lookup_count":    spf.lookup_count,
                    "includes":        spf.includes,
                    "providers":       spf.providers,
                },
                "dmarc": {
                    "present":         dmarc.present,
                    "record":          dmarc.record,
                    "policy":          dmarc.policy,
                    "subdomain_policy": dmarc.subdomain_policy,
                    "pct":             dmarc.pct,
                    "rua":             dmarc.rua,
                    "ruf":             dmarc.ruf,
                    "aspf":            dmarc.aspf,
                    "adkim":           dmarc.adkim,
                    "multiple":        dmarc.multiple,
                },
                "dkim": {
                    "selectors_found":     dkim.selectors,
                    "selectors_attempted": len(DKIM_SELECTORS),
                    "providers":           dkim.providers,
                },
                "detected_providers": all_providers,
                "score_breakdown": {
                    "spf_exposure":   spf.exposure,
                    "dmarc_exposure": dmarc.exposure,
                    "dkim_exposure":  dkim.exposure,
                    "cross_exposure": cross_exposure,
                    "total":          total_exposure,
                },
                "scan_metadata": {
                    "scan_type":        "authentication_health",
                    "module_version":   MODULE_VERSION,
                    "scan_duration_ms": scan_duration_ms,
                    "selectors_checked": len(DKIM_SELECTORS),
                },
            },
        )
