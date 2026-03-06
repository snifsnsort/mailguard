"""
Scan engine — orchestrates all security checks and computes the posture score.

Scoring model:
  Each check has a max_points value.
  PASS   → full points awarded
  WARN   → half points awarded
  FAIL   → 0 points
  Score  = (awarded / total_possible) * 100, rounded to int
  Grade  = A(90+) B(75+) C(60+) D(45+) F(<45)
"""
import asyncio
from typing import List, Dict, Any, Optional
from app.services.graph_client import GraphClient
from app.services.exchange_checker import ExchangeChecker
from app.services.mx_analyzer import analyze_mx, MxAnalysis, SEG_CHECK_CONTEXT
from app.services.lookalike_detector import generate_common_squats
from app.services.google_workspace_checker import GoogleWorkspaceChecker, is_google_workspace_domain, GWS_CHECK_WEIGHTS
from app.models.schemas import FindingResult, Severity


# ── Penalty model ─────────────────────────────────────────────────────────────
# Score starts at 100. Each failing check deducts its penalty.
# FAIL = full penalty deducted. WARN = half penalty deducted. PASS = 0 deducted.
# Penalties are grouped by business criticality, not arbitrary point values.
#
#   CRITICAL (15 pts) — direct breach path or compliance mandate
#   HIGH     (10 pts) — significant attack surface
#   MEDIUM   ( 7 pts) — hardening gap with real-world exploitation
#   LOW      ( 3 pts) — best practice / defence-in-depth

CHECK_WEIGHTS = {
    # ── CRITICAL ──────────────────────────────────────────────────────────────
    "mfa_admins":                 15,
    "legacy_auth_blocked":        15,
    "dmarc_policy":               15,
    "mx_bypass_risk":             15,
    # ── HIGH ──────────────────────────────────────────────────────────────────
    "dkim_enabled":               10,
    "antiphishing_impersonation": 10,
    "safe_links_assigned":        10,
    "direct_send_restricted":     10,
    # ── MEDIUM ────────────────────────────────────────────────────────────────
    "spf_record":                  7,
    "mx_gateway":                  7,
    "lookalike_domains":           7,
    "safe_attachments_mode":       7,
    "antispam_outbound":           7,
    # ── LOW ───────────────────────────────────────────────────────────────────
    "security_defaults_ca":        3,
    # ── Teams & SharePoint ────────────────────────────────────────────────────
    "teams_guest_access":          7,
    "teams_external_access":       7,
    "sharepoint_external_sharing": 10,
    # ── Google Workspace ──────────────────────────────────────────────────────
    "gws_2sv_enforcement":        15,
    "gws_super_admin_mfa":        15,
    "gws_dmarc_policy":           15,
    "gws_less_secure_apps":       10,
    "gws_dkim_enabled":           10,
    "gws_third_party_oauth":      10,
    "gws_gmail_auto_forward":     10,
    "gws_spf_record":              7,
    "gws_mx_routing":              7,
    "gws_imap_pop_access":         7,
    "gws_password_strength":       7,
    "gws_password_reuse":          7,
    "gws_2sv_grace_period":        3,
    "gws_alert_center":            3,
}

CHECK_PENALTIES = CHECK_WEIGHTS  # alias


def _grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 45: return "D"
    return "F"


def _compute_score(findings: list, weights: dict) -> tuple[int, list]:
    """
    Points-earned model: PASS=full points, WARN=half points, FAIL=0.
    Per-domain checks are averaged across domains so multi-domain tenants
    score fairly (adding domains doesn't inflate or deflate the score).
    Returns (score_0_to_100, breakdown).
    """
    from collections import defaultdict
    grouped: dict = defaultdict(list)
    for f in findings:
        check_id = f.check_id if hasattr(f, "check_id") else f.get("check_id", "")
        status   = f.status   if hasattr(f, "status")   else f.get("status", "pass")
        name     = f.name     if hasattr(f, "name")     else f.get("name", check_id)
        if check_id not in weights:
            continue
        grouped[check_id].append({"status": status, "name": name})

    total_possible = 0
    total_earned   = 0
    breakdown      = []

    for check_id, entries in grouped.items():
        max_pts = weights[check_id]
        earned_list = []
        for e in entries:
            if e["status"] == "pass":
                earned_list.append(max_pts)
            elif e["status"] == "warn":
                earned_list.append(max_pts / 2)
            else:
                earned_list.append(0)
        avg_earned = sum(earned_list) / len(earned_list)
        total_possible += max_pts
        total_earned   += avg_earned
        breakdown.append({
            "check_id":      check_id,
            "name":          entries[0]["name"],
            "status":        entries[0]["status"] if len(entries) == 1 else "mixed",
            "points_earned": round(avg_earned, 1),
            "max_points":    max_pts,
        })

    score = round((total_earned / total_possible) * 100) if total_possible > 0 else 0
    return max(0, min(100, score)), breakdown


class ScanEngine:
    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        domain: str,
        domains: Optional[List[str]] = None,
        gws_access_token: Optional[str] = None,
        has_m365: bool = True,
        has_gws: bool = False,
    ):
        self.graph   = GraphClient(tenant_id, client_id, client_secret)
        self.exo     = ExchangeChecker(tenant_id, client_id, client_secret)
        self.domain  = domain
        self.domains: List[str] = domains if domains else [domain]
        self.gws_access_token = gws_access_token
        self._has_m365 = has_m365
        self._has_gws  = has_gws
        self.findings: List[FindingResult] = []
        self._mx_analyses: Dict[str, Optional[MxAnalysis]] = {}
        self._mx_analysis: Optional[MxAnalysis] = None
        self._is_google_workspace: bool = False

    def _add(self, finding: FindingResult, weight_key: str = ""):
        """Append a finding. weight_key kept for call-site compat but unused — scoring is done in run()."""
        self.findings.append(finding)

    def _apply_seg_context(
        self,
        check_id: str,
        status: str,
        severity: Severity,
        desc: str,
    ) -> tuple[str, Severity, str]:
        """
        If a SEG is the exclusive inbound path (no split-MX), look up vendor-specific
        context for this check.  Returns (status, severity, desc) — potentially
        with a downgraded severity and appended vendor note.

        Rules:
          - Only applied when has_seg=True AND split_mx=False
          - If downgrade=True in SEG_CHECK_CONTEXT and status is 'fail',
            severity is softened to warning (reflects architecture choice, not a gap)
          - The vendor note is always appended when a context entry exists
          - Abnormal Security is API-based (post-delivery) so it never triggers a
            downgrade even if listed — handled via downgrade=False in its entries
        """
        mx = self._mx_analysis
        if not mx or not mx.has_seg or mx.split_mx:
            return status, severity, desc

        for vendor in mx.gateways:
            # Normalise vendor string for lookup (handles partial matches like
            # "Proofpoint Essentials" vs "Proofpoint")
            ctx = SEG_CHECK_CONTEXT.get(vendor) or next(
                (v for k, v in SEG_CHECK_CONTEXT.items() if k in vendor or vendor in k),
                None,
            )
            if not ctx:
                continue
            entry = ctx.get(check_id)
            if not entry:
                continue
            downgrade, note = entry
            # Append vendor-specific note
            desc = f"{desc} [{vendor}] {note}"
            # Downgrade fail → warn if this check is architecturally redundant with SEG
            if downgrade and status == "fail":
                status = "warn"
                severity = Severity.warning
            break  # Apply first matching vendor only (primary gateway)

        return status, severity, desc


    # ── DNS / MX checks ───────────────────────────────────────────────────────

    async def _check_mx_gateway(self, domain: str):
        """Detect SEG gateways from MX records and assess routing consistency."""
        try:
            from app.services.mx_analyzer import (
                ROUTING_CLEAN, ROUTING_SPLIT, ROUTING_MULTI_SEG,
                ROUTING_INCONSISTENT, ROUTING_ERRORS, ROUTING_UNKNOWN
            )
            mx = await analyze_mx(domain)
            self._mx_analyses[domain] = mx
            self._mx_analysis = mx

            anomaly_suffix = ""
            if mx.anomalies:
                anomaly_suffix = f" Unresolvable hosts: {'; '.join(mx.anomalies)}"

            current = {
                r.host: f"{r.vendor or 'Unknown'} | a={'yes' if r.has_a_record else 'NO'}"
                for r in mx.raw_records
            }

            if not mx.raw_records:
                status, severity = "warn", Severity.warning
                desc = "No MX records found — unable to determine mail routing."
                remediation = ["Verify DNS MX records are correctly configured for your domain."]

            elif mx.routing_type == ROUTING_MULTI_SEG:
                status, severity = "fail", Severity.critical
                desc = (
                    f"Multiple conflicting SEG vendors in MX records: {', '.join(mx.gateways)}. "
                    f"Mail only flows through the highest-priority gateway — the others receive no traffic "
                    f"but create inconsistent security policies."
                )
                desc += anomaly_suffix
                remediation = mx.recommendations

            elif mx.routing_type == ROUTING_SPLIT:
                status, severity = "fail", Severity.critical
                seg_list = ', '.join(mx.gateways)
                desc = (
                    f"SEG bypass risk: {seg_list} + Microsoft EOP MX records coexist. "
                    f"Attackers can skip {seg_list} by delivering directly to the EOP MX record, "
                    f"bypassing all gateway controls."
                )
                desc += anomaly_suffix
                remediation = mx.recommendations

            elif mx.routing_type == ROUTING_INCONSISTENT:
                status, severity = "fail", Severity.critical
                desc = (
                    "Inconsistent MX records: Microsoft EOP and Google Workspace MX hosts coexist. "
                    "These belong to two different mail platforms — this is almost always a misconfiguration "
                    "and may cause mail to be split between platforms unpredictably."
                )
                desc += anomaly_suffix
                remediation = mx.recommendations

            elif mx.routing_type == ROUTING_ERRORS:
                status, severity = "fail", Severity.critical
                unresolvable = [r.host for r in mx.raw_records if not r.has_a_record]
                desc = f"MX host(s) do not resolve to any IP address: {', '.join(unresolvable)}. Mail delivery to these hosts will fail."
                remediation = mx.recommendations

            elif mx.routing_type == ROUTING_CLEAN and mx.has_seg:
                if mx.anomalies:
                    status, severity = "warn", Severity.warning
                    desc = f"SEG routing ({', '.join(mx.gateways)}) is consistent but has issues.{anomaly_suffix}"
                else:
                    status, severity = "pass", Severity.pass_
                    desc = (
                        f"Consistent SEG routing: {', '.join(mx.gateways)}. "
                        f"All MX records point to the same gateway vendor."
                    )
                remediation = mx.recommendations

            elif mx.routing_type == ROUTING_CLEAN:
                if mx.anomalies:
                    status, severity = "warn", Severity.warning
                    desc = f"Mail routing is consistent but has issues.{anomaly_suffix}"
                else:
                    status, severity = "pass", Severity.pass_
                    desc = mx.summary
                remediation = mx.recommendations

            else:
                status, severity = "warn", Severity.warning
                desc = f"Unrecognized MX configuration: {', '.join(r.host for r in mx.raw_records)}.{anomaly_suffix}"
                remediation = ["Verify your MX configuration and mail routing path."]

        except Exception as e:
            status, severity = "warn", Severity.warning
            desc = f"Unable to analyze MX records: {e}"
            current = "Error"
            remediation = []

        self._add(FindingResult(
            check_id="mx_gateway",
            name="MX Gateway / Mail Routing",
            category="Mail Routing",
            severity=severity,
            status=status,
            description=desc,
            current_value=current,
            expected_value="Single consistent mail flow path — one SEG vendor or one native platform (EOP/GWS), all hosts resolving",
            remediation=remediation,
            reference_url="https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/mail-flow-best-practices",
            benchmark="Microsoft Exchange Online Best Practices",
            domain=domain,
        ), "mx_gateway")

    async def _check_mx_bypass(self, domain: str):
        """Check for direct-to-EOP bypass risk when a SEG is present."""
        # Depends on _check_mx_gateway having run first
        mx = self._mx_analyses.get(domain)

        if mx is None:
            # Run it now if not already done
            try:
                mx = await analyze_mx(domain)
                self._mx_analyses[domain] = mx
                self._mx_analysis = mx
            except Exception as e:
                self._add(FindingResult(
                    check_id="mx_bypass_risk",
                    name="SEG Bypass Risk (Direct-to-EOP)",
                    category="Mail Routing",
                    severity=Severity.warning,
                    status="warn",
                    description=f"Unable to evaluate bypass risk: {e}",
                    current_value="Unknown",
                    expected_value="No Microsoft EOP MX record visible when SEG is in use",
                    remediation=[],
                    reference_url="https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/enhanced-filtering-for-connectors",
                    benchmark="Microsoft Exchange Online Best Practices",
                    domain=domain,
                ), "mx_bypass_risk")
                return

        if not mx.has_seg:
            # No SEG — bypass check not applicable, give full points
            self._add(FindingResult(
                check_id="mx_bypass_risk",
                name="SEG Bypass Risk (Direct-to-EOP)",
                category="Mail Routing",
                severity=Severity.pass_,
                status="pass",
                description="Mail routes directly through Microsoft EOP with no third-party SEG — bypass risk not applicable.",
                current_value="N/A — no SEG in use",
                expected_value="N/A",
                remediation=[
                    "No action required — mail flows directly through Microsoft EOP.",
                    "Periodically verify MX records have not been misconfigured.",
                ],
                reference_url="https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/enhanced-filtering-for-connectors",
                benchmark="Microsoft Exchange Online Best Practices",
                domain=domain,
            ), "mx_bypass_risk")
            return

        if mx.bypass_risk:
            status, severity = "fail", Severity.critical
            gw_list = ", ".join(mx.gateways)
            desc = (
                f"Direct-to-EOP bypass is possible. Your domain publishes a Microsoft EOP MX record "
                f"(*.protection.outlook.com) alongside {gw_list}. Attackers can skip {gw_list} "
                f"entirely by delivering to the EOP MX, bypassing URL scanning, attachment detonation, "
                f"and all SEG-enforced policies."
            )
            # Proofpoint-specific remediation from v4.10 guide (p.10-17)
            vendor = (mx.vendor or "").lower()
            if "proofpoint" in vendor:
                remediation = [
                    "[Proofpoint v4.10, p.16-17] Method 6A (Recommended): Create a 'Block Direct Delivery' "
                    "EOP Connector in Exchange Admin Center → Mail flow → Connectors:",
                    "  • Connection from: Partner organization",
                    "  • Identify partner by: sender domain matches '*' (wildcard)",
                    "  • Security: 'Reject email if not sent from within this IP address range' "
                    "— add ALL Proofpoint Protection Server egress IPs",
                    "  • Also add any other authorized mail systems (on-prem Exchange, bulk senders)",
                    "First, set up the 'Audit Direct Delivery' transport rule to identify all direct "
                    "delivery sources before blocking (tag with X-EOP-DirectDelivery=True, except "
                    "Proofpoint IPs and X-MS-Exchange-Organization-AuthAs=Internal).",
                    "Remove the *.protection.outlook.com MX record from public DNS.",
                    "Enable Enhanced Filtering for Connectors on the 'Inbound from Proofpoint' connector "
                    "so EOP can see original sender IPs (skip Proofpoint cluster IPs).",
                    "Avoid Method 6D (do nothing) — actively exploited by attackers per v4.10 guide.",
                ]
            else:
                remediation = [
                    f"Remove the *.protection.outlook.com MX record from public DNS immediately.",
                    f"Create a dedicated inbound connector in Exchange Online that requires mail "
                    f"to arrive from {gw_list} IP ranges only.",
                    "Enable 'Enhanced Filtering for Connectors' so Microsoft EOP sees original sender IPs.",
                    "Add a transport rule to reject mail not arriving via the approved connector.",
                    "Test by attempting direct SMTP delivery to your EOP hostname — it should be rejected.",
                ]
        else:
            status, severity = "pass", Severity.pass_
            gw_list = ", ".join(mx.gateways)
            desc = f"{gw_list} is configured as the exclusive inbound MX — no direct-to-EOP bypass detected."
            remediation = [
                "Periodically re-verify that no Microsoft EOP MX record has been re-added to DNS.",
                "Ensure your inbound connector enforces SEG IP allowlisting.",
            ]

        # Apply vendor-specific context note (e.g. Proofpoint v4.10 Method 6A guidance)
        status, severity, desc = self._apply_seg_context("mx_bypass_risk", status, severity, desc)

        self._add(FindingResult(
            check_id="mx_bypass_risk",
            name="SEG Bypass Risk (Direct-to-EOP)",
            category="Mail Routing",
            severity=severity,
            status=status,
            description=desc,
            current_value={r.host: r.vendor or "Unknown" for r in mx.raw_records} if mx.raw_records else "Unknown",
            expected_value="No Microsoft EOP MX record when SEG is in use",
            remediation=remediation,
            reference_url="https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/enhanced-filtering-for-connectors",
            benchmark="Microsoft Exchange Online Best Practices / Proofpoint v4.10 Integration Guide",
            domain=domain,
        ), "mx_bypass_risk")

    async def _check_lookalike_domains(self, domain: str):
        """
        Generate typosquat candidates, score them, resolve DNS,
        and report ONLY domains that are registered (have A or MX records).
        """
        try:
            from app.services.lookalike_detector import detect_registered_lookalikes

            candidates = generate_common_squats(domain)
            # Score all candidates, resolve DNS only for those that score high enough
            matches, dns_map = await detect_registered_lookalikes(
                base_domains=[self.domain],
                candidate_domains=candidates,
                min_score=45,   # Score threshold before DNS check
                concurrency=40,
            )

            flagged = [m for m in matches if m.risk_level == "flag" and m.overall_score >= 70]
            review  = [m for m in matches if m.risk_level in ("flag", "review") and m not in flagged]
            total   = len(matches)

            if flagged:
                status, severity = "fail", Severity.critical
                top = flagged[0]
                dns = dns_map.get(top.candidate)
                dns_note = ""
                if dns:
                    if dns.has_mx:
                        dns_note = f" Has active MX records — may be sending email."
                    elif dns.has_a:
                        dns_note = f" Resolves to {dns.a_records[0]} — likely a live site."
                desc = (
                    f"{len(flagged)} registered high-risk lookalike domain(s) found for {self.domain}. "
                    f"Top threat: '{top.candidate}' (score {top.overall_score}/100).{dns_note} "
                    f"Reason: {'; '.join(top.reasons[:2])}."
                )
            elif review:
                status, severity = "warn", Severity.warning
                top = review[0]
                desc = (
                    f"{len(review)} registered domain(s) worth reviewing for lookalike risk against {self.domain}. "
                    f"Top match: '{top.candidate}' (score {top.overall_score}/100)."
                )
            else:
                status, severity = "pass", Severity.pass_
                desc = f"No registered lookalike domains detected for {self.domain} (checked {len(candidates)} candidates)."

            top_matches = []
            for m in (flagged + review)[:20]:
                dns = dns_map.get(m.candidate)
                top_matches.append({
                    "domain":         m.candidate,
                    "score":          m.overall_score,
                    "risk":           m.risk_level,
                    "reasons":        m.reasons,
                    "has_a_record":   dns.has_a if dns else False,
                    "has_mx_record":  dns.has_mx if dns else False,
                    "a_records":      dns.a_records[:3] if dns else [],
                    "mx_records":     dns.mx_records[:2] if dns else [],
                    "signals": {
                        "levenshtein":   round(m.signals.levenshtein, 3),
                        "damerau":       round(m.signals.damerau, 3),
                        "jaro_winkler":  round(m.signals.jaro_winkler, 3),
                        "ngram2":        round(m.signals.ngram2, 3),
                        "ngram3":        round(m.signals.ngram3, 3),
                        "keyboard_typo": round(m.signals.keyboard_typo, 3),
                        "homoglyph":     round(m.signals.homoglyph, 3),
                        "phonetic":      round(m.signals.phonetic, 3),
                    },
                    "has_homoglyphs": m.has_homoglyphs,
                    "mixed_script":   m.mixed_script,
                    "tld_swap":       m.tld_swap,
                })

        except Exception as e:
            status, severity = "warn", Severity.warning
            desc = f"Unable to run lookalike detection: {e}"
            top_matches = []

        self._add(FindingResult(
            check_id="lookalike_domains",
            name="Domain Lookalike / Typosquat Detection",
            category="Domain Protection",
            severity=severity,
            status=status,
            description=desc,
            current_value=top_matches,
            expected_value="No high-risk registered lookalike domains (score ≥ 70)",
            remediation=[
                "Register the most similar typosquat variants of your domain defensively.",
                "Set up monitoring via services like DomainTools, Cisco Umbrella, or free tools like dnstwist.",
                "Configure DMARC reporting (rua/ruf tags) to detect spoofed mail from lookalike domains.",
                "Consider brand protection services for continuous lookalike monitoring.",
                "File abuse reports for confirmed phishing domains via ICANN or the registrar.",
            ],
            reference_url="https://www.cisa.gov/sites/default/files/publications/CISA_MS-ISAC_Ransomware%20Guide_S508C.pdf",
            benchmark="NIST SP 800-61 / Brand Protection Best Practices",
                    domain=domain,
        ), "lookalike_domains")

    # ── Existing checks (unchanged) ───────────────────────────────────────────

    async def _check_dmarc(self, domain: str):
        import re
        record = await self.graph.get_dmarc_record(domain)
        # Also get all TXT records to check for duplicates
        all_txt = await self.graph.get_dns_txt_records(domain)

        # Check at _dmarc.domain — count DMARC records
        # get_dmarc_record already queries _dmarc.domain; check for multiples via all TXT on _dmarc
        dmarc_records = [r for r in all_txt if r.startswith("v=DMARC1")]

        # Multiple DMARC records — same as SPF: PermError
        if len(dmarc_records) > 1:
            status, severity = "fail", Severity.critical
            desc = (
                f"Multiple DMARC records found ({len(dmarc_records)}) — RFC 7489 requires exactly one. "
                f"This causes DMARC to fail permanently (PermError) for all receiving mail servers."
            )
            if status == "pass":
                remediation = []
            else:
                remediation = [
                    "Delete all but one DMARC TXT record from _dmarc." + domain,
                    "Keep only: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com",
                    "Validate with: https://mxtoolbox.com/dmarc.aspx",
                ]
            self._add(FindingResult(
                check_id="dmarc_policy",
                name="DMARC Policy Enforcement",
                category="SPF/DKIM/DMARC",
                severity=severity, status=status, description=desc,
                current_value=dmarc_records,
                expected_value="Exactly one DMARC record at _dmarc." + domain,
                remediation=remediation,
                reference_url="https://datatracker.ietf.org/doc/html/rfc7489",
                benchmark="CIS Microsoft 365 Foundations Benchmark v2.0 — Control 6.5.2",
                domain=domain,
            ), "dmarc_policy")
            return

        if not record:
            status, severity = "fail", Severity.critical
            desc = "No DMARC record found."
            current = "No DMARC TXT record at _dmarc." + domain
            remediation = [
                "Access your DNS management console.",
                "Locate or create the _dmarc TXT record.",
                "Set p=quarantine initially, monitor reports for 2 weeks.",
                "Escalate to p=reject once legitimate mail is confirmed.",
            ]
            self._add(FindingResult(
                check_id="dmarc_policy",
                name="DMARC Policy Enforcement",
                category="SPF/DKIM/DMARC",
                severity=severity, status=status, description=desc,
                current_value=current,
                expected_value="v=DMARC1; p=reject; rua=mailto:dmarc@domain.com",
                remediation=remediation,
                reference_url="https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-dmarc-configure",
                benchmark="CIS Microsoft 365 Foundations Benchmark v2.0 — Control 6.5.2",
                domain=domain,
            ), "dmarc_policy")
            return

        # Parse tags
        tags = {}
        syntax_errors = []
        valid_tag_names = {'v', 'p', 'sp', 'rua', 'ruf', 'adkim', 'aspf', 'pct', 'fo', 'rf', 'ri'}
        for part in record.split(";"):
            part = part.strip()
            if not part:
                continue
            if "=" not in part:
                syntax_errors.append(f"Invalid token '{part}' (missing '=')")
                continue
            k, _, v = part.partition("=")
            k = k.strip().lower()
            v = v.strip()
            if k not in valid_tag_names:
                syntax_errors.append(f"Unknown DMARC tag '{k}'")
            tags[k] = v

        # Validate specific tags
        policy = tags.get("p", "").lower()
        sp_policy = tags.get("sp", "").lower()
        adkim = tags.get("adkim", "r").lower()
        aspf = tags.get("aspf", "r").lower()
        pct = tags.get("pct", "100")

        if policy not in ("none", "quarantine", "reject", ""):
            syntax_errors.append(f"Invalid p= value '{policy}' — must be none, quarantine, or reject")
        if sp_policy and sp_policy not in ("none", "quarantine", "reject"):
            syntax_errors.append(f"Invalid sp= value '{sp_policy}'")
        if adkim not in ("r", "s"):
            syntax_errors.append(f"Invalid adkim= value '{adkim}' — must be r or s")
        if aspf not in ("r", "s"):
            syntax_errors.append(f"Invalid aspf= value '{aspf}' — must be r or s")
        try:
            pct_int = int(pct)
            if not (0 <= pct_int <= 100):
                syntax_errors.append(f"pct= value {pct} out of range (0-100)")
        except ValueError:
            syntax_errors.append(f"Invalid pct= value '{pct}'")

        issues = []
        if syntax_errors:
            issues.extend(syntax_errors)
        if pct not in ("100", "") and not syntax_errors:
            issues.append(f"pct={pct} — policy only applies to {pct}% of mail; set pct=100 for full enforcement")
        if "rua" not in tags:
            issues.append("No rua= tag — you won't receive aggregate reports to monitor mail flow")

        if syntax_errors:
            status, severity = "fail", Severity.critical
            desc = f"DMARC record has syntax errors: {'; '.join(syntax_errors)}. Mail receiving servers may ignore this record."
        elif policy == "none":
            status, severity = "fail", Severity.critical
            desc = f"DMARC policy is 'none' — monitoring mode only. No mail is quarantined or rejected."
            if issues:
                desc += f" Additional issues: {'; '.join(issues)}."
        elif policy == "quarantine":
            status, severity = "warn", Severity.warning
            desc = "DMARC policy is 'quarantine' — consider escalating to 'reject'."
            if issues:
                desc += f" Issues: {'; '.join(issues)}."
        elif policy == "reject":
            if issues:
                status, severity = "warn", Severity.warning
                desc = f"DMARC is enforced (reject) but has configuration gaps: {'; '.join(issues)}."
            else:
                status, severity = "pass", Severity.pass_
                desc = "DMARC policy is enforced (reject)."
        else:
            status, severity = "fail", Severity.critical
            desc = f"DMARC record is malformed — policy value missing or unrecognized."

        if status == "pass":
            remediation = [
                "DMARC is enforced at p=reject — maintain this configuration.",
                "Ensure rua/ruf reporting tags are set to receive aggregate and forensic reports.",
                "Review DMARC reports regularly for spoofing attempts or mail flow issues.",
                "Consider strict alignment: adkim=s; aspf=s for maximum protection.",
            ]
        elif status == "warn":
            remediation = [
                "DMARC is set to p=quarantine or has gaps — review aggregate reports and resolve.",
                "Add rua tag to receive aggregate reports: rua=mailto:dmarc@yourdomain.com",
                "Once reporting is clean for 2+ weeks, upgrade to: p=reject; sp=reject",
                "Validate with: https://mxtoolbox.com/dmarc.aspx",
            ]
        else:
            remediation = [
                "Fix DMARC syntax errors before any policy enforcement will work.",
                "Use a DMARC wizard (e.g. dmarcian.com/dmarc-record-wizard) to generate a valid record.",
                "Set p=quarantine initially, monitor reports for 2 weeks.",
                "Escalate to p=reject once legitimate mail is confirmed.",
            ]

        self._add(FindingResult(
            check_id="dmarc_policy",
            name="DMARC Policy Enforcement",
            category="SPF/DKIM/DMARC",
            severity=severity, status=status, description=desc,
            current_value=record or "Not found",
            expected_value="v=DMARC1; p=reject; rua=mailto:dmarc@domain.com",
            remediation=remediation,
            reference_url="https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-dmarc-configure",
            benchmark="CIS Microsoft 365 Foundations Benchmark v2.0 — Control 6.5.2",
            domain=domain,
        ), "dmarc_policy")

    async def _check_dkim(self, domain: str):
        selectors = await self.graph.get_dkim_selectors(domain)
        configured = {k: v for k, v in selectors.items() if v}
        if not configured:
            status, severity = "fail", Severity.critical
            desc = "No DKIM CNAME selectors found for the primary domain."
        else:
            status, severity = "pass", Severity.pass_
            desc = f"DKIM selectors configured: {', '.join(configured.keys())}."

        self._add(FindingResult(
            check_id="dkim_enabled",
            name="DKIM Signing Enabled",
            category="SPF/DKIM/DMARC",
            severity=severity, status=status, description=desc,
            current_value=selectors,
            expected_value={"selector1": "<cname>", "selector2": "<cname>"},
            remediation=[
                "Go to Microsoft 365 Defender → Email & Collaboration → Policies → DKIM.",
                "Select your domain and click 'Enable'.",
                "Publish the two generated CNAME records to your DNS provider.",
                "Wait up to 48h for propagation, then verify in the portal.",
            ],
            reference_url="https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-dkim-configure",
            benchmark="CIS Microsoft 365 Foundations Benchmark v2.0 — Control 6.5.1",
            domain=domain,
        ), "dkim_enabled")

    async def _check_spf(self, domain: str):
        import re
        records = await self.graph.get_dns_txt_records(domain)
        spf_records = [r for r in records if r.startswith("v=spf1")]

        issues = []
        spf = None

        # Multiple SPF records — RFC 7208 Section 3.2: exactly one SPF record required
        if len(spf_records) > 1:
            status, severity = "fail", Severity.critical
            desc = (
                f"Multiple SPF records found ({len(spf_records)}) — RFC 7208 requires exactly one. "
                f"This causes SPF to fail permanently (PermError). Records found: "
                f"{' | '.join(spf_records[:3])}"
            )
            self._add(FindingResult(
                check_id="spf_record",
                name="SPF Record Configured",
                category="SPF/DKIM/DMARC",
                severity=severity, status=status, description=desc,
                current_value=spf_records,
                expected_value="Exactly one SPF TXT record per domain",
                remediation=[
                    "Delete all but one SPF TXT record from your DNS.",
                    "Merge all includes/mechanisms into a single v=spf1 record.",
                    "Example: v=spf1 include:spf.protection.outlook.com include:other.com -all",
                    "Validate with: https://mxtoolbox.com/spf.aspx",
                ],
                reference_url="https://datatracker.ietf.org/doc/html/rfc7208#section-3.2",
                benchmark="CIS Microsoft 365 Foundations Benchmark v2.0 — Control 6.5.3",
                domain=domain,
            ), "spf_record")
            return

        if not spf_records:
            status, severity = "fail", Severity.critical
            desc = "No SPF record found for the primary domain."
            self._add(FindingResult(
                check_id="spf_record",
                name="SPF Record Configured",
                category="SPF/DKIM/DMARC",
                severity=severity, status=status, description=desc,
                current_value="Not found",
                expected_value="v=spf1 include:spf.protection.outlook.com -all",
                remediation=[
                    "Add a TXT record for your domain: v=spf1 include:spf.protection.outlook.com -all",
                    "Avoid having multiple SPF records — merge into one.",
                    "Validate with: https://mxtoolbox.com/spf.aspx",
                ],
                reference_url="https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-spf-configure",
                benchmark="CIS Microsoft 365 Foundations Benchmark v2.0 — Control 6.5.3",
                domain=domain,
            ), "spf_record")
            return

        spf = spf_records[0]

        # Syntax checks
        # Check for unknown/invalid mechanisms
        valid_mechanisms = re.compile(
            r'^(v=spf1|[-+~?]?(all|include:[^\s]+|a[:/]?[^\s]*|mx[:/]?[^\s]*|'
            r'ptr[:/]?[^\s]*|ip4:[^\s]+|ip6:[^\s]+|exists:[^\s]+|redirect=[^\s]+|'
            r'exp=[^\s]+))$'
        )
        parts = spf.split()
        invalid_parts = []
        for part in parts[1:]:  # skip v=spf1
            if not valid_mechanisms.match(part):
                invalid_parts.append(part)

        # Count DNS lookup mechanisms (RFC 7208: max 10)
        lookup_mechanisms = ['include:', 'a', 'mx', 'ptr', 'exists:', 'redirect=']
        lookup_count = sum(
            1 for p in parts
            if any(p.lstrip('+-~?').startswith(m) for m in lookup_mechanisms)
        )

        # Check for missing -all / ~all / ?all
        has_all = any(p in ('-all', '~all', '+all', '?all') for p in parts)

        # Check for +all (allow all — completely open)
        has_plus_all = '+all' in parts

        if has_plus_all:
            issues.append("'+all' makes SPF useless — any server can send as your domain")
        if invalid_parts:
            issues.append(f"Unrecognized SPF mechanisms: {', '.join(invalid_parts)}")
        if lookup_count > 10:
            issues.append(f"Too many DNS lookups ({lookup_count}/10 max) — will cause PermError during evaluation")
        elif lookup_count >= 8:
            issues.append(f"Approaching DNS lookup limit ({lookup_count}/10) — reduce includes to avoid future PermError")
        if not has_all:
            issues.append("No 'all' mechanism — SPF record is incomplete and may not enforce policy")

        if issues:
            status, severity = "fail" if any("PermError" in i or "useless" in i for i in issues) else "warn", \
                               Severity.critical if any("PermError" in i or "useless" in i for i in issues) else Severity.warning
            desc = f"SPF record has issues: {'; '.join(issues)}."
        elif "-all" in spf:
            status, severity = "pass", Severity.pass_
            desc = "SPF record present with hard fail (-all)."
        elif "~all" in spf:
            status, severity = "warn", Severity.warning
            desc = "SPF uses softfail (~all) — consider upgrading to hard fail (-all) to reject unauthorized senders."
        else:
            status, severity = "warn", Severity.warning
            desc = "SPF record exists but policy may be too permissive."

        remediation = []
        if issues:
            if any("Too many DNS lookups" in i or "Approaching" in i for i in issues):
                remediation += [
                    "Reduce the number of 'include:' mechanisms — each counts as one DNS lookup.",
                    "Use SPF flattening tools (e.g. AutoSPF, dmarcian) to consolidate includes into ip4: ranges.",
                    "Maximum allowed DNS lookups is 10 per RFC 7208.",
                ]
            if any("Unrecognized" in i for i in issues):
                remediation += ["Remove or correct unrecognized SPF mechanisms."]
            if any("all" in i for i in issues):
                remediation += ["Add '-all' at the end of your SPF record to reject unauthorized senders."]
            if has_plus_all:
                remediation += ["Remove '+all' immediately — replace with '-all' or '~all'."]
        else:
            remediation = [
                "Add a TXT record for your domain: v=spf1 include:spf.protection.outlook.com -all",
                "Avoid having multiple SPF records — merge into one.",
                "Validate with: https://mxtoolbox.com/spf.aspx",
            ]

        self._add(FindingResult(
            check_id="spf_record",
            name="SPF Record Configured",
            category="SPF/DKIM/DMARC",
            severity=severity, status=status, description=desc,
            current_value=spf,
            expected_value="v=spf1 include:spf.protection.outlook.com -all (max 10 DNS lookups, single record)",
            remediation=remediation,
            reference_url="https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-spf-configure",
            benchmark="CIS Microsoft 365 Foundations Benchmark v2.0 — Control 6.5.3",
            domain=domain,
        ), "spf_record")

    async def _check_mfa_admins(self):
        try:
            no_mfa = await self.graph.get_users_without_mfa()
            if no_mfa:
                status, severity = "fail", Severity.critical
                desc = f"{len(no_mfa)} admin account(s) without MFA: {', '.join(no_mfa[:5])}"
            else:
                status, severity = "pass", Severity.pass_
                desc = "All admin accounts have MFA registered."
        except Exception as e:
            status, severity = "warn", Severity.warning
            desc = f"Unable to verify MFA status (check API permissions): {e}"
            no_mfa = []

        self._add(FindingResult(
            check_id="mfa_admins",
            name="MFA for Admin Accounts",
            category="MFA & Admin",
            severity=severity, status=status, description=desc,
            current_value=no_mfa or "All admins have MFA",
            expected_value="All admin accounts must have MFA registered",
            remediation=[
                "Go to Entra ID → Security → Conditional Access → New Policy.",
                "Target users with any admin role.",
                "Grant: Require multi-factor authentication.",
                "For break-glass accounts use FIDO2 hardware keys.",
            ],
            reference_url="https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-azure-mfa",
            benchmark="CIS Microsoft 365 Foundations Benchmark v2.0 — Control 1.1.1",
        ), "mfa_admins")

    async def _check_legacy_auth(self):
        try:
            policies = await self.graph.get_conditional_access_policies()
            blocks_legacy = any(
                p.get("state") == "enabled" and
                "exchangeActiveSync" in str(p.get("conditions", {}).get("clientAppTypes", []))
                for p in policies
            )
            if blocks_legacy:
                status, severity = "pass", Severity.pass_
                desc = "Conditional Access policy blocking legacy authentication found."
            else:
                status, severity = "fail", Severity.critical
                desc = "No Conditional Access policy blocking legacy authentication detected."
        except Exception as e:
            status, severity = "warn", Severity.warning
            desc = f"Unable to evaluate legacy auth CA policies: {e}"

        self._add(FindingResult(
            check_id="legacy_auth_blocked",
            name="Legacy Authentication Blocked",
            category="MFA & Admin",
            severity=severity, status=status, description=desc,
            current_value="Legacy auth allowed" if status == "fail" else "Blocked via CA",
            expected_value="Conditional Access policy blocking all legacy auth",
            remediation=[
                "Create a Conditional Access policy targeting all users.",
                "Conditions → Client apps → select legacy auth protocols.",
                "Grant → Block access.",
                "Enable in report-only mode first, review sign-in logs, then enforce.",
            ],
            reference_url="https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication",
            benchmark="CIS Microsoft 365 Foundations Benchmark v2.0 — Control 1.2.1",
        ), "legacy_auth_blocked")

    async def _check_security_defaults(self):
        try:
            sd = await self.graph.get_security_defaults()
            enabled = sd.get("isEnabled", False)
            policies = await self.graph.get_conditional_access_policies()
            ca_count = len([p for p in policies if p.get("state") == "enabled"])
            if enabled and ca_count > 0:
                status, severity = "warn", Severity.warning
                desc = f"Security Defaults enabled alongside {ca_count} active CA policies — potential conflicts."
            elif not enabled and ca_count == 0:
                status, severity = "fail", Severity.critical
                desc = "Security Defaults disabled and no Conditional Access policies found."
            else:
                status, severity = "pass", Severity.pass_
                desc = "Security posture managed via Conditional Access (Security Defaults disabled)."
        except Exception as e:
            status, severity = "warn", Severity.warning
            desc = f"Unable to evaluate Security Defaults: {e}"

        self._add(FindingResult(
            check_id="security_defaults_ca",
            name="Security Defaults vs Conditional Access",
            category="MFA & Admin",
            severity=severity, status=status, description=desc,
            current_value="See description",
            expected_value="Security Defaults OFF + Conditional Access policies active",
            remediation=[
                "Ensure all Security Defaults protections are replicated in CA policies.",
                "Disable Security Defaults: Entra ID → Properties → Manage Security Defaults.",
                "Monitor sign-in logs after the change.",
            ],
            reference_url="https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults",
            benchmark="Microsoft Best Practices — Security Defaults",
        ), "security_defaults_ca")

    async def _check_antiphishing(self):
        try:
            policy = await self.exo.get_antiphishing_policy()
            if isinstance(policy, list): policy = policy[0] if policy else {}
            user_prot   = policy.get("EnableTargetedUserProtection", False)
            domain_prot = policy.get("EnableTargetedDomainsProtection", False)
            if not user_prot and not domain_prot:
                status, severity = "fail", Severity.critical
                desc = "Both user and domain impersonation protection are disabled."
            elif not user_prot or not domain_prot:
                status, severity = "warn", Severity.warning
                desc = "Partial impersonation protection — one of user/domain protection is disabled."
            else:
                status, severity = "pass", Severity.pass_
                desc = "User and domain impersonation protection are both enabled."
        except Exception as e:
            status, severity = "warn", Severity.warning
            desc = f"Unable to read anti-phishing policy (check Exchange permissions): {e}"
            policy = {}

        status, severity, desc = self._apply_seg_context("antiphishing_impersonation", status, severity, desc)

        self._add(FindingResult(
            check_id="antiphishing_impersonation",
            name="Anti-Phishing Impersonation Protection",
            category="Anti-Phishing",
            severity=severity, status=status, description=desc,
            current_value={"EnableTargetedUserProtection": policy.get("EnableTargetedUserProtection"), "EnableTargetedDomainsProtection": policy.get("EnableTargetedDomainsProtection")},
            expected_value={"EnableTargetedUserProtection": True, "EnableTargetedDomainsProtection": True},
            remediation=[
                "Go to Microsoft 365 Defender → Anti-phishing policies.",
                "Enable 'Impersonation protection' for users — add executives and VIPs.",
                "Enable domain impersonation for owned and partner domains.",
                "Set action to 'Quarantine message' for impersonation detections.",
                "Enable mailbox intelligence.",
            ],
            reference_url="https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-phishing-policies-mdo-configure",
            benchmark="Microsoft Defender for Office 365 Best Practices",
        ), "antiphishing_impersonation")

    async def _check_antispam_outbound(self):
        try:
            policy = await self.exo.get_antispam_outbound_policy()
            if isinstance(policy, list): policy = policy[0] if policy else {}
            limit    = policy.get("RecipientLimitPerDay", 0)
            auto_fwd = policy.get("AutoForwardingMode", "On")
            # In Exchange, 0 means "unlimited" — not zero recipients
            limit_display = "Unlimited (not configured)" if limit == 0 else f"{limit}/day"
            if limit == 0 or limit > 5000 or auto_fwd == "On":
                status, severity = "warn", Severity.warning
                desc = f"Outbound recipient limit: {limit_display}; AutoForwarding: {auto_fwd}."
            else:
                status, severity = "pass", Severity.pass_
                desc = f"Outbound limits acceptable ({limit_display}); AutoForwarding: {auto_fwd}."
        except Exception as e:
            status, severity = "warn", Severity.warning
            desc = f"Unable to read outbound spam policy: {e}"
            policy = {}

        status, severity, desc = self._apply_seg_context("antispam_outbound", status, severity, desc)

        self._add(FindingResult(
            check_id="antispam_outbound",
            name="Anti-Spam Outbound Policy",
            category="Anti-Phishing",
            severity=severity, status=status, description=desc,
            current_value={"RecipientLimitPerDay": policy.get("RecipientLimitPerDay"), "AutoForwardingMode": policy.get("AutoForwardingMode")},
            expected_value={"RecipientLimitPerDay": "≤ 1000", "AutoForwardingMode": "Off or Controlled"},
            remediation=[
                "Go to Microsoft 365 Defender → Anti-spam → Outbound spam filter policy.",
                "Reduce RecipientLimitPerDay to match your highest legitimate volume.",
                "Set AutoForwardingMode to 'Automatic' (on) only if needed, or 'Off'.",
                "Enable alerts when users hit sending thresholds.",
            ],
            reference_url="https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/outbound-spam-policies-configure",
            benchmark="Microsoft Best Practices — Anti-Spam",
        ), "antispam_outbound")

    async def _check_safe_links(self):
        try:
            policies = await self.exo.get_safe_links_policies()
            rules    = await self.exo.get_safe_links_rules()
            if not isinstance(policies, list): policies = [policies] if policies else []
            if not isinstance(rules, list):    rules    = [rules]    if rules    else []
            enabled_policies = [p for p in policies if p.get("IsEnabled") or p.get("Enable")]
            assigned_rules   = [r for r in rules if r.get("State") == "Enabled"]
            if not enabled_policies:
                status, severity = "fail", Severity.critical
                desc = "No enabled Safe Links policies found."
            elif not assigned_rules:
                status, severity = "fail", Severity.critical
                desc = "Safe Links policy exists but is not assigned to any users/groups."
            else:
                status, severity = "pass", Severity.pass_
                desc = f"{len(enabled_policies)} Safe Links policy(s) enabled and assigned."
        except Exception as e:
            status, severity = "warn", Severity.warning
            desc = f"Unable to read Safe Links configuration: {e}"

        # Contextualise against MX gateway
        status, severity, desc = self._apply_seg_context("safe_links_assigned", status, severity, desc)

        self._add(FindingResult(
            check_id="safe_links_assigned",
            name="Safe Links Policy Assigned",
            category="Safe Links / Attachments",
            severity=severity, status=status, description=desc,
            current_value="See description",
            expected_value="Safe Links policy enabled and assigned to all users",
            remediation=[
                "Go to Microsoft 365 Defender → Safe Links.",
                "Edit or create a policy, enable URL scanning for email and Teams.",
                "Under 'Applied to', assign to 'All recipients' or relevant groups.",
                "Enable: Track clicks, Do not allow click-through to original URL.",
            ],
            reference_url="https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-links-policies-configure",
            benchmark="Microsoft Defender for Office 365 Best Practices",
        ), "safe_links_assigned")

    async def _check_safe_attachments(self):
        try:
            policies = await self.exo.get_safe_attachments_policy()
            if not isinstance(policies, list): policies = [policies] if policies else []
            block_policies = [p for p in policies if p.get("Action") in ("Block", "DynamicDelivery")]
            if not block_policies:
                status, severity = "fail", Severity.critical
                desc = "Safe Attachments has no active blocking/dynamic delivery policy."
            elif any(p.get("Action") == "Block" for p in block_policies):
                status, severity = "pass", Severity.pass_
                desc = "Safe Attachments policy with Block action is active."
            else:
                status, severity = "warn", Severity.warning
                desc = "Safe Attachments uses Dynamic Delivery — consider Block for high-risk users."
        except Exception as e:
            status, severity = "warn", Severity.warning
            desc = f"Unable to read Safe Attachments policy: {e}"

        status, severity, desc = self._apply_seg_context("safe_attachments_mode", status, severity, desc)

        self._add(FindingResult(
            check_id="safe_attachments_mode",
            name="Safe Attachments Policy Mode",
            category="Safe Links / Attachments",
            severity=severity, status=status, description=desc,
            current_value="See description",
            expected_value="Action: Block or DynamicDelivery (Block preferred for high-risk groups)",
            remediation=[
                "Go to Microsoft 365 Defender → Safe Attachments.",
                "Create or edit a policy — set Action to 'Block'.",
                "Enable Safe Attachments for SharePoint, OneDrive, and Teams.",
                "Enable admin quarantine notifications.",
            ],
            reference_url="https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-attachments-policies-configure",
            benchmark="Microsoft Defender for Office 365 Best Practices",
        ), "safe_attachments_mode")

    async def _check_direct_send(self):
        try:
            smtp_cfg   = await self.exo.get_smtp_auth_settings()
            connectors = await self.exo.get_receive_connectors()
            smtp_disabled = smtp_cfg.get("SmtpClientAuthenticationDisabled", False)
            if not isinstance(connectors, list): connectors = [connectors] if connectors else []
            anon_connectors = [
                c for c in connectors
                if c.get("AnonymousUsers") or "AnonymousUsers" in str(c.get("PermissionGroups", ""))
            ]
            if smtp_disabled and not anon_connectors:
                status, severity = "pass", Severity.pass_
                desc = "SMTP AUTH disabled globally; no anonymous receive connectors detected."
            elif smtp_disabled:
                status, severity = "warn", Severity.warning
                desc = f"SMTP AUTH disabled but {len(anon_connectors)} anonymous connector(s) found — review."
            else:
                status, severity = "fail", Severity.critical
                desc = "SMTP AUTH enabled globally — legacy authenticated SMTP allowed."
        except Exception as e:
            status, severity = "warn", Severity.warning
            desc = f"Unable to evaluate direct send configuration: {e}"

        self._add(FindingResult(
            check_id="direct_send_restricted",
            name="Direct Send / SMTP AUTH Configuration",
            category="Direct Send",
            severity=severity, status=status, description=desc,
            current_value="See description",
            expected_value="SmtpClientAuthenticationDisabled: True; no anonymous connectors",
            remediation=[
                "Inventory all devices using direct send (printers, scanners, LOB apps).",
                "Migrate anonymous senders to authenticated SMTP or Graph API.",
                "Disable SMTP AUTH globally: EAC → Settings → Mail flow → Turn off SMTP AUTH.",
                "Create inbound connectors restricted to known internal IP ranges.",
                "Monitor mail flow logs for anomalies.",
            ],
            reference_url="https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/how-to-set-up-a-multifunction-device-or-application-to-send-email-using-microsoft-365-or-office-365",
            benchmark="Microsoft Exchange Online Best Practices",
        ), "direct_send_restricted")

    async def _check_teams_guest_access(self):
        """CIS 8.1.1 — Teams guest access should be disabled or tightly controlled."""
        try:
            settings = await self.graph.get_teams_guest_settings()
            values   = {v["name"]: v["value"] for v in settings.get("values", [])}
            # AllowGuestsToAccessGroups drives Teams guest join
            guests_allowed = values.get("AllowGuestsToAccessGroups", "true").lower()
            if guests_allowed == "false":
                status, severity = "pass", Severity.pass_
                desc = "Guest access to Microsoft 365 Groups (Teams) is disabled."
            else:
                status, severity = "warn", Severity.warning
                desc = (
                    "Guest access to Teams is enabled. Guests can read channel messages, "
                    "files, and calendar events. Restrict or disable unless business-justified."
                )
        except Exception as e:
            status, severity = "warn", Severity.warning
            desc = f"Unable to retrieve Teams guest settings: {e}"

        self._add(FindingResult(
            check_id="teams_guest_access",
            name="Teams Guest Access",
            category="Teams & Collaboration",
            severity=severity, status=status, description=desc,
            current_value="See description",
            expected_value="AllowGuestsToAccessGroups: False",
            remediation=[
                "Microsoft 365 Admin Centre → Settings → Org settings → Microsoft Teams.",
                "Under 'Guest access', toggle 'Allow guest access in Teams' to Off.",
                "Or via PowerShell: Set-CsTeamsClientConfiguration -AllowGuestUser $false",
                "Review existing guest accounts: Azure AD → Users → Filter by 'Guest'.",
            ],
            reference_url="https://learn.microsoft.com/en-us/microsoftteams/set-up-guests",
            benchmark="CIS Microsoft 365 Foundations Benchmark v4.0.0 — Control 8.1.1",
        ), "teams_guest_access")

    async def _check_teams_external_access(self):
        """CIS 8.2.1 — Teams external federation should restrict unmanaged domains."""
        try:
            fed = await self.graph.get_teams_federation_settings()
            # allowAllUsersToJoinExternalMeetings / isExternalAccessEnabled differ by tenant
            # Heuristic: if the policy object is empty or allows all, flag as warning
            if not fed or fed.get("allowExternalIdp", True):
                status, severity = "warn", Severity.warning
                desc = (
                    "Teams external access (federation) appears open to all external domains. "
                    "This allows any Teams or Skype for Business user to initiate contact — "
                    "a recognised phishing and social-engineering vector."
                )
            else:
                status, severity = "pass", Severity.pass_
                desc = "Teams external access is restricted to specific allowed domains."
        except Exception as e:
            status, severity = "warn", Severity.warning
            desc = f"Unable to retrieve Teams federation settings: {e}"

        self._add(FindingResult(
            check_id="teams_external_access",
            name="Teams External Access (Federation)",
            category="Teams & Collaboration",
            severity=severity, status=status, description=desc,
            current_value="See description",
            expected_value="External access limited to allow-listed trusted domains only",
            remediation=[
                "Teams Admin Centre → Users → External access.",
                "Change 'Teams and Skype for Business users in external orgs' to 'Allow only specific external domains'.",
                "Add only explicitly trusted partner domains to the allow list.",
                "Block all Skype external access unless required.",
            ],
            reference_url="https://learn.microsoft.com/en-us/microsoftteams/manage-external-access",
            benchmark="CIS Microsoft 365 Foundations Benchmark v4.0.0 — Control 8.2.1",
        ), "teams_external_access")

    async def _check_sharepoint_external_sharing(self):
        """CIS 7.2.1 / 7.2.2 — SharePoint external sharing level."""
        try:
            sp = await self.graph.get_sharepoint_settings()
            # sharingCapability: Disabled | ExistingExternalUserSharingOnly | ExternalUserSharingOnly | ExternalUserAndGuestSharing
            capability = sp.get("sharingCapability", "")
            if capability == "Disabled":
                status, severity = "pass", Severity.pass_
                desc = "External sharing is fully disabled for SharePoint and OneDrive."
            elif capability in ("ExistingExternalUserSharingOnly",):
                status, severity = "warn", Severity.warning
                desc = (
                    "SharePoint external sharing is limited to existing external users only. "
                    "This is an acceptable intermediate state — consider disabling entirely."
                )
            elif capability in ("ExternalUserSharingOnly",):
                status, severity = "warn", Severity.warning
                desc = (
                    "SharePoint external sharing allows authenticated external users. "
                    "Ensure all shared links require sign-in and are scoped to specific people."
                )
            elif capability in ("ExternalUserAndGuestSharing", ""):
                status, severity = "fail", Severity.critical
                desc = (
                    "SharePoint external sharing allows 'Anyone' links — files can be shared "
                    "with unauthenticated users via link. This is a significant data-loss risk."
                )
            else:
                status, severity = "warn", Severity.warning
                desc = f"SharePoint sharing level is '{capability}' — review against policy."
        except Exception as e:
            status, severity = "warn", Severity.warning
            desc = f"Unable to retrieve SharePoint sharing settings: {e}"

        self._add(FindingResult(
            check_id="sharepoint_external_sharing",
            name="SharePoint / OneDrive External Sharing",
            category="SharePoint & OneDrive",
            severity=severity, status=status, description=desc,
            current_value=locals().get("capability", "Unknown"),
            expected_value="Disabled or ExistingExternalUserSharingOnly",
            remediation=[
                "SharePoint Admin Centre → Policies → Sharing.",
                "Set SharePoint external sharing to 'Only people in your organization' (Disabled).",
                "If external sharing is required, set to 'New and existing guests' (require sign-in).",
                "Disable 'Anyone' links organisation-wide.",
                "Enable expiry on guest access links (recommended: 30 days).",
                "CIS Control 7.2.9: Ensure 'Anyone' links are disabled.",
            ],
            reference_url="https://learn.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off",
            benchmark="CIS Microsoft 365 Foundations Benchmark v4.0.0 — Controls 7.2.1, 7.2.2, 7.2.9",
        ), "sharepoint_external_sharing")

        # ── Orchestrator ──────────────────────────────────────────────────────────

    async def _run_domain_checks(self, domain: str, platform: str) -> None:
        """Run all domain-scoped checks for a single domain in parallel."""

        if platform == "Google Workspace":
            # GWS-only: skip M365 MX gateway/bypass checks entirely
            # Run lookalike detection in parallel with GWS checker
            gws_checker = GoogleWorkspaceChecker(
                domain=domain,
                access_token=self.gws_access_token,
            )
            lookalike_task = self._check_lookalike_domains(domain)
            gws_task       = gws_checker.run()

            results = await asyncio.gather(lookalike_task, gws_task, return_exceptions=True)
            gws_result = results[1] if not isinstance(results[1], Exception) else {"findings": []}

            for f_dict in gws_result.get("findings", []):
                try:
                    f_dict.setdefault("domain", domain)
                    fr = FindingResult(**f_dict)
                    self.findings.append(fr)
                except Exception:
                    pass
        else:
            # M365: run all DNS + bypass + lookalike checks in parallel
            domain_coros = [
                self._check_mx_bypass(domain),
                self._check_spf(domain),
                self._check_dkim(domain),
                self._check_dmarc(domain),
                self._check_lookalike_domains(domain),
            ]
            await asyncio.gather(*domain_coros, return_exceptions=True)

    async def run(self) -> Dict:
        # ── Step 1: Deduplicate domains, filter blanks ────────────────────────
        seen = set()
        domains: List[str] = []
        for d in self.domains:
            d = (d or "").strip().lower()
            if d and d not in seen:
                seen.add(d)
                domains.append(d)
        if not domains:
            domains = [self.domain]

        # ── Step 2: Platform detection ────────────────────────────────────────
        # Use explicit flags if set; otherwise auto-detect from MX
        if self._has_m365 and self._has_gws:
            platform = "Microsoft 365 + Google Workspace"
            self._is_google_workspace = False  # run M365 tenant checks too
        elif self._has_gws and not self._has_m365:
            self._is_google_workspace = True
            platform = "Google Workspace"
        elif self._has_m365 and not self._has_gws:
            self._is_google_workspace = False
            platform = "Microsoft 365"
        else:
            # Fallback: auto-detect from MX
            self._is_google_workspace = await is_google_workspace_domain(domains[0])
            platform = "Google Workspace" if self._is_google_workspace else "Microsoft 365"

        # ── Step 3: Run domain checks for all domains in parallel ─────────────
        # For dual-platform, run both M365 and GWS domain checks
        if self._has_m365 and self._has_gws:
            m365_tasks = [self._run_domain_checks(d, "Microsoft 365") for d in domains]
            gws_tasks  = [self._run_domain_checks(d, "Google Workspace") for d in domains]
            await asyncio.gather(*(m365_tasks + gws_tasks), return_exceptions=True)
        else:
            domain_tasks = [self._run_domain_checks(d, platform) for d in domains]
            await asyncio.gather(*domain_tasks, return_exceptions=True)

        # ── Step 4: Run tenant-wide checks ────────────────────────────────────
        if self._has_m365:
            tenant_checks = [
                self._check_mfa_admins(),
                self._check_legacy_auth(),
                self._check_security_defaults(),
                self._check_antiphishing(),
                self._check_antispam_outbound(),
                self._check_safe_links(),
                self._check_safe_attachments(),
                self._check_direct_send(),
                self._check_teams_guest_access(),
                self._check_teams_external_access(),
                self._check_sharepoint_external_sharing(),
            ]
            await asyncio.gather(*tenant_checks, return_exceptions=True)

        # ── Step 5: Score via penalty model ──────────────────────────────────
        # For multi-domain tenants, domain-scoped checks (SPF/DKIM/DMARC etc.)
        # fire once per domain. To keep the 0–100 scale meaningful regardless
        # of domain count, we average each domain's domain-check penalty
        # and add the tenant-wide penalty on top.
        DOMAIN_CHECK_KEYS = {
            "mx_gateway", "mx_bypass_risk", "spf_record",
            "dkim_enabled", "dmarc_policy", "lookalike_domains",
            "gws_mx_routing", "gws_spf_record", "gws_dkim_enabled", "gws_dmarc_policy",
        }

        n = len(domains)
        domain_findings  = [f for f in self.findings if f.domain]
        tenant_findings  = [f for f in self.findings if not f.domain]

        # Compute per-domain scores and average them
        domain_scores_by_domain: Dict[str, int] = {}
        for d in domains:
            df = [f for f in domain_findings if f.domain == d]
            domain_score, _ = _compute_score(df, CHECK_WEIGHTS)
            domain_scores_by_domain[d] = domain_score

        avg_domain_score    = (sum(domain_scores_by_domain.values()) / n) if n else 100
        tenant_score, tenant_breakdown = _compute_score(tenant_findings, CHECK_WEIGHTS)

        # Blend domain and tenant scores weighted by their check counts
        n_domain_checks = len([k for k in CHECK_WEIGHTS if k in {
            "spf_record", "dkim_enabled", "dmarc_policy", "mx_bypass_risk",
            "mx_gateway", "lookalike_domains",
            "gws_mx_routing", "gws_spf_record", "gws_dkim_enabled", "gws_dmarc_policy",
        }])
        n_tenant_checks = len(CHECK_WEIGHTS) - n_domain_checks
        total_checks = n_domain_checks + n_tenant_checks
        score = round(
            (avg_domain_score * n_domain_checks + tenant_score * n_tenant_checks) / total_checks
        ) if total_checks > 0 else tenant_score

        # Build breakdown: worst domain + tenant checks
        penalty_breakdown = tenant_breakdown
        if domain_scores_by_domain:
            worst_domain = min(domain_scores_by_domain, key=domain_scores_by_domain.get)
            worst_df     = [f for f in domain_findings if f.domain == worst_domain]
            _, worst_bd  = _compute_score(worst_df, CHECK_WEIGHTS)
            penalty_breakdown = worst_bd + tenant_breakdown

        return {
            "score":            score,
            "grade":            _grade(score),
            "platform":         platform,
            "domains_scanned":  domains,
            "penalty_breakdown": penalty_breakdown,
            "findings":         [f.dict() for f in self.findings],
        }

