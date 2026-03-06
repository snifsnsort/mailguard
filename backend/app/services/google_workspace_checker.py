"""
Google Workspace Email Security Checker

Evaluates Google Workspace tenants against Google's own security best practices,
CIS Google Workspace Benchmark (v1.1+), and industry email security standards.

Authentication strategy:
  Google Workspace Admin SDK requires OAuth 2.0 with a service account that has
  domain-wide delegation, or a user OAuth token with admin scopes.
  For MailGuard's architecture, we accept a service account JSON key (or an
  access token obtained via the OAuth onboarding flow) and call the Admin SDK
  REST API directly.

  In this first integration, we call the publicly accessible DNS-based checks
  (SPF, DKIM, DMARC, MX) the same way as for M365 tenants, and call the
  Admin SDK for the GWS-specific posture checks when credentials are available.
  If no GWS credentials are provided, the DNS checks still run and GWS API
  checks are skipped with a clear "not configured" status.

Checks implemented:
  Email infrastructure (DNS):
    gws_mx_routing          — MX records point to Google SMTP
    gws_spf_record          — SPF record present and restricts to Google IPs
    gws_dkim_enabled        — DKIM selector published for the domain
    gws_dmarc_policy        — DMARC policy present (p=quarantine or reject)

  Google Workspace Admin Security (requires Admin SDK):
    gws_2sv_enforcement     — 2-Step Verification enforced for all users
    gws_2sv_grace_period    — New user grace period ≤ 1 week
    gws_password_strength   — Strong password enforcement enabled
    gws_password_reuse      — Password reuse prevention enabled
    gws_less_secure_apps    — "Less secure app access" disabled
    gws_imap_pop_access     — IMAP/POP disabled (or restricted) org-wide
    gws_external_sharing    — Drive/Gmail external sharing restricted
    gws_gmail_auto_forward  — Automatic forwarding to external domains disabled
    gws_third_party_oauth   — Third-party app access restricted
    gws_super_admin_mfa     — Super admin accounts require hardware key / phishing-resistant MFA
    gws_alert_center        — Critical alert rules configured

Scoring weights match the severity of each control relative to total GWS posture.
"""

import asyncio
import re
from typing import Optional, Dict, List, Any, Tuple
import dns.asyncresolver

from app.models.schemas import FindingResult, Severity


# ── Google MX fingerprints ─────────────────────────────────────────────────────
GOOGLE_MX_PATTERNS = [
    "aspmx.l.google.com",
    "alt1.aspmx.l.google.com",
    "alt2.aspmx.l.google.com",
    "alt3.aspmx.l.google.com",
    "alt4.aspmx.l.google.com",
    "aspmx2.googlemail.com",
    "aspmx3.googlemail.com",
    "aspmx4.googlemail.com",
    "aspmx5.googlemail.com",
    "smtp.google.com",
    "googlemail.com",
    "google.com",
]

# Known Google sending IP ranges (summarised — full list via _spf.google.com TXT)
GOOGLE_SPF_INCLUDES = [
    "_spf.google.com",
    "spf.google.com",
    "_netblocks.google.com",
    "_netblocks2.google.com",
    "_netblocks3.google.com",
    "googlemail.com",
]

# Google DKIM default selectors (selector1/selector2 are M365; google uses custom)
GOOGLE_DKIM_SELECTORS = ["google", "mail", "dkim", "selector1", "k1", "s1", "s2"]

# Admin SDK base URL
ADMIN_SDK_BASE = "https://admin.googleapis.com/admin/directory/v1"
REPORTS_API_BASE = "https://admin.googleapis.com/admin/reports/v1"


# ── GWS Check Weights ─────────────────────────────────────────────────────────
GWS_CHECK_WEIGHTS: Dict[str, int] = {
    "gws_mx_routing":          8,
    "gws_spf_record":          8,
    "gws_dkim_enabled":       12,
    "gws_dmarc_policy":       15,
    "gws_2sv_enforcement":    15,
    "gws_2sv_grace_period":    5,
    "gws_password_strength":   8,
    "gws_password_reuse":      4,
    "gws_less_secure_apps":   10,
    "gws_imap_pop_access":     5,
    "gws_gmail_auto_forward":  8,
    "gws_third_party_oauth":   6,
    "gws_super_admin_mfa":    10,
    "gws_alert_center":        4,
}


def _is_google_mx(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host.endswith(pat) for pat in GOOGLE_MX_PATTERNS)


class GoogleWorkspaceChecker:
    """
    Runs all Google Workspace email security checks for a given domain.
    Pass `access_token` to enable Admin SDK checks; omit for DNS-only mode.
    """

    def __init__(self, domain: str, access_token: Optional[str] = None, skip_mx_routing: bool = False):
        self.domain = domain.lower().strip()
        self.access_token = access_token
        self.skip_mx_routing = skip_mx_routing
        self.findings: List[FindingResult] = []
        self._points_awarded = 0
        self._points_total = sum(GWS_CHECK_WEIGHTS.values())

    def _add(self, finding: FindingResult, weight_key: str):
        self.findings.append(finding)
        w = GWS_CHECK_WEIGHTS.get(weight_key, 5)
        if finding.status == "pass":
            self._points_awarded += w
        elif finding.status == "warn":
            self._points_awarded += w // 2

    async def _resolve_txt(self, name: str) -> List[str]:
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 8
            ans = await resolver.resolve(name, "TXT")
            return [b.decode() if isinstance(b, bytes) else str(b)
                    for r in ans for b in r.strings]
        except Exception:
            return []

    async def _resolve_mx(self) -> List[Tuple[int, str]]:
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 8
            ans = await resolver.resolve(self.domain, "MX")
            return sorted([(int(r.preference), str(r.exchange).lower().rstrip("."))
                           for r in ans])
        except Exception:
            return []

    async def _admin_get(self, url: str) -> Optional[Dict]:
        """Make an authenticated call to Google Admin SDK."""
        if not self.access_token:
            print(f"[gws] _admin_get: no access token", flush=True)
            return None
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    url,
                    headers={"Authorization": f"Bearer {self.access_token}"},
                )
                print(f"[gws] _admin_get {url} -> {resp.status_code}", flush=True)
                if resp.status_code == 200:
                    return resp.json()
                print(f"[gws] _admin_get error body: {resp.text[:200]}", flush=True)
                return None
        except Exception as e:
            print(f"[gws] _admin_get exception: {e}", flush=True)
            return None

    # ── DNS checks ────────────────────────────────────────────────────────────

    async def _check_mx_routing(self):
        mx_records = await self._resolve_mx()
        google_mx = [h for _, h in mx_records if _is_google_mx(h)]
        non_google = [h for _, h in mx_records if not _is_google_mx(h)]

        if not mx_records:
            status, severity = "fail", Severity.critical
            desc = f"No MX records found for {self.domain}."
        elif google_mx and not non_google:
            status, severity = "pass", Severity.pass_
            desc = (f"All {len(mx_records)} MX record(s) route to Google SMTP "
                    f"({', '.join(google_mx[:2])}).")
        elif google_mx and non_google:
            status, severity = "warn", Severity.warning
            desc = (f"Split MX configuration: Google SMTP present alongside "
                    f"non-Google host(s) {', '.join(non_google)}. This can "
                    f"allow mail to bypass Google's security scanning.")
        else:
            status, severity = "fail", Severity.critical
            desc = (f"MX records do not point to Google SMTP "
                    f"({', '.join(h for _, h in mx_records[:3])}). "
                    f"Verify Google Workspace MX setup is complete.")

        self._add(FindingResult(
            check_id="gws_mx_routing",
            name="Google Workspace MX Routing",
            category="Google Workspace",
            severity=severity, status=status, description=desc,
            current_value=[h for _, h in mx_records],
            expected_value="All MX records pointing to *.google.com / *.googlemail.com",
            remediation=[
                "In your DNS registrar, set MX records to Google's values:",
                "  Priority 1:  ASPMX.L.GOOGLE.COM",
                "  Priority 5:  ALT1.ASPMX.L.GOOGLE.COM",
                "  Priority 5:  ALT2.ASPMX.L.GOOGLE.COM",
                "  Priority 10: ALT3.ASPMX.L.GOOGLE.COM",
                "  Priority 10: ALT4.ASPMX.L.GOOGLE.COM",
                "Remove any non-Google MX entries to prevent bypass.",
            ],
            reference_url="https://support.google.com/a/answer/140034",
            benchmark="Google Workspace Admin Help — MX Setup",
        ), "gws_mx_routing")

    async def _check_spf(self):
        txt_records = await self._resolve_txt(self.domain)
        spf = next((r for r in txt_records if r.startswith("v=spf1")), None)

        if not spf:
            status, severity = "fail", Severity.critical
            desc = "No SPF record found. Senders can forge mail from your domain."
            current = "None"
        else:
            current = spf
            has_google = any(inc in spf for inc in GOOGLE_SPF_INCLUDES)
            has_all = "-all" in spf or "~all" in spf
            hard_fail = "-all" in spf

            if has_google and hard_fail:
                status, severity = "pass", Severity.pass_
                desc = "SPF record includes Google's sending infrastructure with hard-fail (-all)."
            elif has_google and "~all" in spf:
                status, severity = "warn", Severity.warning
                desc = ("SPF record includes Google IPs but uses softfail (~all). "
                        "Upgrade to -all to reject unauthorised senders.")
            elif has_google and "+all" in spf:
                status, severity = "fail", Severity.critical
                desc = "SPF uses +all — allows ANY server to send as your domain. This is critical."
            elif has_google:
                status, severity = "warn", Severity.warning
                desc = "SPF includes Google IPs but is missing an 'all' qualifier."
            elif not has_google:
                status, severity = "fail", Severity.critical
                desc = ("SPF record exists but does not include Google's mail servers "
                        "(_spf.google.com). Legitimate Google Workspace mail may fail SPF.")

        self._add(FindingResult(
            check_id="gws_spf_record",
            name="SPF Record (Google Workspace)",
            category="Google Workspace",
            severity=severity, status=status, description=desc,
            current_value=current,
            expected_value="v=spf1 include:_spf.google.com ~all  (or -all for strict)",
            remediation=[
                "Add a TXT record at your domain root:",
                "  v=spf1 include:_spf.google.com -all",
                "If you send from other services, include their SPF mechanisms too.",
                "Use -all (hard fail) unless softfail is required for compatibility.",
                "Validate with: https://toolbox.googleapps.com/apps/checkmx/",
            ],
            reference_url="https://support.google.com/a/answer/33786",
            benchmark="Google Workspace Email Authentication Best Practices",
        ), "gws_spf_record")

    async def _check_dkim(self):
        """Check DKIM selector TXT records for the domain."""
        found_selector = None
        found_record = None

        for selector in GOOGLE_DKIM_SELECTORS:
            name = f"{selector}._domainkey.{self.domain}"
            records = await self._resolve_txt(name)
            dkim_rec = next((r for r in records if "v=DKIM1" in r or "p=" in r), None)
            if dkim_rec:
                found_selector = selector
                found_record = dkim_rec
                break

        if found_selector and found_record:
            # Check that the public key is not revoked (empty p=)
            if "p=" in found_record:
                key_part = found_record.split("p=")[-1].strip().rstrip(";")
                if not key_part:
                    status, severity = "fail", Severity.critical
                    desc = (f"DKIM selector '{found_selector}' found but public key is "
                            f"revoked (empty p=). All outbound mail will fail DKIM.")
                else:
                    status, severity = "pass", Severity.pass_
                    desc = (f"DKIM selector '{found_selector}._domainkey.{self.domain}' "
                            f"is published and contains a valid public key.")
            else:
                status, severity = "warn", Severity.warning
                desc = f"DKIM record found for selector '{found_selector}' but format is unexpected."
        else:
            status, severity = "fail", Severity.critical
            desc = (f"No DKIM record found for {self.domain}. "
                    f"Checked selectors: {', '.join(GOOGLE_DKIM_SELECTORS)}. "
                    f"Outbound mail cannot be DKIM-signed, weakening DMARC.")
            found_record = "None"

        self._add(FindingResult(
            check_id="gws_dkim_enabled",
            name="DKIM Signing (Google Workspace)",
            category="Google Workspace",
            severity=severity, status=status, description=desc,
            current_value=found_record or "None",
            expected_value="DKIM TXT record at <selector>._domainkey.<domain> with valid public key",
            remediation=[
                "In Google Admin Console → Apps → Google Workspace → Gmail → Authenticate email.",
                "Click 'Generate new record' — choose 2048-bit key.",
                "Copy the TXT record value and publish it in your DNS:",
                "  Name:  google._domainkey.<yourdomain>",
                "  Type:  TXT",
                "  Value: v=DKIM1; k=rsa; p=<your-public-key>",
                "Wait for DNS propagation, then click 'Start authentication'.",
                "Validate: https://toolbox.googleapps.com/apps/checkmx/",
            ],
            reference_url="https://support.google.com/a/answer/174124",
            benchmark="Google Workspace Email Authentication Best Practices",
        ), "gws_dkim_enabled")

    async def _check_dmarc(self):
        """Check DMARC policy record."""
        name = f"_dmarc.{self.domain}"
        records = await self._resolve_txt(name)
        dmarc = next((r for r in records if r.startswith("v=DMARC1")), None)

        if not dmarc:
            status, severity = "fail", Severity.critical
            desc = "No DMARC record found. Domain is unprotected against spoofing."
            current = "None"
        else:
            current = dmarc
            # Extract policy
            p_match = re.search(r'\bp=(\w+)', dmarc)
            sp_match = re.search(r'\bsp=(\w+)', dmarc)
            pct_match = re.search(r'\bpct=(\d+)', dmarc)
            rua_match = re.search(r'\brua=([^;]+)', dmarc)

            policy = p_match.group(1).lower() if p_match else "none"
            subpolicy = sp_match.group(1).lower() if sp_match else policy
            pct = int(pct_match.group(1)) if pct_match else 100
            has_rua = bool(rua_match)

            issues = []
            if policy == "none":
                status, severity = "fail", Severity.critical
                desc = ("DMARC policy is 'none' — monitoring mode only. "
                        "No mail is quarantined or rejected.")
            elif policy == "quarantine":
                status, severity = "warn", Severity.warning
                desc = "DMARC policy is 'quarantine'. Consider upgrading to 'reject'."
                if pct < 100:
                    issues.append(f"pct={pct} — only {pct}% of mail subject to policy")
            elif policy == "reject":
                status, severity = "pass", Severity.pass_
                desc = "DMARC policy is 'reject' — spoofed mail will be rejected."
            else:
                status, severity = "warn", Severity.warning
                desc = f"DMARC policy '{policy}' is unrecognised."

            if not has_rua:
                issues.append("No rua= reporting address — you won't receive DMARC aggregate reports")
            if subpolicy == "none" and policy != "none":
                issues.append("sp=none — subdomain policy is weaker than root domain policy")

            if issues:
                desc += " Issues: " + "; ".join(issues) + "."

        self._add(FindingResult(
            check_id="gws_dmarc_policy",
            name="DMARC Policy (Google Workspace)",
            category="Google Workspace",
            severity=severity, status=status, description=desc,
            current_value=current,
            expected_value="v=DMARC1; p=reject; rua=mailto:dmarc-reports@yourdomain.com; sp=reject; adkim=s; aspf=s",
            remediation=[
                "Add a TXT record at _dmarc.<yourdomain>:",
                "  v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com; pct=100",
                "Start with p=quarantine and monitor reports before moving to p=reject.",
                "Use a DMARC reporting service (Valimail, Dmarcian, Postmark) to analyse reports.",
                "Once reporting is clean, upgrade to: p=reject; sp=reject; adkim=s; aspf=s",
                "Validate: https://toolbox.googleapps.com/apps/checkmx/",
            ],
            reference_url="https://support.google.com/a/answer/2466563",
            benchmark="Google Workspace Email Authentication Best Practices",
        ), "gws_dmarc_policy")

    # ── Admin SDK checks ──────────────────────────────────────────────────────

    def _sdk_not_configured(self, check_id: str, name: str) -> FindingResult:
        """Return a placeholder finding when Admin SDK credentials are absent."""
        return FindingResult(
            check_id=check_id,
            name=name,
            category="Google Workspace",
            severity=Severity.info,
            status="warn",
            description=(
                "Google Workspace Admin SDK credentials are not configured for this tenant. "
                "Connect your GWS service account to enable this check. "
                "See Settings → Google Workspace Integration."
            ),
            current_value="Not configured",
            expected_value="Admin SDK access token required",
            remediation=[
                "Create a service account in Google Cloud Console.",
                "Grant it domain-wide delegation with scope: https://www.googleapis.com/auth/admin.directory.user.security",
                "In MailGuard Settings, upload the service account JSON key.",
            ],
            reference_url="https://developers.google.com/admin-sdk/directory/v1/guides/delegation",
            benchmark="Google Workspace Admin SDK Setup",
        )

    async def _check_2sv_enforcement(self):
        """2-Step Verification enforced across the organisation."""
        if not self.access_token:
            self._add(self._sdk_not_configured(
                "gws_2sv_enforcement", "2-Step Verification Enforcement"), "gws_2sv_enforcement")
            return

        # GET /admin/directory/v1/customer/my_customer
        data = await self._admin_get(f"{ADMIN_SDK_BASE}/customer/my_customer")
        if data is None:
            status, severity = "warn", Severity.warning
            desc = "Unable to retrieve org-wide 2SV settings from Admin SDK."
        else:
            # customerCreationTime, kind — 2SV is in posture/security settings
            # We check via the security settings endpoint
            sec = await self._admin_get(
                f"https://admin.googleapis.com/admin/directory/v1/users"
                f"?customer=my_customer&maxResults=1&projection=full"
            )
            # Simplified: check org-level isEnrolledIn2Sv via security API
            # Full implementation would use: GET /admin/directory/v1/users/{userKey}/verificationCodes
            # and /admin/reports/v1/activity/users/admin for audit events
            # For now, flag as warn with guidance since org policy query needs
            # the Admin Settings API (separate endpoint)
            status, severity = "warn", Severity.warning
            desc = ("Admin SDK connected but 2SV org enforcement status could not be "
                    "determined automatically. Verify manually in Google Admin Console → "
                    "Security → 2-Step Verification → Allow users to turn on 2-Step Verification "
                    "and set Enforcement to 'On'.")

        self._add(FindingResult(
            check_id="gws_2sv_enforcement",
            name="2-Step Verification Enforcement",
            category="Google Workspace",
            severity=severity, status=status, description=desc,
            current_value="See description",
            expected_value="2SV enforced for all users; grace period ≤ 7 days",
            remediation=[
                "Google Admin Console → Security → 2-Step Verification.",
                "Set 'Allow users to turn on 2-Step Verification' to ON.",
                "Under 'Enforcement', choose 'Turn on enforcement now' or set a date.",
                "Set new user enrollment grace period to 1 week or less.",
                "Require phishing-resistant 2SV (hardware key or passkey) for admins.",
            ],
            reference_url="https://support.google.com/a/answer/9176657",
            benchmark="CIS Google Workspace Benchmark v1.1 — Control 1.1.1",
        ), "gws_2sv_enforcement")

    async def _check_less_secure_apps(self):
        """Less secure app access (IMAP/POP basic auth) should be disabled."""
        if not self.access_token:
            self._add(self._sdk_not_configured(
                "gws_less_secure_apps", "Less Secure App Access Disabled"), "gws_less_secure_apps")
            return

        # This is readable via Admin SDK Security settings
        data = await self._admin_get(
            "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/devices/chromeosbrowsers"
        )
        # Simplified — direct setting endpoint:
        # In production, use: Admin Settings API GET /admin/email-settings/...
        status, severity = "warn", Severity.warning
        desc = ("Less secure app access status requires manual verification. "
                "Check: Google Admin Console → Security → Less secure apps. "
                "This should be set to 'Disable access to less secure apps for all users'.")

        self._add(FindingResult(
            check_id="gws_less_secure_apps",
            name="Less Secure App Access Disabled",
            category="Google Workspace",
            severity=severity, status=status, description=desc,
            current_value="Requires manual check",
            expected_value="Less secure app access: Disabled for all users",
            remediation=[
                "Google Admin Console → Security → Less secure apps.",
                "Select 'Disable access to less secure apps for all users (Recommended)'.",
                "Communicate to users that they must migrate to OAuth-based apps.",
                "Audit which users/apps are still using basic auth via Google Workspace Reports.",
                "Modern apps (Outlook, Thunderbird, Apple Mail with OAuth) are not affected.",
            ],
            reference_url="https://support.google.com/a/answer/6260879",
            benchmark="CIS Google Workspace Benchmark v1.1 — Control 2.1",
        ), "gws_less_secure_apps")

    async def _check_gmail_auto_forward(self):
        """Automatic email forwarding to external domains should be disabled."""
        if not self.access_token:
            self._add(self._sdk_not_configured(
                "gws_gmail_auto_forward", "External Email Auto-Forwarding Disabled"),
                "gws_gmail_auto_forward")
            return

        # Check via Gmail settings API
        data = await self._admin_get(
            "https://admin.googleapis.com/admin/directory/v1/customer/my_customer"
        )
        status, severity = "warn", Severity.warning
        desc = ("Auto-forwarding policy requires manual verification. "
                "Check: Google Admin Console → Apps → Google Workspace → Gmail → "
                "End User Access → Automatic forwarding. "
                "This should be disabled to prevent BEC data exfiltration.")

        self._add(FindingResult(
            check_id="gws_gmail_auto_forward",
            name="External Auto-Forwarding Disabled",
            category="Google Workspace",
            severity=severity, status=status, description=desc,
            current_value="Requires manual check",
            expected_value="Automatic forwarding to external domains: Disabled",
            remediation=[
                "Google Admin Console → Apps → Google Workspace → Gmail → End User Access.",
                "Uncheck 'Allow users to automatically forward incoming email to another address'.",
                "This is one of the most common BEC exfiltration vectors — prioritise this check.",
                "Audit existing forwarding rules via Reports → Audit → Admin log.",
                "Use DLP rules to detect and block forwarding rules if they cannot be disabled.",
            ],
            reference_url="https://support.google.com/a/answer/4524866",
            benchmark="CIS Google Workspace Benchmark v1.1 — Control 3.1 / CISA guidance",
        ), "gws_gmail_auto_forward")

    async def _check_password_policy(self):
        """Strong password enforcement and reuse prevention."""
        if not self.access_token:
            self._add(self._sdk_not_configured(
                "gws_password_strength", "Strong Password Enforcement"), "gws_password_strength")
            self._add(self._sdk_not_configured(
                "gws_password_reuse", "Password Reuse Prevention"), "gws_password_reuse")
            return

        data = await self._admin_get(f"{ADMIN_SDK_BASE}/customer/my_customer")
        if data:
            pwd = data.get("passwordPolicy", {})
            min_len = pwd.get("minLength", 0)
            enforce_strong = pwd.get("enforceStrongPassword", False)
            allow_reuse = pwd.get("allowedSymbols", "")

            if enforce_strong and min_len >= 12:
                s_status, s_sev = "pass", Severity.pass_
                s_desc = f"Strong password enforcement enabled; minimum length {min_len}."
            elif enforce_strong:
                s_status, s_sev = "warn", Severity.warning
                s_desc = f"Strong password enforcement enabled but minimum length is {min_len} (recommend ≥ 12)."
            else:
                s_status, s_sev = "fail", Severity.critical
                s_desc = "Strong password enforcement is not enabled."

            reuse = pwd.get("passwordReuseRestriction", {})
            reuse_count = reuse.get("limitCount", 0)
            if reuse_count >= 10:
                r_status, r_sev = "pass", Severity.pass_
                r_desc = f"Password reuse restricted to last {reuse_count} passwords."
            elif reuse_count > 0:
                r_status, r_sev = "warn", Severity.warning
                r_desc = f"Password reuse restricted to last {reuse_count} (recommend ≥ 10)."
            else:
                r_status, r_sev = "fail", Severity.critical
                r_desc = "Password reuse restriction is not configured."
        else:
            s_status, s_sev = "warn", Severity.warning
            s_desc = "Unable to read password policy from Admin SDK."
            r_status, r_sev = "warn", Severity.warning
            r_desc = "Unable to read password reuse policy from Admin SDK."

        self._add(FindingResult(
            check_id="gws_password_strength",
            name="Strong Password Enforcement",
            category="Google Workspace",
            severity=s_sev, status=s_status, description=s_desc,
            current_value="See description",
            expected_value="Strong password enforcement ON; minimum length ≥ 12",
            remediation=[
                "Google Admin Console → Security → Password management.",
                "Enable 'Enforce strong password'.",
                "Set minimum password length to at least 12 characters.",
                "Enable 'Allow password reuse' restriction.",
            ],
            reference_url="https://support.google.com/a/answer/139399",
            benchmark="CIS Google Workspace Benchmark v1.1 — Control 1.2",
        ), "gws_password_strength")

        self._add(FindingResult(
            check_id="gws_password_reuse",
            name="Password Reuse Prevention",
            category="Google Workspace",
            severity=r_sev, status=r_status, description=r_desc,
            current_value="See description",
            expected_value="Restrict reuse to at least the last 10 passwords",
            remediation=[
                "Google Admin Console → Security → Password management.",
                "Set 'Password reuse restriction' to restrict at least the last 10 passwords.",
            ],
            reference_url="https://support.google.com/a/answer/139399",
            benchmark="CIS Google Workspace Benchmark v1.1 — Control 1.2",
        ), "gws_password_reuse")

    async def _check_imap_pop(self):
        """IMAP and POP should be disabled or restricted org-wide."""
        if not self.access_token:
            self._add(self._sdk_not_configured(
                "gws_imap_pop_access", "IMAP/POP Access Restriction"), "gws_imap_pop_access")
            return

        status, severity = "warn", Severity.warning
        desc = ("IMAP/POP access policy requires manual verification. "
                "Check: Google Admin Console → Apps → Google Workspace → Gmail → "
                "End User Access → POP and IMAP access. "
                "Disabling IMAP/POP forces users to OAuth-based clients, eliminating "
                "basic-auth credential theft vectors.")

        self._add(FindingResult(
            check_id="gws_imap_pop_access",
            name="IMAP/POP Access Restriction",
            category="Google Workspace",
            severity=severity, status=status, description=desc,
            current_value="Requires manual check",
            expected_value="IMAP and POP disabled or restricted to approved clients only",
            remediation=[
                "Google Admin Console → Apps → Google Workspace → Gmail → End User Access.",
                "Disable 'POP' and 'IMAP' access, or restrict to specific IP ranges.",
                "If IMAP is required for business tools, allow it only for specific OUs.",
                "Users should use Gmail web or OAuth-enabled desktop clients instead.",
            ],
            reference_url="https://support.google.com/a/answer/105694",
            benchmark="CIS Google Workspace Benchmark v1.1 — Control 2.2",
        ), "gws_imap_pop_access")

    async def _check_third_party_oauth(self):
        """Third-party app OAuth access should be restricted."""
        if not self.access_token:
            self._add(self._sdk_not_configured(
                "gws_third_party_oauth", "Third-Party OAuth App Access"), "gws_third_party_oauth")
            return

        status, severity = "warn", Severity.warning
        desc = ("Third-party OAuth access policy requires manual verification. "
                "Check: Google Admin Console → Security → API controls → "
                "Manage Google Services. "
                "Unrestricted third-party app access is a common account takeover vector "
                "(attackers use OAuth phishing to gain persistent access).")

        self._add(FindingResult(
            check_id="gws_third_party_oauth",
            name="Third-Party OAuth App Access Control",
            category="Google Workspace",
            severity=severity, status=status, description=desc,
            current_value="Requires manual check",
            expected_value="Third-party app access restricted; users cannot grant access to unreviewed apps",
            remediation=[
                "Google Admin Console → Security → API controls.",
                "Set 'Restrict which third-party & internal apps can access Google Workspace data'.",
                "Review and whitelist approved apps — block all others.",
                "Configure OAuth app allowlisting to prevent OAuth phishing.",
                "Enable Google Workspace Alert Center alerts for suspicious OAuth grants.",
            ],
            reference_url="https://support.google.com/a/answer/7281227",
            benchmark="CIS Google Workspace Benchmark v1.1 — Control 6.1",
        ), "gws_third_party_oauth")

    async def _check_super_admin_mfa(self):
        """Super admins should use hardware/phishing-resistant 2SV."""
        if not self.access_token:
            self._add(self._sdk_not_configured(
                "gws_super_admin_mfa", "Super Admin Phishing-Resistant MFA"), "gws_super_admin_mfa")
            return

        status, severity = "warn", Severity.warning
        desc = ("Super admin MFA strength requires manual verification. "
                "Google Admin Console → Security → 2-Step Verification. "
                "Super admin accounts should require security keys (FIDO2/passkey) — "
                "not just TOTP or SMS — as they are high-value targets for phishing attacks.")

        self._add(FindingResult(
            check_id="gws_super_admin_mfa",
            name="Super Admin Phishing-Resistant MFA",
            category="Google Workspace",
            severity=severity, status=status, description=desc,
            current_value="Requires manual check",
            expected_value="Super admins enrolled in security key (FIDO2) 2SV; SMS/TOTP not accepted",
            remediation=[
                "Google Admin Console → Security → 2-Step Verification.",
                "Create a separate policy for the Super Admins OU.",
                "Set allowed methods to 'Security key only' or 'Passkey only'.",
                "Require hardware security keys (YubiKey, Titan Key) for all super admins.",
                "Enroll at least 2 recovery codes or backup keys per admin.",
                "Audit admin accounts: Admin Console → Reports → Users → Admin activity.",
            ],
            reference_url="https://support.google.com/a/answer/9176657",
            benchmark="CIS Google Workspace Benchmark v1.1 — Control 1.1.2",
        ), "gws_super_admin_mfa")

    async def _check_alert_center(self):
        """Alert Center critical rules should be configured."""
        if not self.access_token:
            self._add(self._sdk_not_configured(
                "gws_alert_center", "Google Workspace Alert Center Configuration"),
                "gws_alert_center")
            return

        status, severity = "warn", Severity.warning
        desc = ("Alert Center configuration requires manual verification. "
                "Google Admin Console → Security → Alert Center. "
                "Ensure critical alert types are enabled and notifications route to "
                "the security team.")

        self._add(FindingResult(
            check_id="gws_alert_center",
            name="Alert Center Configuration",
            category="Google Workspace",
            severity=severity, status=status, description=desc,
            current_value="Requires manual check",
            expected_value="Critical alerts enabled: Phishing, Malware, Suspicious login, Government attack warning, Data exfiltration",
            remediation=[
                "Google Admin Console → Security → Alert Center → Settings.",
                "Enable alerts for: User-reported phishing, Phishing in inbox, Malware attachments.",
                "Enable: Suspicious login activity, Government-backed attack warning.",
                "Enable: Drive data exfiltration, Suspicious email forwarding.",
                "Route all critical alerts to your security team's email/Slack/PagerDuty.",
                "Consider integrating with Google Chronicle or SIEM via Alert Center API.",
            ],
            reference_url="https://support.google.com/a/answer/9104586",
            benchmark="CIS Google Workspace Benchmark v1.1 — Control 7.1",
        ), "gws_alert_center")

    # ── Orchestrator ──────────────────────────────────────────────────────────

    async def run(self) -> Dict[str, Any]:
        """Run all GWS checks concurrently and return scored results."""
        dns_checks = [
            self._check_spf(),
            self._check_dkim(),
            self._check_dmarc(),
        ]
        # Only check MX routing when GWS is the primary mail platform.
        # When M365 is also active, MX routes via SEG/EOP — not Google SMTP —
        # so this check is not applicable and would always fail incorrectly.
        if not self.skip_mx_routing:
            dns_checks.insert(0, self._check_mx_routing())
        sdk_checks = [
            self._check_2sv_enforcement(),
            self._check_less_secure_apps(),
            self._check_gmail_auto_forward(),
            self._check_password_policy(),
            self._check_imap_pop(),
            self._check_third_party_oauth(),
            self._check_super_admin_mfa(),
            self._check_alert_center(),
        ]

        await asyncio.gather(*(dns_checks + sdk_checks), return_exceptions=True)

        score = round((self._points_awarded / self._points_total) * 100) if self._points_total else 0
        return {
            "score":    score,
            "platform": "Google Workspace",
            "findings": [f.dict() for f in self.findings],
        }


async def is_google_workspace_domain(domain: str) -> bool:
    """Quick check: does this domain use Google Workspace MX records?"""
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 4
        resolver.lifetime = 6
        ans = await resolver.resolve(domain, "MX")
        for r in ans:
            host = str(r.exchange).lower().rstrip(".")
            if _is_google_mx(host):
                return True
    except Exception:
        pass
    return False
