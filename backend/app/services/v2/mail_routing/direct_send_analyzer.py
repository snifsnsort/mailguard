# direct_send_analyzer.py
#
# DirectSendAnalyzer — task: direct_send_check
#
# Tenant-authenticated. Checks for direct send misconfiguration:
#   - SMTP AUTH global setting (SmtpClientAuthenticationDisabled)
#   - Anonymous receive connectors that allow direct send
#   - Transport rules that should restrict but don't
#   - Lack of IP restriction on anonymous connectors
#
# GWS-only tenants receive a "not_applicable" result.

import uuid
from datetime import datetime, timezone
from typing import List

from app.models.v2.scan_request import ScanRequest
from app.models.v2.scan_result import ScanResult
from app.models.v2.finding import Finding


def _get_tenant_creds(tenant_id: str):
    try:
        from app.core.database import SessionLocal
        from app.models.tenant import Tenant
        from app.core.security import decrypt
        db = SessionLocal()
        try:
            tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
            if not tenant or not tenant.has_m365:
                return None
            return (tenant.tenant_id, tenant.client_id, decrypt(tenant.client_secret))
        finally:
            db.close()
    except Exception:
        return None


class DirectSendAnalyzer:

    def __init__(self, domain: str):
        self.domain = domain

    async def run(self, request: ScanRequest) -> ScanResult:
        t0 = datetime.now(timezone.utc)
        findings: List[Finding] = []

        if not request.tenant_id:
            return self._not_applicable(t0, "No tenant_id in scan request")

        creds = _get_tenant_creds(request.tenant_id)
        if creds is None:
            return self._not_applicable(t0, "Not an M365 tenant or credentials unavailable")

        azure_tenant_id, client_id, client_secret = creds

        try:
            from app.services.exchange_checker import ExchangeChecker
            exo = ExchangeChecker(azure_tenant_id, client_id, client_secret)
        except Exception as e:
            return self._error(t0, str(e))

        # ── Gather data ───────────────────────────────────────────────────────
        try:
            import asyncio
            smtp_cfg_raw, connectors_raw, rules_raw = await asyncio.gather(
                exo.get_smtp_auth_settings(),
                exo.get_receive_connectors(),
                exo.get_transport_rules(),
                return_exceptions=True,
            )
        except Exception as e:
            return self._error(t0, f"Data collection failed: {e}")

        smtp_cfg   = smtp_cfg_raw if isinstance(smtp_cfg_raw, dict) else {}
        connectors = connectors_raw if isinstance(connectors_raw, list) else \
                     ([connectors_raw] if isinstance(connectors_raw, dict) else [])
        rules      = rules_raw if isinstance(rules_raw, list) else \
                     ([rules_raw] if isinstance(rules_raw, dict) else [])

        smtp_disabled = smtp_cfg.get("SmtpClientAuthenticationDisabled", False)

        # ── SMTP AUTH global setting ──────────────────────────────────────────
        if not smtp_disabled:
            findings.append(Finding(
                id=f"direct-send-smtp-auth-enabled-{self.domain}",
                category="direct_send",
                severity="critical",
                title="Legacy SMTP AUTH is globally enabled",
                description=f"SMTP AUTH (legacy authenticated SMTP on port 587) is enabled globally "
                            f"for this organisation. This allows any user with valid credentials to "
                            f"authenticate and send mail from any device or application, bypassing "
                            f"modern Conditional Access policies and MFA. It is a common vector for "
                            f"credential-stuffing attacks and business email compromise.",
                recommended_action="Disable SMTP AUTH globally in Exchange Admin Center → Settings → "
                                   "Mail flow → Turn off SMTP AUTH. Then selectively re-enable it "
                                   "only for specific mailboxes that require it (e.g. printers, scanners) "
                                   "via Set-CASMailbox -SmtpClientAuthenticationDisabled $false. "
                                   "Use OAuth 2.0 or Azure App Passwords for modern applications instead.",
                evidence={
                    "impact": "Credential stuffing via SMTP AUTH bypasses MFA and Conditional Access.",
                    "smtp_auth_disabled_globally": False,
                },
            ))
        else:
            # SMTP AUTH disabled globally — check for anonymous connectors that re-enable direct send
            anon_connectors = [
                c for c in connectors
                if c.get("AnonymousUsers") or
                   "AnonymousUsers" in str(c.get("PermissionGroups", ""))
            ]

            for conn in anon_connectors:
                name       = conn.get("Name", "Unknown")
                remote_ips = conn.get("RemoteIPRanges", []) or []
                bindings   = conn.get("Bindings", []) or []

                if not remote_ips or remote_ips == ["0.0.0.0-255.255.255.255"]:
                    findings.append(Finding(
                        id=f"direct-send-anon-connector-unrestricted-{name.replace(' ', '-')}",
                        category="direct_send",
                        severity="high",
                        title=f"Anonymous receive connector '{name}' has no IP restriction",
                        description=f"Receive connector '{name}' allows anonymous SMTP connections "
                                    f"(direct send) from any IP address. Even though global SMTP AUTH "
                                    f"is disabled, this connector allows any device on the internet "
                                    f"to submit mail without authentication.",
                        recommended_action=f"Restrict '{name}' to only the IP addresses of known "
                                           f"internal devices (printers, scanners, LOB apps) that "
                                           f"legitimately require direct send. "
                                           f"Remove the connector if direct send is not required.",
                        evidence={
                            "impact": "Any device can submit mail anonymously, bypassing authentication controls.",
                            "connector_name":    name,
                            "remote_ip_ranges":  remote_ips,
                            "bindings":          bindings,
                        },
                    ))
                else:
                    # Connector is IP-restricted — check for transport rule enforcement
                    direct_send_rules = [
                        r for r in rules
                        if r.get("State") == "Enabled" and
                           r.get("FromScope") in ("", None) and
                           r.get("SenderIPRanges")
                    ]
                    if not direct_send_rules:
                        findings.append(Finding(
                            id=f"direct-send-anon-connector-no-rule-{name.replace(' ', '-')}",
                            category="direct_send",
                            severity="medium",
                            title=f"Anonymous connector '{name}' has no blocking transport rule",
                            description=f"Receive connector '{name}' allows anonymous SMTP from specific IPs "
                                        f"({', '.join(str(ip) for ip in remote_ips[:3])}...). "
                                        f"However, no transport rule was found that restricts or audits "
                                        f"mail arriving via this connector. Without a rule, there is no "
                                        f"enforcement layer to block spoofing from these IPs.",
                            recommended_action=f"Create a transport rule that matches mail arriving on connector "
                                               f"'{name}' and enforces sender domain restrictions, adds "
                                               f"a disclaimer, or routes to a specific mailbox for auditing.",
                            evidence={
                                "impact": "Direct send from allowed IPs is not audited or restricted by transport rules.",
                                "connector_name":   name,
                                "remote_ip_ranges": remote_ips,
                            },
                        ))

        # ── Check if transport rules compensate for missing global restriction ─
        if smtp_disabled:
            # Good — global SMTP AUTH disabled. Log as informational.
            pass

        duration_ms = int((datetime.now(timezone.utc) - t0).total_seconds() * 1000)

        evidence = {
            "domain":                   self.domain,
            "tenant_id":                request.tenant_id,
            "smtp_auth_disabled":       smtp_disabled,
            "receive_connectors":       connectors,
            "transport_rule_count":     len(rules),
            "scan_duration_ms":         duration_ms,
        }

        return ScanResult(
            scan_id=str(uuid.uuid4()),
            tenant_id=request.tenant_id,
            family="mail_routing_topology",
            findings=findings,
            score=min(100, len([f for f in findings if f.severity in ("critical","high")]) * 30),
            status="completed",
            timestamp=t0.isoformat(),
            evidence=evidence,
        )

    def _not_applicable(self, t0, reason: str) -> ScanResult:
        return ScanResult(
            scan_id=str(uuid.uuid4()),
            tenant_id="",
            family="mail_routing_topology",
            findings=[],
            score=0,
            status="completed",
            timestamp=t0.isoformat(),
            evidence={"domain": self.domain, "not_applicable": True, "reason": reason},
        )

    def _error(self, t0, reason: str) -> ScanResult:
        return ScanResult(
            scan_id=str(uuid.uuid4()),
            tenant_id="",
            family="mail_routing_topology",
            findings=[Finding(
                id=f"direct-send-error-{self.domain}",
                category="direct_send",
                severity="info",
                title="Direct send analysis could not complete",
                description=reason,
                recommended_action="Verify tenant credentials and Exchange Online permissions.",
                evidence={"impact": "Direct send analysis unavailable."},
            )],
            score=0,
            status="completed",
            timestamp=t0.isoformat(),
            evidence={"domain": self.domain, "error": reason},
        )
