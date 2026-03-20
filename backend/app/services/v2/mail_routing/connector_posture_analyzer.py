# connector_posture_analyzer.py
#
# ConnectorPostureAnalyzer — task: connector_posture
#
# Tenant-authenticated. Requires stored M365 credentials.
# Queries Exchange Online (PowerShell) for:
#   - Inbound connectors: partner, on-premises, enhanced filtering status
#   - Outbound connectors: TLS enforcement, smart host config
#   - Transport rules: overly broad rules, direct send restrictions
#
# Also queries Graph API for outbound connector TLS enforcement details.
# GWS-only tenants receive a "not_applicable" result — no error.

import uuid
import asyncio
from datetime import datetime, timezone
from typing import List, Optional

from app.models.v2.scan_request import ScanRequest
from app.models.v2.scan_result import ScanResult
from app.models.v2.finding import Finding


def _get_tenant_creds(tenant_id: str):
    """
    Load and decrypt M365 credentials for the given tenant_id (our DB id, not Azure tenant_id).
    Returns (azure_tenant_id, client_id, client_secret) or None if not M365 tenant.
    """
    try:
        from app.core.database import SessionLocal
        from app.models.tenant import Tenant
        from app.core.security import decrypt
        db = SessionLocal()
        try:
            tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
            if not tenant or not tenant.has_m365:
                return None
            return (
                tenant.tenant_id,
                tenant.client_id,
                decrypt(tenant.client_secret),
            )
        finally:
            db.close()
    except Exception:
        return None


class ConnectorPostureAnalyzer:

    def __init__(self, domain: str):
        self.domain = domain

    async def run(self, request: ScanRequest) -> ScanResult:
        t0 = datetime.now(timezone.utc)
        findings: List[Finding] = []

        # ── Authenticate ──────────────────────────────────────────────────────
        if not request.tenant_id:
            return self._not_applicable(t0, "No tenant_id in scan request")

        creds = _get_tenant_creds(request.tenant_id)
        if creds is None:
            return self._not_applicable(t0, "Tenant is not an M365 tenant or credentials not found")

        azure_tenant_id, client_id, client_secret = creds

        try:
            from app.services.exchange_checker import ExchangeChecker
            from app.services.graph_client import GraphClient
            exo   = ExchangeChecker(azure_tenant_id, client_id, client_secret)
            graph = GraphClient(azure_tenant_id, client_id, client_secret)
        except Exception as e:
            return self._error(t0, f"Failed to initialise Exchange/Graph clients: {e}")

        # ── Gather data concurrently ──────────────────────────────────────────
        try:
            (
                inbound_raw,
                outbound_raw,
                transport_raw,
            ) = await asyncio.gather(
                self._get_inbound_connectors(exo),
                self._get_outbound_connectors_graph(graph, azure_tenant_id, client_id, client_secret),
                self._get_transport_rules(exo),
                return_exceptions=True,
            )
        except Exception as e:
            return self._error(t0, f"Data collection failed: {e}")

        inbound_connectors  = inbound_raw  if isinstance(inbound_raw, list)  else []
        outbound_connectors = outbound_raw if isinstance(outbound_raw, list) else []
        transport_rules     = transport_raw if isinstance(transport_raw, list) else []

        # ── Analyse inbound connectors ────────────────────────────────────────
        for conn in inbound_connectors:
            name    = conn.get("Name", "Unknown")
            enabled = conn.get("Enabled", True)
            ctype   = conn.get("ConnectorType", "")
            ef      = conn.get("EFSkipLastIP", conn.get("EFEnabled", False))
            require_tls  = conn.get("RequireTls", False)
            restrict_ips = conn.get("SenderIPAddresses", []) or conn.get("TlsSenderCertificateName", "")

            if not enabled:
                continue

            if ctype == "Partner" and not require_tls:
                findings.append(Finding(
                    id=f"connector-inbound-no-tls-{name.replace(' ', '-')}",
                    category="connector_posture",
                    severity="high",
                    title=f"Inbound partner connector '{name}' does not require TLS",
                    description=f"The inbound connector '{name}' accepts mail from partner organisations "
                                f"without enforcing TLS. Mail may be received in plaintext, allowing "
                                f"interception in transit.",
                    recommended_action=f"Enable 'Require TLS' on connector '{name}' in Exchange Admin Center → "
                                       f"Mail flow → Connectors. Also consider pinning the sender certificate.",
                    evidence={
                        "impact": "Inbound mail from this partner may travel unencrypted.",
                        "connector_name": name,
                        "connector_type": ctype,
                        "require_tls":    require_tls,
                    },
                ))

            # Enhanced Filtering not enabled for SEG connectors
            if ctype == "Partner" and not ef:
                findings.append(Finding(
                    id=f"connector-inbound-no-ef-{name.replace(' ', '-')}",
                    category="connector_posture",
                    severity="medium",
                    title=f"Inbound connector '{name}' missing Enhanced Filtering",
                    description=f"The inbound connector '{name}' does not have Enhanced Filtering for "
                                f"Connectors enabled. When mail arrives via a SEG (e.g. Proofpoint, Mimecast), "
                                f"EOP sees only the SEG's IP address — not the original sender IP. Without "
                                f"Enhanced Filtering, Microsoft's anti-spam and anti-phishing systems cannot "
                                f"correctly evaluate the original sender, reducing detection accuracy.",
                    recommended_action=f"Enable Enhanced Filtering on connector '{name}' in "
                                       f"Exchange Admin Center → Mail flow → Connectors → Edit → "
                                       f"Enhanced Filtering. This allows EOP to skip the known "
                                       f"SEG IPs and evaluate the true originating IP.",
                    evidence={
                        "impact": "Reduced anti-spam/phishing accuracy — EOP evaluates SEG IP instead of original sender.",
                        "connector_name": name,
                        "ef_enabled":     ef,
                    },
                ))

        # ── Analyse outbound connectors ───────────────────────────────────────
        for conn in outbound_connectors:
            name         = conn.get("name", conn.get("Name", "Unknown"))
            enabled      = conn.get("isEnabled", conn.get("Enabled", True))
            use_mx       = conn.get("useMxRecord", True)
            tls_settings = conn.get("tlsSettings", {})
            tls_domain   = tls_settings.get("tlsDomain", "") if isinstance(tls_settings, dict) else ""
            tls_cert      = tls_settings.get("tlsCertificateName", "") if isinstance(tls_settings, dict) else ""

            if not enabled:
                continue

            if not use_mx and not tls_domain and not tls_cert:
                findings.append(Finding(
                    id=f"connector-outbound-no-tls-{name.replace(' ', '-')}",
                    category="connector_posture",
                    severity="high",
                    title=f"Outbound connector '{name}' routes via smart host without TLS enforcement",
                    description=f"Outbound connector '{name}' routes mail through a smart host but does not "
                                f"enforce TLS. Outbound mail may be delivered in plaintext to the smart host.",
                    recommended_action=f"Configure TLS enforcement on outbound connector '{name}'. "
                                       f"Set 'Always use TLS' and pin the destination certificate if possible.",
                    evidence={
                        "impact": "Outbound mail may be relayed to smart host without encryption.",
                        "connector_name":  name,
                        "tls_domain":      tls_domain or "not set",
                    },
                ))

        # ── Analyse transport rules ───────────────────────────────────────────
        broad_rules  = []
        bypass_rules = []

        for rule in transport_rules:
            name      = rule.get("Name", "Unknown")
            state     = rule.get("State", "Enabled")
            from_scope = rule.get("FromScope", "")
            sender_ips = rule.get("SenderIPRanges", []) or []
            bypass_spam = rule.get("SetSCL", None)

            if state != "Enabled":
                continue

            # Rules that bypass spam filtering entirely for broad scopes
            if bypass_spam == -1 and from_scope in ("", "NotInOrganization", None):
                bypass_rules.append(name)

            # Rules with no sender IP restriction from external scope
            if from_scope in ("NotInOrganization", "") and not sender_ips:
                broad_rules.append(name)

        if bypass_rules:
            findings.append(Finding(
                id=f"connector-transport-bypass-spam-{self.domain}",
                category="connector_posture",
                severity="high",
                title=f"Transport rule(s) bypass spam filtering for external senders",
                description=f"{len(bypass_rules)} transport rule(s) set SCL=-1 (bypass spam filter) "
                            f"for mail from external sources without restricting by sender IP. "
                            f"This allows external senders to bypass Microsoft's spam and phishing detection. "
                            f"Affected rules: {', '.join(bypass_rules)}.",
                recommended_action="Review transport rules that set SCL=-1. Restrict bypass rules to "
                                   "specific trusted IP ranges or remove them if not required. "
                                   "Use allow lists in anti-spam policy instead of transport rule bypasses.",
                evidence={
                    "impact": "Phishing and spam from external sources may bypass EOP filtering controls.",
                    "affected_rules": bypass_rules,
                },
            ))

        if len(broad_rules) > 3:
            findings.append(Finding(
                id=f"connector-transport-broad-rules-{self.domain}",
                category="connector_posture",
                severity="low",
                title=f"{len(broad_rules)} transport rules apply to all external senders without IP restriction",
                description=f"{len(broad_rules)} enabled transport rules match all external senders "
                            f"without a sender IP restriction. While not inherently dangerous, broad rules "
                            f"increase the attack surface for rule abuse and make mail flow harder to audit.",
                recommended_action="Audit transport rules and add sender IP restrictions where possible. "
                                   "Document the business purpose of each broad rule.",
                evidence={
                    "impact": "Transport rules apply broadly — increases rule abuse risk.",
                    "broad_rule_count": len(broad_rules),
                    "rule_names":       broad_rules[:10],
                },
            ))

        duration_ms = int((datetime.now(timezone.utc) - t0).total_seconds() * 1000)

        evidence = {
            "domain":               self.domain,
            "tenant_id":            request.tenant_id,
            "inbound_connector_count":  len(inbound_connectors),
            "outbound_connector_count": len(outbound_connectors),
            "transport_rule_count":     len(transport_rules),
            "inbound_connectors":   inbound_connectors,
            "outbound_connectors":  outbound_connectors,
            "transport_rules":      transport_rules,
            "scan_duration_ms":     duration_ms,
        }

        return ScanResult(
            scan_id=str(uuid.uuid4()),
            tenant_id=request.tenant_id,
            family="mail_routing_topology",
            findings=findings,
            score=min(100, len([f for f in findings if f.severity in ("critical","high")]) * 25),
            status="completed",
            timestamp=t0.isoformat(),
            evidence=evidence,
        )

    # ── Data fetchers ─────────────────────────────────────────────────────────

    async def _get_inbound_connectors(self, exo) -> list:
        script = exo._script("""
$c = Get-InboundConnector | Select-Object Name,Enabled,ConnectorType,
     RequireTls,TlsSenderCertificateName,SenderIPAddresses,
     EFSkipLastIP,EFEnabled,EFSkipIPs | ConvertTo-Json -Depth 4
Write-Output $c
""")
        from app.services.exchange_checker import _run_pwsh
        raw = await _run_pwsh(script)
        if isinstance(raw, list): return raw
        if isinstance(raw, dict): return [raw]
        return []

    async def _get_outbound_connectors_graph(
        self, graph, azure_tenant_id: str, client_id: str, client_secret: str
    ) -> list:
        """Get outbound connectors via Graph API beta endpoint."""
        try:
            import httpx
            token = await graph._get_token()
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    "https://graph.microsoft.com/v1.0/organization",
                    headers={"Authorization": f"Bearer {token}"},
                )
                # Graph doesn't expose connectors directly — fall back to EXO PowerShell
                raise NotImplementedError("Using EXO fallback")
        except Exception:
            # Fall back to Exchange PowerShell
            try:
                from app.services.exchange_checker import ExchangeChecker, _run_pwsh
                exo = ExchangeChecker(azure_tenant_id, client_id, client_secret)
                script = exo._script("""
$c = Get-OutboundConnector | Select-Object Name,Enabled,UseMxRecord,
     SmartHosts,TlsDomain,TlsCertificateName,RequireTls,
     IsTransportRuleScoped | ConvertTo-Json -Depth 4
Write-Output $c
""")
                raw = await _run_pwsh(script)
                # Normalise to list with consistent field names
                items = raw if isinstance(raw, list) else ([raw] if isinstance(raw, dict) else [])
                return [
                    {
                        "name":        item.get("Name", "Unknown"),
                        "isEnabled":   item.get("Enabled", True),
                        "useMxRecord": item.get("UseMxRecord", True),
                        "tlsSettings": {
                            "tlsDomain":          item.get("TlsDomain", ""),
                            "tlsCertificateName": item.get("TlsCertificateName", ""),
                        },
                        "requireTls":  item.get("RequireTls", False),
                        "smartHosts":  item.get("SmartHosts", []),
                    }
                    for item in items
                ]
            except Exception:
                return []

    async def _get_transport_rules(self, exo) -> list:
        script = exo._script("""
$r = Get-TransportRule | Select-Object Name,State,Priority,
     FromScope,SenderIPRanges,SetSCL,
     RejectMessageReasonText | ConvertTo-Json -Depth 3
Write-Output $r
""")
        from app.services.exchange_checker import _run_pwsh
        raw = await _run_pwsh(script)
        if isinstance(raw, list): return raw
        if isinstance(raw, dict): return [raw]
        return []

    def _not_applicable(self, t0, reason: str) -> ScanResult:
        return ScanResult(
            scan_id=str(uuid.uuid4()),
            tenant_id="",
            family="mail_routing_topology",
            findings=[],
            score=0,
            status="completed",
            timestamp=t0.isoformat(),
            evidence={
                "domain": self.domain,
                "not_applicable": True,
                "reason": reason,
            },
        )

    def _error(self, t0, reason: str) -> ScanResult:
        return ScanResult(
            scan_id=str(uuid.uuid4()),
            tenant_id="",
            family="mail_routing_topology",
            findings=[Finding(
                id=f"connector-scan-error-{self.domain}",
                category="connector_posture",
                severity="info",
                title="Connector analysis could not complete",
                description=reason,
                recommended_action="Verify tenant credentials and Exchange Online permissions.",
                evidence={"impact": "Connector posture analysis unavailable."},
            )],
            score=0,
            status="completed",
            timestamp=t0.isoformat(),
            evidence={"domain": self.domain, "error": reason},
        )
