"""
Microsoft Graph + Exchange Online API client.
Uses client credentials (app-only) OAuth 2.0 flow.
Required App Registration permissions (Application, not Delegated):
  - Policy.Read.All
  - Directory.Read.All
  - SecurityEvents.Read.All
  - ReportingWebService.Read.All
  - Exchange.ManageAsApp  (+ Exchange Online admin role assigned to the SP)
"""
import httpx
from typing import Any, Dict, Optional


GRAPH_URL  = "https://graph.microsoft.com/v1.0"
LOGIN_URL  = "https://login.microsoftonline.com"
SCOPE      = "https://graph.microsoft.com/.default"
EXO_SCOPE  = "https://outlook.office365.com/.default"


class GraphClient:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id     = tenant_id
        self.client_id     = client_id
        self.client_secret = client_secret
        self._token: Optional[str] = None

    # ── Auth ──────────────────────────────────────────────────────────────────

    async def _get_token(self, scope: str = SCOPE) -> str:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{LOGIN_URL}/{self.tenant_id}/oauth2/v2.0/token",
                data={
                    "grant_type":    "client_credentials",
                    "client_id":     self.client_id,
                    "client_secret": self.client_secret,
                    "scope":         scope,
                },
            )
            resp.raise_for_status()
            return resp.json()["access_token"]

    async def _graph(self, path: str, params: Dict = None) -> Any:
        if not self._token:
            self._token = await self._get_token()
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{GRAPH_URL}/{path}",
                headers={"Authorization": f"Bearer {self._token}"},
                params=params or {},
                timeout=30,
            )
            if resp.status_code == 401:
                # Token may have expired — refresh once
                self._token = await self._get_token()
                resp = await client.get(
                    f"{GRAPH_URL}/{path}",
                    headers={"Authorization": f"Bearer {self._token}"},
                    params=params or {},
                    timeout=30,
                )
            resp.raise_for_status()
            return resp.json()

    # ── Graph endpoints ───────────────────────────────────────────────────────

    async def get_domains(self) -> list:
        data = await self._graph("domains")
        return data.get("value", [])

    async def get_secure_score(self) -> Dict:
        data = await self._graph("security/secureScores", {"$top": "1"})
        scores = data.get("value", [])
        return scores[0] if scores else {}

    async def get_users_without_mfa(self) -> list:
        """Returns admin users who don't have MFA registered."""
        # Get directory role members for privileged roles
        roles_data = await self._graph(
            "directoryRoles",
            {"$filter": "roleTemplateId eq '62e90394-69f5-4237-9190-012177145e10'"}  # Global Admin
        )
        roles = roles_data.get("value", [])
        admin_users = []
        for role in roles:
            members = await self._graph(f"directoryRoles/{role['id']}/members")
            admin_users.extend(members.get("value", []))

        # Check auth methods registration
        no_mfa = []
        for user in admin_users:
            uid = user.get("id")
            if not uid:
                continue
            try:
                methods = await self._graph(f"users/{uid}/authentication/methods")
                method_types = [m.get("@odata.type","") for m in methods.get("value",[])]
                has_mfa = any(
                    t for t in method_types
                    if "microsoftAuthenticator" in t or "fido2" in t or "phone" in t
                )
                if not has_mfa:
                    no_mfa.append(user.get("userPrincipalName", uid))
            except Exception:
                no_mfa.append(user.get("userPrincipalName", uid))
        return no_mfa

    async def get_conditional_access_policies(self) -> list:
        data = await self._graph("identity/conditionalAccess/policies")
        return data.get("value", [])

    async def get_security_defaults(self) -> Dict:
        data = await self._graph("policies/identitySecurityDefaultsEnforcementPolicy")
        return data

    async def get_dns_txt_records(self, domain: str) -> list:
        """Uses Graph to retrieve DNS records if available, else falls back to dns.resolver."""
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, "TXT")
            return [r.to_text().strip('"') for r in answers]
        except Exception:
            return []

    async def get_dkim_selectors(self, domain: str) -> Dict:
        """Check common DKIM selectors for a domain."""
        import dns.resolver
        selectors = ["selector1", "selector2"]
        result = {}
        for sel in selectors:
            try:
                answers = dns.resolver.resolve(f"{sel}._domainkey.{domain}", "CNAME")
                result[sel] = str(answers[0])
            except Exception:
                result[sel] = None
        return result

    async def get_dmarc_record(self, domain: str) -> Optional[str]:
        import dns.resolver
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for r in answers:
                txt = r.to_text().strip('"')
                if txt.startswith("v=DMARC1"):
                    return txt
        except Exception:
            pass
        return None

    # ── Teams settings ────────────────────────────────────────────────────────

    async def get_teams_settings(self) -> Dict:
        """
        CIS 8.1.1 / 8.2.1 — Teams external access and guest access settings.
        Requires TeamsAdministrator or Global Reader role on the app registration.
        Falls back gracefully if Teams admin API is not permissioned.
        """
        try:
            # Teams tenant-wide config via Graph teamsApp / teamwork endpoint
            data = await self._graph("teamwork")
            return data
        except Exception:
            return {}

    async def get_teams_federation_settings(self) -> Dict:
        """
        External access (federation) settings — whether users can communicate
        with external Teams / Skype for Business orgs.
        CIS Microsoft 365 v4.0.0 — Control 8.2.1
        """
        try:
            data = await self._graph("policies/externalIdentityPolicies")
            return data
        except Exception:
            return {}

    async def get_teams_guest_settings(self) -> Dict:
        """
        Guest access in Teams — CIS 8.1.1.
        Uses the directory settings endpoint (B2B collaboration settings).
        """
        try:
            data = await self._graph("settings")
            settings_list = data.get("value", [])
            for s in settings_list:
                if "B2B" in s.get("displayName", "") or "Guest" in s.get("displayName", ""):
                    return s
            return {}
        except Exception:
            return {}

    # ── SharePoint settings ───────────────────────────────────────────────────

    async def get_sharepoint_settings(self) -> Dict:
        """
        SharePoint tenant-wide settings for external sharing.
        CIS Microsoft 365 v4.0.0 — Controls 7.2.1, 7.2.2, 7.2.9.
        Requires SharePoint Administrator or Global Reader role.
        Uses the SharePoint admin API via Graph (admin/sharepoint/settings).
        """
        try:
            data = await self._graph("admin/sharepoint/settings")
            return data
        except Exception:
            return {}
