# tenant_discovery.py
#
# Microsoft 365 public tenant discovery module.
#
# Uses only public, unauthenticated Microsoft endpoints:
#   - GetUserRealm    — namespace type, cloud instance
#   - OIDC config     — tenant ID, issuer, region
#   - Autodiscover    — M365 signal confirmation
#
# No credentials required. No write operations.

import re
import uuid
import httpx

from app.models.v2.finding import Finding, SEVERITIES
from app.models.v2.scan_result import ScanResult
from app.models.v2.scan_request import ScanRequest

# Public Microsoft endpoints used for discovery
_GETUSERREALM_URL = "https://login.microsoftonline.com/getuserrealm.srf"
_OIDC_URL         = "https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration"
_AUTODISCOVER_URL = "https://autodiscover-s.outlook.com/autodiscover/autodiscoverv1.xml"

# Regex to pull tenant GUID from a token_endpoint URL
_TENANT_ID_RE = re.compile(
    r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/"
)


class M365TenantDiscovery:
    """
    Discovers public Microsoft 365 tenant metadata for a given domain.

    Usage:
        module = M365TenantDiscovery("example.com")
        result = await module.run(request)
    """

    def __init__(self, domain: str):
        self.domain = domain
        self.findings: list[Finding] = []
        self.summary = {
            "discovered":           False,
            "domain":               domain,
            "tenant_id":            None,
            "namespace_type":       None,
            "cloud_instance_name":  None,
            "tenant_region_scope":  None,
            "oidc_issuer":          None,
            "is_m365_detected":     False,
        }

    async def run(self, request: ScanRequest) -> ScanResult:
        import datetime

        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
            await self._discover_userrealm(client)
            await self._discover_oidc(client)
            await self._check_autodiscover(client)

        # If nothing resolved, add a negative finding
        if not self.summary["discovered"]:
            self.findings.append(self._finding(
                fid="tenant-not-found",
                severity="info",
                title="Tenant discovery returned no results",
                description=(
                    f"No Microsoft 365 tenant signals were found for {self.domain}. "
                    "The domain may not be associated with an M365 tenant, or signals are suppressed."
                ),
                evidence={"domain": self.domain},
            ))

        return ScanResult(
            scan_id=str(uuid.uuid4()),
            tenant_id=self.summary.get("tenant_id") or self.domain,
            family="public_intel",
            findings=self.findings,
            score=0,          # Scoring to be implemented in a later phase
            status="complete",
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            evidence=self.summary,
        )

    # ------------------------------------------------------------------
    # Discovery methods
    # ------------------------------------------------------------------

    async def _discover_userrealm(self, client: httpx.AsyncClient) -> None:
        """
        Queries GetUserRealm to determine namespace type and cloud instance.
        Returns Managed, Federated, or Unknown.
        """
        try:
            resp = await client.get(
                _GETUSERREALM_URL,
                params={"login": f"probe@{self.domain}", "json": "1"},
            )
            resp.raise_for_status()
            data = resp.json()

            ns_type       = data.get("NameSpaceType", "Unknown")
            cloud_instance = data.get("CloudInstanceName")
            brand_name    = data.get("FederationBrandName")

            self.summary["namespace_type"]      = ns_type
            self.summary["cloud_instance_name"] = cloud_instance

            if ns_type in ("Managed", "Federated"):
                self.summary["is_m365_detected"] = True
                self.summary["discovered"]       = True
                self.findings.append(self._finding(
                    fid="namespace-type",
                    severity="info",
                    title=f"{ns_type} namespace detected",
                    description=(
                        f"Domain {self.domain} uses a {ns_type} Microsoft 365 namespace. "
                        + (f"Tenant brand name: {brand_name}." if brand_name else "")
                    ),
                    evidence={
                        "namespace_type":      ns_type,
                        "cloud_instance_name": cloud_instance,
                        "federation_brand":    brand_name,
                    },
                ))

            if ns_type == "Federated":
                auth_url = data.get("AuthURL")
                self.findings.append(self._finding(
                    fid="federated-auth-url",
                    severity="low",
                    title="Federated authentication URL exposed",
                    description=(
                        f"Domain {self.domain} delegates authentication to an external IdP. "
                        f"The federation URL is publicly discoverable."
                    ),
                    evidence={"auth_url": auth_url},
                ))

        except httpx.HTTPStatusError as e:
            self._add_failure("getuserrealm", str(e))
        except Exception as e:
            self._add_failure("getuserrealm", str(e))

    async def _discover_oidc(self, client: httpx.AsyncClient) -> None:
        """
        Queries the OIDC openid-configuration endpoint for tenant metadata.
        Extracts tenant_id, issuer, region, and cloud instance name.
        """
        url = _OIDC_URL.format(domain=self.domain)
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                # Non-200 means this domain has no OIDC config — not an error
                return

            data = resp.json()

            issuer          = data.get("issuer")
            token_endpoint  = data.get("token_endpoint", "")
            tenant_region   = data.get("tenant_region_scope")
            cloud_instance  = data.get("cloud_instance_name")

            # Extract tenant GUID from token_endpoint path
            tenant_id = None
            match = _TENANT_ID_RE.search(token_endpoint)
            if match:
                tenant_id = match.group(1)

            self.summary["tenant_id"]           = tenant_id
            self.summary["oidc_issuer"]         = issuer
            self.summary["tenant_region_scope"] = tenant_region
            if cloud_instance:
                self.summary["cloud_instance_name"] = cloud_instance

            if tenant_id:
                self.summary["discovered"] = True
                self.findings.append(self._finding(
                    fid="tenant-id-discovered",
                    severity="info",
                    title="Microsoft 365 tenant ID discovered",
                    description=(
                        f"Tenant ID {tenant_id} was publicly discovered for {self.domain} "
                        f"via OIDC configuration."
                    ),
                    evidence={
                        "tenant_id":            tenant_id,
                        "oidc_issuer":          issuer,
                        "tenant_region_scope":  tenant_region,
                        "cloud_instance_name":  cloud_instance,
                    },
                ))

            if tenant_region:
                self.findings.append(self._finding(
                    fid="tenant-region",
                    severity="info",
                    title=f"Tenant region scope: {tenant_region}",
                    description=f"The Microsoft 365 tenant for {self.domain} is in region: {tenant_region}.",
                    evidence={"tenant_region_scope": tenant_region},
                ))

        except httpx.HTTPStatusError as e:
            self._add_failure("oidc", str(e))
        except Exception as e:
            self._add_failure("oidc", str(e))

    async def _check_autodiscover(self, client: httpx.AsyncClient) -> None:
        """
        Checks the autodiscover endpoint for an M365 signal.
        A response (even 401/403) from this endpoint confirms Exchange Online.
        This is best-effort only — failures are silently ignored.
        """
        try:
            resp = await client.get(
                _AUTODISCOVER_URL,
                params={"Email": f"probe@{self.domain}"},
            )
            server_header = resp.headers.get("server", "")
            is_exchange   = resp.status_code in (200, 401, 403) or "Microsoft" in server_header

            if is_exchange:
                self.summary["is_m365_detected"] = True
                self.summary["discovered"]       = True
                self.findings.append(self._finding(
                    fid="autodiscover-m365-signal",
                    severity="info",
                    title="Autodiscover confirms Microsoft 365 presence",
                    description=(
                        f"The autodiscover endpoint responded for {self.domain}, "
                        "confirming the domain is hosted on Exchange Online / Microsoft 365."
                    ),
                    evidence={
                        "status_code":   resp.status_code,
                        "server_header": server_header,
                    },
                ))
        except Exception:
            # Autodiscover is best-effort. Suppress all errors here.
            pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _finding(
        self,
        fid: str,
        severity: str,
        title: str,
        description: str,
        evidence: dict,
    ) -> Finding:
        return Finding(
            id=f"public-intel-m365-{fid}-{self.domain}",
            category="public_intel",
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
        )

    def _add_failure(self, source: str, error: str) -> None:
        self.findings.append(self._finding(
            fid=f"{source}-failed",
            severity="info",
            title=f"Discovery signal failed: {source}",
            description=f"The {source} lookup encountered an error: {error}",
            evidence={"error": error, "source": source},
        ))