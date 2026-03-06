"""
Exchange Online configuration checker.
Uses the ExchangeOnlineManagement PowerShell module via subprocess.
The Docker image includes PowerShell + the module pre-installed.
"""
import asyncio
import json
import tempfile
import os
from typing import Any, Dict, Optional


PWSH = "pwsh"  # PowerShell 7 binary in the Docker image


async def _run_pwsh(script: str) -> Dict:
    """Run a PowerShell script and return parsed JSON output."""
    with tempfile.NamedTemporaryFile(suffix=".ps1", mode="w", delete=False) as f:
        f.write(script)
        fname = f.name
    try:
        proc = await asyncio.create_subprocess_exec(
            PWSH, "-NonInteractive", "-File", fname,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        if proc.returncode != 0:
            raise RuntimeError(f"PowerShell error: {stderr.decode()}")
        raw = stdout.decode().strip()
        return json.loads(raw) if raw else {}
    finally:
        os.unlink(fname)


def _connect_block(tenant_id: str, client_id: str, client_secret: str) -> str:
    """
    Returns PowerShell block to connect to Exchange Online using app-only auth
    with client secret (requires ExchangeOnlineManagement v3.2+).

    Uses Connect-ExchangeOnline with -TenantId and -ClientSecret.
    The app registration needs:
      - Exchange.ManageAsApp API permission (granted admin consent)
      - Exchange Administrator role assigned to the service principal
    """
    return f"""
$secureSecret = ConvertTo-SecureString "{client_secret}" -AsPlainText -Force
Connect-ExchangeOnline `
    -AppId "{client_id}" `
    -TenantId "{tenant_id}" `
    -ClientSecret $secureSecret `
    -ShowBanner:$false `
    -ErrorAction Stop
"""


class ExchangeChecker:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id     = tenant_id
        self.client_id     = client_id
        self.client_secret = client_secret

    def _script(self, commands: str) -> str:
        return f"""
Import-Module ExchangeOnlineManagement -ErrorAction Stop
{_connect_block(self.tenant_id, self.client_id, self.client_secret)}
{commands}
Disconnect-ExchangeOnline -Confirm:$false
"""

    async def get_antiphishing_policy(self) -> Dict:
        script = self._script("""
$p = Get-AntiPhishPolicy | Select-Object Name,Enabled,EnableTargetedUserProtection,
     EnableTargetedDomainsProtection,EnableMailboxIntelligence,
     EnableMailboxIntelligenceProtection,TargetedUserProtectionAction,
     TargetedDomainProtectionAction | ConvertTo-Json -Depth 3
Write-Output $p
""")
        return await _run_pwsh(script)

    async def get_antispam_outbound_policy(self) -> Dict:
        script = self._script("""
$p = Get-HostedOutboundSpamFilterPolicy | Select-Object Name,
     RecipientLimitExternalPerHour,RecipientLimitInternalPerHour,
     RecipientLimitPerDay,ActionWhenThresholdReached,
     AutoForwardingMode | ConvertTo-Json -Depth 3
Write-Output $p
""")
        return await _run_pwsh(script)

    async def get_safe_links_policies(self) -> Any:
        script = self._script("""
$p = Get-SafeLinksPolicy | Select-Object Name,IsEnabled,EnableSafeLinksForEmail,
     EnableSafeLinksForTeams,EnableSafeLinksForOffice,
     TrackClicks,AllowClickThrough | ConvertTo-Json -Depth 3
Write-Output $p
""")
        return await _run_pwsh(script)

    async def get_safe_links_rules(self) -> Any:
        script = self._script("""
$r = Get-SafeLinksRule | Select-Object Name,State,SafeLinksPolicy,
     SentTo,SentToMemberOf,RecipientDomainIs | ConvertTo-Json -Depth 3
Write-Output $r
""")
        return await _run_pwsh(script)

    async def get_safe_attachments_policy(self) -> Any:
        script = self._script("""
$p = Get-SafeAttachmentPolicy | Select-Object Name,Enable,Action,
     QuarantineTag,Redirect | ConvertTo-Json -Depth 3
Write-Output $p
""")
        return await _run_pwsh(script)

    async def get_transport_rules(self) -> Any:
        """Get transport rules to assess direct send restrictions."""
        script = self._script("""
$r = Get-TransportRule | Select-Object Name,State,Priority,
     FromScope,SenderIPRanges,RejectMessageReasonText | ConvertTo-Json -Depth 3
Write-Output $r
""")
        return await _run_pwsh(script)

    async def get_smtp_auth_settings(self) -> Dict:
        script = self._script("""
$org = Get-TransportConfig | Select-Object SmtpClientAuthenticationDisabled | ConvertTo-Json
Write-Output $org
""")
        return await _run_pwsh(script)

    async def get_accepted_domains(self) -> Any:
        script = self._script("""
$d = Get-AcceptedDomain | Select-Object Name,DomainName,DomainType,Default | ConvertTo-Json -Depth 3
Write-Output $d
""")
        return await _run_pwsh(script)

    async def get_receive_connectors(self) -> Any:
        script = self._script("""
$c = Get-ReceiveConnector | Select-Object Name,Enabled,Bindings,
     RemoteIPRanges,PermissionGroups,AnonymousUsers | ConvertTo-Json -Depth 3
Write-Output $c
""")
        return await _run_pwsh(script)
