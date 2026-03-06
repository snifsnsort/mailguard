"""
OAuth Onboarding Service

Flow:
1. Admin visits /connect, clicks button → redirected to Microsoft consent
2. Admin grants consent → callback receives auth code
3. We exchange code for token, extract tenant ID
4. We use the delegated token to grant app-only permissions to our service principal
5. We save tenant and use client_credentials for all future scans
"""

import httpx
import secrets
import base64
import os
import json
from typing import Dict, Tuple
from urllib.parse import urlencode

GRAPH_BASE         = "https://graph.microsoft.com/v1.0"
AUTH_BASE          = "https://login.microsoftonline.com"
COMMON_TOKEN_URL   = f"{AUTH_BASE}/common/oauth2/v2.0/token"
COMMON_AUTH_URL    = f"{AUTH_BASE}/common/oauth2/v2.0/authorize"

MAILGUARD_CLIENT_ID     = os.environ.get("MAILGUARD_CLIENT_ID", "")
MAILGUARD_CLIENT_SECRET = os.environ.get("MAILGUARD_CLIENT_SECRET", "")
MAILGUARD_REDIRECT_URI  = os.environ.get("MAILGUARD_REDIRECT_URI", "")

# Delegated scopes for the consent screen
# These must be delegated scopes — we need admin consent to also grant app permissions
CONSENT_SCOPES = [
    "https://graph.microsoft.com/Directory.Read.All",
    "https://graph.microsoft.com/Policy.Read.All",
    "https://graph.microsoft.com/AppRoleAssignment.ReadWrite.All",
    "https://graph.microsoft.com/Application.ReadWrite.All",
    "offline_access",
]

# Application permission IDs on Microsoft Graph (resource: 00000003-0000-0000-c000-000000000000)
# These are the app-only permissions needed for scanning
GRAPH_APP_PERMISSIONS = [
    "246dd0d5-5bd0-4def-940b-0421030a5b68",  # Policy.Read.All
    "7ab1d382-f21e-4acd-a863-ba3e13f7da61",  # Directory.Read.All
    "b0afded3-3588-46d8-8b3d-9842eff778da",  # AuditLog.Read.All
    "9e640839-a198-48fb-8b9a-013fd6f6cbcd",  # SecurityEvents.Read.All (ReportingWebService)
    "38d9df27-64da-44fd-b7c5-a6fbac20248f",  # UserAuthenticationMethod.Read.All
    "e1fe6dd8-ba31-4d61-89e7-88639da4683d",  # User.Read.All
    "dbb9058a-0e50-45d7-ae91-66909b5d4664",  # Organization.Read.All
    "bac3b9c2-b516-4ef4-bd3b-c2ef73d8d804",  # Domain.Read.All
]

# Exchange Online app permissions (resource: 00000002-0000-0ff1-ce00-000000000000)
EXO_APP_PERMISSIONS = [
    "dc50a0fb-09a3-484d-be87-e023b12c6440",  # Exchange.ManageAsApp
]

GRAPH_RESOURCE_ID = "00000003-0000-0000-c000-000000000000"
EXO_RESOURCE_ID   = "00000002-0000-0ff1-ce00-000000000000"

# Exchange Administrator role template ID
EXCHANGE_ADMIN_ROLE = "29232cdf-9323-42fd-ade2-1d097af3e4de"

_state_store: Dict[str, dict] = {}


def generate_auth_url(redirect_after: str = "/") -> Tuple[str, str]:
    if not MAILGUARD_CLIENT_ID:
        raise RuntimeError("MAILGUARD_CLIENT_ID not set.")

    state = secrets.token_urlsafe(32)
    _state_store[state] = {"redirect_after": redirect_after}

    params = {
        "client_id":     MAILGUARD_CLIENT_ID,
        "response_type": "code",
        "redirect_uri":  MAILGUARD_REDIRECT_URI,
        "scope":         " ".join(CONSENT_SCOPES),
        "response_mode": "query",
        "state":         state,
        "prompt":        "consent",
    }
    return f"{COMMON_AUTH_URL}?{urlencode(params)}", state


async def exchange_code_for_token(code: str, state: str) -> Tuple[dict, str]:
    """Exchange auth code for access token. Returns (token_data, tenant_id)."""
    if state not in _state_store:
        raise ValueError("Invalid or expired state token")

    async with httpx.AsyncClient() as client:
        resp = await client.post(COMMON_TOKEN_URL, data={
            "client_id":     MAILGUARD_CLIENT_ID,
            "client_secret": MAILGUARD_CLIENT_SECRET,
            "code":          code,
            "redirect_uri":  MAILGUARD_REDIRECT_URI,
            "grant_type":    "authorization_code",
            "scope":         " ".join(CONSENT_SCOPES),
        })
        resp.raise_for_status()
        token_data = resp.json()

    # Decode tenant ID from JWT
    jwt_payload = token_data["access_token"].split(".")[1]
    jwt_payload += "=" * (4 - len(jwt_payload) % 4)
    claims = json.loads(base64.b64decode(jwt_payload))
    tenant_id = claims.get("tid", "")

    del _state_store[state]
    return token_data, tenant_id


async def provision_tenant(access_token: str, tenant_id: str) -> Dict:
    """
    After consent:
    1. Get org info (domain, display name)
    2. Find our service principal in the customer tenant
    3. Grant app-only permissions to our SP
    4. Assign Exchange Administrator role
    5. Verify client_credentials works
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=60) as client:

        # 1. Get org info
        org_resp = await client.get(f"{GRAPH_BASE}/organization", headers=headers)
        org_resp.raise_for_status()
        orgs = org_resp.json().get("value", [])
        if not orgs:
            raise ValueError("Could not retrieve organization info")
        org = orgs[0]
        domain = next(
            (d["name"] for d in org.get("verifiedDomains", []) if d.get("isDefault")),
            tenant_id
        )
        display_name = domain.split(".")[0].upper()

        # 2. Find our service principal in this tenant (created when admin granted consent)
        sp_resp = await client.get(
            f"{GRAPH_BASE}/servicePrincipals",
            headers=headers,
            params={"$filter": f"appId eq '{MAILGUARD_CLIENT_ID}'"}
        )
        sp_resp.raise_for_status()
        sp_list = sp_resp.json().get("value", [])
        if not sp_list:
            raise ValueError("MailGuard service principal not found in tenant — consent may not have completed")
        sp_id = sp_list[0]["id"]

        # 3. Find the Graph service principal in this tenant
        graph_sp_resp = await client.get(
            f"{GRAPH_BASE}/servicePrincipals",
            headers=headers,
            params={"$filter": f"appId eq '{GRAPH_RESOURCE_ID}'"}
        )
        graph_sp_resp.raise_for_status()
        graph_sp_list = graph_sp_resp.json().get("value", [])
        if graph_sp_list:
            graph_sp_id = graph_sp_list[0]["id"]
            # Grant Graph app permissions
            for perm_id in GRAPH_APP_PERMISSIONS:
                await _grant_app_role(client, headers, sp_id, graph_sp_id, perm_id)

        # 4. Find Exchange Online SP and grant permission
        exo_sp_resp = await client.get(
            f"{GRAPH_BASE}/servicePrincipals",
            headers=headers,
            params={"$filter": f"appId eq '{EXO_RESOURCE_ID}'"}
        )
        exo_sp_resp.raise_for_status()
        exo_sp_list = exo_sp_resp.json().get("value", [])
        if exo_sp_list:
            exo_sp_id = exo_sp_list[0]["id"]
            for perm_id in EXO_APP_PERMISSIONS:
                await _grant_app_role(client, headers, sp_id, exo_sp_id, perm_id)

        # 5. Assign Exchange Administrator role to our SP
        # First get the role definition
        roles_resp = await client.get(
            f"{GRAPH_BASE}/directoryRoles",
            headers=headers,
            params={"$filter": f"roleTemplateId eq '{EXCHANGE_ADMIN_ROLE}'"}
        )
        if roles_resp.status_code == 200:
            roles = roles_resp.json().get("value", [])
            if roles:
                role_id = roles[0]["id"]
                await client.post(
                    f"{GRAPH_BASE}/directoryRoles/{role_id}/members/$ref",
                    headers=headers,
                    json={"@odata.id": f"{GRAPH_BASE}/directoryObjects/{sp_id}"},
                )
                # Ignore errors — role may already be assigned

    # 6. Verify client_credentials works (wait a moment for permissions to propagate)
    import asyncio
    await asyncio.sleep(5)

    async with httpx.AsyncClient(timeout=30) as client:
        token_resp = await client.post(
            f"{AUTH_BASE}/{tenant_id}/oauth2/v2.0/token",
            data={
                "client_id":     MAILGUARD_CLIENT_ID,
                "client_secret": MAILGUARD_CLIENT_SECRET,
                "scope":         "https://graph.microsoft.com/.default",
                "grant_type":    "client_credentials",
            }
        )
        if token_resp.status_code != 200:
            raise ValueError(f"App consent not yet active: {token_resp.text}")

    return {
        "tenant_id":     tenant_id,
        "domain":        domain,
        "client_id":     MAILGUARD_CLIENT_ID,
        "client_secret": MAILGUARD_CLIENT_SECRET,
        "display_name":  display_name,
    }


async def _grant_app_role(client, headers, sp_id: str, resource_sp_id: str, app_role_id: str):
    """Grant an app role to our service principal. Ignores duplicate errors."""
    try:
        resp = await client.post(
            f"{GRAPH_BASE}/servicePrincipals/{sp_id}/appRoleAssignments",
            headers=headers,
            json={
                "principalId": sp_id,
                "resourceId":  resource_sp_id,
                "appRoleId":   app_role_id,
            }
        )
        # 409 = already assigned, that's fine
        if resp.status_code not in (200, 201, 409):
            pass  # Log but don't fail — partial permissions still allow partial scanning
    except Exception:
        pass
