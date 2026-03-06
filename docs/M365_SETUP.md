# Microsoft 365 App Registration Setup

MailGuard uses Microsoft Graph API to audit your M365 security posture. You need to create an Azure AD App Registration and grant it the required API permissions.

## Step-by-Step

### 1. Create the App Registration

1. Go to [portal.azure.com](https://portal.azure.com)
2. Navigate to **Azure Active Directory → App registrations → New registration**
3. Name: `MailGuard` (or any name you prefer)
4. Supported account types: **Accounts in this organizational directory only**
5. Redirect URI: leave blank
6. Click **Register**

### 2. Copy the IDs

On the app overview page, copy:
- **Application (client) ID** → this is your `SEED_CLIENT_ID`
- **Directory (tenant) ID** → this is your `SEED_TENANT_ID`

### 3. Create a Client Secret

1. Go to **Certificates & secrets → Client secrets → New client secret**
2. Description: `mailguard`
3. Expiry: choose your preferred duration (24 months recommended)
4. Click **Add**
5. **Copy the secret value immediately** — it won't be shown again
   → this is your `SEED_CLIENT_SECRET`

### 4. Grant API Permissions

1. Go to **API permissions → Add a permission → Microsoft Graph → Application permissions**
2. Add each of the following:

| Permission | Why it's needed |
|---|---|
| `Organization.Read.All` | Read tenant domain and org info |
| `Policy.Read.All` | Read anti-spam, anti-phishing policies |
| `Domain.Read.All` | Read domain verification status |
| `SecurityEvents.Read.All` | Read security alerts |
| `Mail.Read` | SEG bypass detection (mail flow analysis) |

3. Click **Grant admin consent for [your tenant]** — this is required for application permissions

### 5. Set the Environment Variables

```env
SEED_TENANT_DOMAIN=yourdomain.com
SEED_TENANT_ID=<Directory (tenant) ID>
SEED_CLIENT_ID=<Application (client) ID>
SEED_CLIENT_SECRET=<Client secret value>
```

---

## Least-Privilege Note

If you prefer not to grant `Mail.Read`, MailGuard will still run — the SEG bypass check will show as "Unable to verify" instead of a real result. All other checks will work normally.

---

## Rotating the Client Secret

When your client secret expires:
1. Create a new secret in the Azure portal (Certificates & secrets)
2. Update `SEED_CLIENT_SECRET` in your Azure Container App environment variables
3. Redeploy or restart the app
