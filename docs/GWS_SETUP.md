# Google Workspace Setup

MailGuard connects to Google Workspace via OAuth 2.0. You create a Google Cloud project, configure OAuth credentials, and then authorize MailGuard through the UI.

## Step-by-Step

### 1. Create a Google Cloud Project

1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Click the project selector → **New Project**
3. Name: `MailGuard`
4. Click **Create**

### 2. Enable Required APIs

In the new project, go to **APIs & Services → Library** and enable:
- **Admin SDK API** (for directory and policy checks)
- **Gmail API** (for MX and mail flow checks)

### 3. Configure the OAuth Consent Screen

1. Go to **APIs & Services → OAuth consent screen**
2. User type: **Internal** (if your Google account is in the same org as the workspace you're auditing) — or **External** for testing
3. Fill in:
   - App name: `MailGuard`
   - User support email: your email
   - Developer contact: your email
4. Scopes — click **Add or Remove Scopes** and add:
   - `https://www.googleapis.com/auth/admin.directory.domain.readonly`
   - `https://www.googleapis.com/auth/admin.directory.user.readonly`
   - `https://www.googleapis.com/auth/gmail.settings.basic` (read-only)
5. Save and continue

### 4. Create OAuth 2.0 Credentials

1. Go to **APIs & Services → Credentials → Create Credentials → OAuth client ID**
2. Application type: **Web application**
3. Name: `MailGuard Web`
4. Authorized redirect URIs — add your MailGuard URL:
   - Local: `http://localhost:8000/api/v1/google/callback`
   - Azure: `https://your-app.azurecontainerapps.io/api/v1/google/callback`
5. Click **Create**
6. Copy the **Client ID** and **Client Secret**

### 5. Set Environment Variables

```env
GOOGLE_CLIENT_ID=<your OAuth client ID>
GOOGLE_CLIENT_SECRET=<your OAuth client secret>
GOOGLE_REDIRECT_URI=https://your-app.azurecontainerapps.io/api/v1/google/callback
```

### 6. Authorize in the UI

1. Log into your MailGuard dashboard
2. Click **+ Google Workspace** in the sidebar
3. Complete the Google OAuth flow
4. MailGuard stores the refresh token encrypted in the database **and** backs it up to `/data/gws_tokens.json` on the Azure File Share — it survives container redeployments automatically

---

## Token Persistence

After you authorize GWS once, the encrypted refresh token is:
- Stored in the SQLite database (`/tmp/mailguard.db`)
- Backed up to the Azure File Share at `/data/gws_tokens.json`

On every container restart, `start.py` restores the token from the backup file if the database is empty. You should never need to re-authorize after a deployment.

---

## Troubleshooting

**"Access blocked: This app's request is invalid"** — check that your redirect URI exactly matches what you configured in Google Cloud Console (including `https://` vs `http://`).

**GWS checks return "manual verification required"** — some checks (IMAP/POP, Third-Party OAuth, Alert Center) require additional Admin SDK scopes. These are planned for a future release.

**Token lost after redeploy** — ensure the Azure File Share is correctly mounted at `/data`. Run `.\Setup-Storage.ps1` if needed, then reconnect GWS once.
