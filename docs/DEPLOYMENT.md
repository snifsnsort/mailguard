# Deploying MailGuard to Azure

MailGuard deploys to Azure Container Apps with one command. The `deploy.ps1` script handles everything — no manual resource creation, no Azure Portal required.

## Prerequisites

Install these three tools before running the script:

| Tool | Download |
|---|---|
| Docker Desktop | https://docker.com |
| Azure CLI | https://aka.ms/installazurecliwindows |
| PowerShell 7+ | https://aka.ms/powershell |

---

## First-Time Deployment

```powershell
git clone https://github.com/snifsnsort/mailguard.git
cd mailguard
.\deploy.ps1
```

The script will:
1. Sign you into Azure (opens browser)
2. Let you pick your subscription
3. Ask for a dashboard password
4. Ask whether to create the M365 App Registration automatically or use existing credentials
5. Create all Azure resources (Resource Group, Container Registry, Container Apps Environment, Storage Account)
6. Build and push the Docker image
7. Deploy the app with all environment variables configured
8. Mount persistent storage at `/data` for GWS token backup
9. Run a health check
10. Open MailGuard in your browser

**Total time: approximately 10-15 minutes** (most of that is the Docker build on first run).

---

## Updating After Code Changes

Every time you pull new code from GitHub:

```powershell
cd mailguard
.\update.ps1
```

No configuration needed — `update.ps1` reads `deployment-info.json` saved by `deploy.ps1` and knows exactly where to deploy.

---

## Setting Up the M365 App Registration

If you chose to skip M365 setup during deployment, run this separately:

```powershell
.\scripts\Setup-AppRegistration.ps1
```

This creates an Azure AD App Registration in your Microsoft 365 tenant with all required permissions and prints the credentials to paste into MailGuard.

Requires: Global Administrator in your M365 tenant.

---

## Connecting Google Workspace

After deployment:
1. Log into MailGuard
2. Click **+ Google Workspace** in the sidebar
3. Complete the OAuth flow in your browser

The GWS refresh token is encrypted and backed up to the persistent Azure File Share at `/data/gws_tokens.json`. It survives all future `.\update.ps1` deployments automatically.

---

## Tearing Down

To delete all Azure resources:

```powershell
.\deploy.ps1 -Destroy
```

---

## Deploying to a Different Azure Region

```powershell
.\deploy.ps1 -Location "westeurope"
```

Available locations: `eastus`, `westeurope`, `australiaeast`, `uksouth`, `canadacentral`, etc.

---

## Troubleshooting

**Docker build fails** — Make sure Docker Desktop is running before running the script.

**Azure login fails** — Run `az login` manually first, then re-run `.\deploy.ps1`.

**App starts but M365 scan fails** — Exchange permissions can take up to 15 minutes to propagate after the App Registration is created. Wait and try again.

**GWS token lost after update** — This shouldn't happen — the token is backed up to Azure File Share. If it does happen, reconnect GWS once from the dashboard. It will persist from that point forward.

**Health check fails** — The app may still be warming up. Wait 60 seconds and visit the URL manually.
