# Deploying MailGuard to Azure Container Apps

This guide covers a full deployment of MailGuard on Azure Container Apps with persistent storage for the GWS token backup.

## Prerequisites

- Azure CLI installed and logged in (`az login`)
- Docker Desktop installed
- PowerShell 7+ (Windows) or pwsh (macOS/Linux)
- An Azure subscription
- An Azure Container Registry (ACR) — or create one below

---

## First-Time Setup

### 1. Create Azure resources (one time)

```powershell
# Variables — update these
$RG       = "mailguard-rg"
$LOCATION = "eastus"
$ACR      = "mailguardacr"     # must be globally unique
$ENV      = "mailguard-env"
$APP      = "mailguard-app"

# Resource group
az group create --name $RG --location $LOCATION

# Container Registry
az acr create --name $ACR --resource-group $RG --sku Basic --admin-enabled true

# Container Apps environment
az containerapp env create --name $ENV --resource-group $RG --location $LOCATION
```

### 2. Set up persistent storage

Run this **once** to create the Azure File Share that stores `gws_tokens.json`:

```powershell
.\Setup-Storage.ps1
```

This creates a Storage Account, file share, and links it to the Container Apps environment at `/data`.

### 3. Create the Container App with environment variables

```powershell
az containerapp create `
  --name $APP `
  --resource-group $RG `
  --environment $ENV `
  --image mcr.microsoft.com/azuredocs/containerapps-helloworld:latest `
  --target-port 8000 `
  --ingress external `
  --env-vars `
    SECRET_KEY="your-random-secret" `
    ADMIN_PASSWORD="YourPassword123" `
    SEED_TENANT_DOMAIN="yourdomain.com" `
    SEED_TENANT_ID="<azure-tenant-id>" `
    SEED_CLIENT_ID="<app-client-id>" `
    SEED_CLIENT_SECRET="<app-client-secret>"
```

### 4. Deploy the application

```powershell
.\Build-And-Deploy.ps1
```

---

## Ongoing Deployments

Every time you update the code:

```powershell
.\Build-And-Deploy.ps1
```

This will:
1. Build the Docker image with a timestamp tag
2. Push it to ACR
3. Deactivate the old revision
4. Update the Container App to use the new image

---

## Environment Variables Reference

Set these in the Azure Portal under **Container App → Environment variables** or pass them in the `az containerapp create` command.

| Variable | Description |
|---|---|
| `SECRET_KEY` | Long random string used for JWT signing and GWS token encryption |
| `ADMIN_PASSWORD` | Login password for the `admin` account |
| `SEED_TENANT_DOMAIN` | Your M365 domain (e.g. `contoso.com`) |
| `SEED_TENANT_ID` | Azure AD tenant GUID |
| `SEED_CLIENT_ID` | App Registration client ID |
| `SEED_CLIENT_SECRET` | App Registration client secret |
| `MULTI_TENANT_MODE` | Set to `true` to enable multiple tenant management |

---

## Updating Environment Variables

In the Azure Portal:
1. Go to **Container Apps → mailguard-app → Containers**
2. Click **Edit and deploy**
3. Click the container name
4. Edit environment variables
5. Save and deploy

Or via CLI:
```powershell
az containerapp update `
  --name mailguard-app `
  --resource-group mailguard-rg `
  --set-env-vars "ADMIN_PASSWORD=NewPassword123"
```

---

## Viewing Logs

```powershell
az containerapp logs show `
  --name mailguard-app `
  --resource-group mailguard-rg `
  --follow
```

---

## Troubleshooting

**Container won't start:** Check logs with the command above. Common causes:
- Missing required environment variable
- Database lock (shouldn't happen — DB is on `/tmp`)
- Azure File Share not mounted

**GWS token lost after deploy:** The token is backed up to `/data/gws_tokens.json` on the Azure File Share. If the volume isn't mounted, run `.\Setup-Storage.ps1` again. After mounting, reconnect GWS once through the UI.

**Old revision still running:** `Build-And-Deploy.ps1` deactivates old revisions automatically. If you see two active revisions manually deactivate the old one:
```powershell
az containerapp revision list --name mailguard-app --resource-group mailguard-rg -o table
az containerapp revision deactivate --name mailguard-app --resource-group mailguard-rg --revision <revision-name>
```
