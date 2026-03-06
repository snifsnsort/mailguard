# 🛡️ MailGuard

**MailGuard scans your Microsoft 365 tenant and tells you exactly how secure your email is — and how to fix any problems.**

It checks things like:
- Are your emails protected from spoofing? (SPF, DKIM, DMARC)
- Do your admins all use two-factor login? (MFA)
- Could attackers bypass your email security gateway?
- Are there fake versions of your domain registered by attackers?

---

## What you need before starting

| Thing | Where to get it | Cost |
|-------|----------------|------|
| An **Azure account** | [portal.azure.com](https://portal.azure.com) | Free to sign up |
| An **Azure subscription** | Inside Azure portal | Pay-as-you-go, ~$5/month |
| **Docker Desktop** | [docker.com/get-started](https://www.docker.com/get-started/) | Free |
| **PowerShell 7** | [aka.ms/PSWindows](https://aka.ms/PSWindows) | Free |
| **Azure CLI** | [aka.ms/installazurecliwindows](https://aka.ms/installazurecliwindows) | Free |

> 💡 **Already have all of these?** Skip straight to [Deploy MailGuard](#part-1--deploy-mailguard-to-azure-10-minutes).

---

## Part 1 — Deploy MailGuard to Azure (~10 minutes)

### Step 1 — Download MailGuard

Click the green **Code** button on this page → **Download ZIP** → unzip it somewhere easy (like your Desktop).

### Step 2 — Open PowerShell 7

- Press **Windows key**, type `pwsh`, press **Enter**
- Navigate to the MailGuard folder:
  ```powershell
  cd "$env:USERPROFILE\Desktop\mailguard"
  ```

### Step 3 — Run the deploy script

```powershell
.\deploy.ps1
```

That's it. The script will:
1. Ask you to sign in to Azure (a browser window opens)
2. Create all the Azure resources automatically
3. Build and upload the app
4. Print the URL when it's ready

☕ **This takes about 10 minutes.** Go make a coffee.

When it's done you'll see:
```
🎉  Deployment Complete!

  MailGuard is live at:
  https://mailguard-app.xxxxxx.eastus.azurecontainerapps.io
```

The URL is also saved to `deployment-info.txt`.

---

## Part 2 — Connect your Microsoft 365 tenant (~5 minutes)

This gives MailGuard read-only access to scan your tenant. **No changes are made — MailGuard only reads settings.**

### Step 1 — Run the setup script

> ⚠️ You must be a **Global Administrator** of the Microsoft 365 tenant you want to scan.

```powershell
.\scripts\Setup-AppRegistration.ps1
```

The script:
1. Opens a browser — sign in with your **M365 admin account**
2. Creates a read-only app registration automatically
3. Grants all required permissions
4. Prints your credentials

When done you'll see:
```
✅  Setup Complete!

  Tenant ID     : 12345678-...
  Domain        : yourcompany.com
  Client ID     : 87654321-...
  Client Secret : AbCdEf~...
```

> ⚠️ **Copy the Client Secret now** — it won't be shown again!

### Step 2 — Add the tenant to MailGuard

1. Open MailGuard (the URL from Part 1)
2. Click **Connect Tenant**
3. Paste in the four values
4. Click **Save**

### Step 3 — Run your first scan

Click **Start Scan** — results appear in about 90 seconds.

---

## Understanding your results

| Score | Grade | Meaning |
|-------|-------|---------|
| 90–100 | A | Excellent |
| 75–89  | B | Good — a few things to tighten |
| 60–74  | C | Fair — real risks present |
| 45–59  | D | Poor — address findings soon |
| 0–44   | F | Critical — act immediately |

### What MailGuard checks

| Check | What it means |
|-------|--------------|
| **SPF** | Prevents other servers from sending email as you |
| **DKIM** | Adds a digital signature so recipients know emails are real |
| **DMARC** | Tells the world what to do with fake emails from your domain |
| **MFA for Admins** | All admin accounts should require two-factor login |
| **Legacy Auth** | Old email protocols attackers exploit — should be blocked |
| **MX Gateway** | Identifies your email security gateway (Proofpoint, Mimecast, etc.) |
| **SEG Bypass Risk** | Checks if attackers can skip your gateway entirely |
| **Lookalike Domains** | Finds registered typosquat domains that look like yours |
| **Safe Links** | Microsoft URL scanner — is it configured? |
| **Safe Attachments** | Microsoft attachment scanner — is it configured? |
| **SMTP Auth** | Legacy email sending — should be disabled if unused |

---

## Updating after code changes

```powershell
cd "$env:USERPROFILE\Desktop\mailguard"
# Your registry name is in deployment-info.txt
az acr login --name <your-registry-name>
docker build -t <your-registry-name>.azurecr.io/mailguard:latest .
docker push <your-registry-name>.azurecr.io/mailguard:latest
az containerapp update --name mailguard-app --resource-group mailguard-rg --image <your-registry-name>.azurecr.io/mailguard:latest
```

---

## Tearing everything down

```powershell
.\deploy.ps1 -Destroy
```

Deletes all Azure resources and stops all costs.

---

## FAQ

**Can MailGuard change anything in my tenant?**
No. Read-only permissions only. It cannot send emails, delete users, or modify settings.

**How much does it cost?**
Mainly the Container Registry (~$5/month). Total at low usage is under $10/month.

**Can I scan multiple tenants?**
Yes — run `Setup-AppRegistration.ps1` in each tenant and add them all.

**The Exchange checks are failing.**
Exchange permissions take up to 15 minutes to propagate. Wait and re-scan.

**How long do results last?**
Results persist until the container restarts. For permanent storage, migrate to PostgreSQL.

---

## Project structure

```
mailguard/
├── deploy.ps1                        ← One-command Azure deployment
├── scripts/
│   └── Setup-AppRegistration.ps1     ← One-command tenant setup
├── backend/
│   └── app/services/
│       ├── scan_engine.py            ← Orchestrates all checks
│       ├── graph_client.py           ← Microsoft Graph API
│       ├── exchange_checker.py       ← Exchange Online PowerShell
│       ├── mx_analyzer.py            ← MX/gateway detection
│       └── lookalike_detector.py     ← Typosquat detection
├── frontend/                         ← React dashboard
└── Dockerfile                        ← Builds the full image
```

---

## Security notes

- Client secrets are encrypted at rest using Fernet symmetric encryption
- Encryption key is randomly generated per deployment
- MailGuard uses minimum required permissions — read-only on everything
- All traffic is HTTPS via Azure Container Apps managed TLS
