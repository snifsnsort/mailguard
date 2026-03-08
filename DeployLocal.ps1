<#
.SYNOPSIS
    MailGuard One-Click Setup – creates a fresh Azure AD app, configures permissions, generates .env, and starts Docker.
.DESCRIPTION
    This script:
    - Checks for prerequisites (PowerShell 5+, winget, Azure CLI) and installs missing components.
    - Logs you into Azure (Global Admin required).
    - Creates an app registration named "MailGuardLocal-DD-MM-YYYY-HH-MM".
    - Adds the exact Microsoft Graph application permissions that made scanning work in your manual test.
    - Grants admin consent automatically (or provides manual URL if needed).
    - Generates a client secret and writes a complete .env file (including SEED_TENANT_NAME).
    - Optionally starts Docker Compose.
    - Optionally cleans up local sensitive files after success.
.NOTES
    Run this from the MailGuard root folder (where docker-compose.yml lives).
    All created credentials are saved to a backup text file.
#>

param(
    [string]$TenantDomain,
    [string]$TenantName,
    [string]$AdminPassword
)

#region ===== Helper Functions =====
function Write-Step {
    param([string]$Message, [string]$Color = "Cyan")
    Write-Host "`n>> $Message" -ForegroundColor $Color
}

function Write-Success {
    param([string]$Message)
    Write-Host "   ✅ $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "   ⚠️  $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "   ❌ $Message" -ForegroundColor Red
    exit 1
}
#endregion

Clear-Host
Write-Host @"

╔══════════════════════════════════════════════════════════════════════════╗
║                     MailGuard One-Click Setup Wizard                     ║
║                         Created by George Mikhailov                      ║
║         Questions? george@cloud4you.ca  |  linkedin.com/in/stayprotected ║
╚══════════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Magenta

#region ===== Prerequisite Checks =====
Write-Step "Checking prerequisites..."

# 1. PowerShell version (5+ required for some modules)
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Error "PowerShell 5 or higher is required. Please upgrade."
} else {
    Write-Success "PowerShell $($PSVersionTable.PSVersion.Major) detected"
}

# 2. winget (for Azure CLI installation)
$winget = Get-Command winget -ErrorAction SilentlyContinue
if (-not $winget) {
    Write-Warning "winget not found – attempting to install App Installer from Microsoft Store..."
    try {
        Start-Process "ms-appinstaller:?source=https://aka.ms/getwinget"
        Write-Host "   Please complete the installation from the Store, then re-run this script." -ForegroundColor Yellow
        exit 1
    } catch {
        Write-Error "Unable to install winget. Please install Azure CLI manually from https://aka.ms/installazurecliwindows"
    }
} else {
    Write-Success "winget found"
}

# 3. Azure CLI
$az = Get-Command az -ErrorAction SilentlyContinue
if (-not $az) {
    Write-Warning "Azure CLI not found. Installing via winget..."
    winget install -e --id Microsoft.AzureCLI --accept-source-agreements
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Azure CLI installation failed. Please install manually from https://aka.ms/installazurecliwindows"
    }
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    $az = Get-Command az -ErrorAction SilentlyContinue
    if (-not $az) {
        Write-Error "Azure CLI still not found. Please restart your terminal and re-run the script."
    }
    Write-Success "Azure CLI installed"
} else {
    Write-Success "Azure CLI found"
}

# 4. Docker (optional – we'll check but not force install)
$docker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $docker) {
    Write-Warning "Docker not found. You'll need to install Docker Desktop manually from https://www.docker.com/products/docker-desktop/"
    $dockerInstalled = $false
} else {
    Write-Success "Docker found"
    $dockerInstalled = $true
}

# 5. Correct folder (docker-compose.yml must exist)
if (-not (Test-Path "docker-compose.yml")) {
    Write-Error "docker-compose.yml not found. Please run this script from the MailGuard root folder."
}
Write-Success "MailGuard root folder detected"
#endregion

#region ===== Gather Inputs =====
Write-Step "Gathering configuration inputs"

if (-not $TenantDomain) {
    $TenantDomain = Read-Host "Enter your Microsoft 365 tenant domain (e.g., contoso.com)"
}
if (-not $TenantName) {
    $TenantName = ($TenantDomain -split '\.')[0]
    $defaultName = $TenantName
    $TenantName = Read-Host "Enter a friendly name for your tenant [$defaultName]"
    if (-not $TenantName) { $TenantName = $defaultName }
}
if (-not $AdminPassword) {
    $securePass = Read-Host "Set MailGuard admin password" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePass)
    $AdminPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
}
#endregion

#region ===== Azure Login & App Creation =====
Write-Step "Logging into Azure (Global Admin required)"
az login --allow-no-subscriptions | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Azure login failed"
}
$tenantInfo = az account show | ConvertFrom-Json
$tenantId = $tenantInfo.tenantId
Write-Success "Connected to tenant: $tenantId"

# Generate unique app name
$appName = "MailGuardLocal-$((Get-Date).ToString('dd-MM-yyyy-HH-mm'))"
$redirectUri = "http://localhost:8000/api/auth/callback"

Write-Step "Creating app registration: $appName"
$app = az ad app create `
    --display-name $appName `
    --sign-in-audience "AzureADMyOrg" `
    --web-redirect-uris $redirectUri `
    --enable-access-token-issuance true `
    --enable-id-token-issuance true | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
    Write-Error "App creation failed"
}
$clientId = $app.appId
$appObjectId = $app.id
Write-Success "App created with Client ID: $clientId"

# Wait a few seconds for Azure to propagate
Start-Sleep -Seconds 5
#endregion

#region ===== Add Application Permissions using temporary file =====
Write-Step "Adding Microsoft Graph application permissions (the exact set that made scanning work)"

# These are the permission IDs that allowed manual scanning in your environment
$appPermissions = @(
    "7ab1d382-f21e-4acd-a863-ba3e13f7da61", # Mail.Read
    "246dd0d5-5bd0-4def-940b-0421030a5b68", # Mail.Send
    "b0afded3-3588-46d8-8b3d-9842eff778da", # Domain.Read.All
    "e1fe6dd8-ba31-4d61-89e7-88639da4683d", # User.Read
    "dbb9058a-0e50-45d7-ae91-66909b5d4664", # Directory.Read.All
    "bac3b9c2-b516-4ef4-bd3b-c2ef73d8d804", # Mail.ReadWrite
    "38d9df27-64da-44fd-b7c5-a6fbac20248f"  # Mail.ReadBasic
)

# Build the required-resource-access structure
$resourceAccess = $appPermissions | ForEach-Object { @{ id = $_; type = "Role" } }
$requiredResourceAccess = @(
    @{
        resourceAppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
        resourceAccess = $resourceAccess
    }
)

# Convert to JSON and save to a temporary file
$tempJsonFile = [System.IO.Path]::GetTempFileName() + ".json"
$requiredResourceAccess | ConvertTo-Json -Depth 10 | Set-Content -Path $tempJsonFile -Encoding utf8

# Use the @ convention to load from file – this bypasses PowerShell quoting issues
az ad app update --id $clientId --required-resource-accesses "@$tempJsonFile"

if ($LASTEXITCODE -ne 0) {
    # Clean up temp file before exiting
    Remove-Item -Path $tempJsonFile -Force -ErrorAction SilentlyContinue
    Write-Error "Failed to add permissions"
}

# Clean up temp file
Remove-Item -Path $tempJsonFile -Force -ErrorAction SilentlyContinue
Write-Success "Permissions added"
#endregion

#region ===== Admin Consent =====
Write-Step "Granting admin consent for your tenant"
az ad app permission admin-consent --id $clientId
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Admin consent may have already been granted or needs manual approval."
    Write-Host "   If this fails, you can manually consent using: https://login.microsoftonline.com/$TenantDomain/adminconsent?client_id=$clientId" -ForegroundColor Yellow
} else {
    Write-Success "Admin consent granted"
}
#endregion

#region ===== Generate Client Secret =====
Write-Step "Generating client secret (valid for 1 year)"
$endDate = (Get-Date).AddYears(1).ToString("yyyy-MM-dd")
$secret = az ad app credential reset `
    --id $clientId `
    --display-name "MailGuard-Secret" `
    --end-date $endDate | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to generate client secret"
}
$clientSecret = $secret.password
Write-Success "Client secret created"
#endregion

#region ===== Generate SECRET_KEY for MailGuard =====
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$secretKey = -join ($bytes | ForEach-Object { $_.ToString("x2") })
#endregion

#region ===== Write .env File =====
Write-Step "Writing .env file to backend\.env"
$envContent = @"
# MailGuard environment – automatically generated
SECRET_KEY=$secretKey
ADMIN_PASSWORD=$AdminPassword
DATABASE_URL=/data/mailguard.db
ALLOWED_ORIGINS=http://localhost:8000,http://127.0.0.1:8000
MULTI_TENANT_MODE=false
DEBUG=true

# Microsoft 365 (seed tenant – auto‑registers on boot)
SEED_TENANT_NAME=$TenantName
SEED_TENANT_ID=$tenantId
SEED_TENANT_DOMAIN=$TenantDomain
SEED_CLIENT_ID=$clientId
SEED_CLIENT_SECRET=$clientSecret
"@

# Ensure backend folder exists
New-Item -ItemType Directory -Force -Path "backend" | Out-Null
Set-Content -Path "backend\.env" -Value $envContent -Encoding ascii
Write-Success ".env file written"
#endregion

#region ===== Save Backup Configuration =====
$configBackup = "MailGuard-config-$((Get-Date).ToString('yyyyMMdd-HHmmss')).txt"
@"
MailGuard Setup Summary
=======================
Generated: $(Get-Date)

Tenant Name   : $TenantName
Tenant Domain : $TenantDomain
Tenant ID     : $tenantId
Client ID     : $clientId
Client Secret : $clientSecret
Admin Password: [hidden]

App Registration Name: $appName
Redirect URI        : $redirectUri

Permissions added (all with type Role):
$($appPermissions -join "`n")
"@ | Out-File -FilePath $configBackup -Encoding ascii
Write-Success "Backup configuration saved to: $configBackup"
#endregion

#region ===== Final Instructions & Docker Start =====
Write-Host @"

╔══════════════════════════════════════════════════════════════════════════╗
║                         MailGuard Setup Complete                         ║
╚══════════════════════════════════════════════════════════════════════════╝

✅ All Azure resources created and configured.
✅ .env file ready.
✅ Admin consent granted (or URL provided).
"@ -ForegroundColor Green

if ($dockerInstalled) {
    $startNow = Read-Host "`nStart MailGuard with Docker Compose now? (y/n)"
    if ($startNow -eq 'y') {
        Write-Step "Starting containers in detached mode..."
        docker compose up --build -d
        
        Write-Step "Waiting 5 seconds for services to initialize..."
        Start-Sleep -Seconds 5
        
        Write-Step "Opening browser to http://localhost:8000"
        Start-Process "http://localhost:8000"
        
        Write-Host "`nContainers are running in the background." -ForegroundColor Green
        Write-Host "To view logs, run: docker compose logs -f app" -ForegroundColor Yellow
    } else {
        Write-Host "`nYou can start MailGuard later with: docker compose up --build" -ForegroundColor Yellow
    }
}

Write-Host "`nAfter starting, open http://localhost:8000 and log in with username 'admin' and the password you provided." -ForegroundColor White
Write-Host "Your tenant will appear automatically – no need to click Connect." -ForegroundColor White

#region ===== Optional Cleanup of Sensitive Files =====
Write-Step "Cleanup"
Write-Host "Local files (backend/.env and MailGuard-config-*.txt) contain secrets." -ForegroundColor Gray
$cleanup = Read-Host "Delete these sensitive files now? (y/n)"
if ($cleanup -eq 'y') {
    $filesRemoved = 0
    if (Test-Path "backend\.env") {
        Remove-Item "backend\.env" -Force
        Write-Success "Deleted backend\.env"
        $filesRemoved++
    }
    Get-ChildItem "MailGuard-config-*.txt" -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-Item $_.FullName -Force
        Write-Success "Deleted $($_.Name)"
        $filesRemoved++
    }
    if ($filesRemoved -eq 0) {
        Write-Host "   No sensitive files found to delete." -ForegroundColor Gray
    }
} else {
    Write-Host "   Skipped – remember to secure them manually." -ForegroundColor Yellow
}
#endregion

Write-Host "`nEnjoy using MailGuard! 🛡️" -ForegroundColor Magenta
#endregion