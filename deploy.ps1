#Requires -Version 7
<#
.SYNOPSIS
    One-command deployment of MailGuard to your Azure environment.

.DESCRIPTION
    Deploys a fully configured MailGuard instance to Azure Container Apps.
    Handles everything — Azure resources, Docker build, persistent storage,
    M365 App Registration, and app configuration.

    Prerequisites:
      - Docker Desktop (running)            https://docker.com
      - Azure CLI                           https://aka.ms/installazurecliwindows
      - PowerShell 7+                       https://aka.ms/powershell

    Usage:
      .\deploy.ps1

.EXAMPLE
    .\deploy.ps1
    .\deploy.ps1 -Location "westeurope"
    .\deploy.ps1 -Destroy
#>

[CmdletBinding()]
param(
    [string] $Location = "eastus",
    [switch] $Destroy
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Header { param($msg)
    Write-Host ""
    Write-Host "  ── $msg" -ForegroundColor Cyan }
function Write-Ok   { param($msg) Write-Host "  ✅  $msg" -ForegroundColor Green }
function Write-Info { param($msg) Write-Host "  →   $msg" -ForegroundColor Gray }
function Write-Warn { param($msg) Write-Host "  ⚠️   $msg" -ForegroundColor Yellow }
function Write-Fail { param($msg) Write-Host "  ❌  $msg" -ForegroundColor Red; exit 1 }

function Wait-ForRevision {
    param($AppName, $RG, $ExpectedImage, [int]$TimeoutSeconds = 240)
    Write-Info "Waiting for new revision to start (up to $($TimeoutSeconds/60) min)..."
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 8
        $revs = az containerapp revision list `
            --name $AppName --resource-group $RG `
            --query "[].{name:name,state:properties.runningState,image:properties.template.containers[0].image}" `
            | ConvertFrom-Json
        $target = $revs | Where-Object { $_.image -eq $ExpectedImage } | Select-Object -First 1
        if ($target) {
            Write-Info "  Revision $($target.name): $($target.state)"
            if ($target.state -in @("Running","RunningAtMaxScale")) { return $target }
            if ($target.state -in @("Failed","Stopped")) { Write-Fail "Revision failed — check Azure Portal logs" }
        }
    }
    Write-Fail "Revision did not reach Running state within $($TimeoutSeconds/60) minutes"
}

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "  ║          MailGuard  —  Azure Deployment               ║" -ForegroundColor Magenta
Write-Host "  ╚═══════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""

# ── Step 1: Prerequisites ──────────────────────────────────────────────────────
Write-Header "Checking prerequisites..."

# Docker
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Fail "Docker not found. Install Docker Desktop from https://docker.com and try again."
}
try { docker info 2>&1 | Out-Null; Write-Ok "Docker is running" }
catch { Write-Fail "Docker is installed but not running. Start Docker Desktop and try again." }

# Azure CLI
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Fail "Azure CLI not found. Install from https://aka.ms/installazurecliwindows and try again."
}
$azVer = (az version --output json | ConvertFrom-Json).'azure-cli'
Write-Ok "Azure CLI $azVer"

# Dockerfile present
if (-not (Test-Path (Join-Path $ScriptDir "Dockerfile"))) {
    Write-Fail "Dockerfile not found. Run this script from the mailguard project root."
}
Write-Ok "Running from mailguard project root"

# ── Step 2: Azure login ────────────────────────────────────────────────────────
Write-Header "Signing in to Azure..."

$account = az account show --output json 2>$null | ConvertFrom-Json
if (-not $account) {
    Write-Info "Opening browser for Azure login..."
    az login --output none
    $account = az account show --output json | ConvertFrom-Json
}
Write-Ok "Signed in as: $($account.user.name)"

# Subscription selector
$subs = az account list --output json | ConvertFrom-Json
if ($subs.Count -gt 1) {
    Write-Host ""
    Write-Host "  Available subscriptions:" -ForegroundColor White
    for ($i = 0; $i -lt $subs.Count; $i++) {
        $marker = if ($subs[$i].isDefault) { "* " } else { "  " }
        Write-Host ("  {0}[{1}] {2}" -f $marker, ($i+1), $subs[$i].name) -ForegroundColor White
    }
    Write-Host ""
    $choice = Read-Host "  Press Enter to use '$($account.name)' or enter a number to switch"
    if ($choice -match '^\d+$') {
        $selected = $subs[[int]$choice - 1]
        az account set --subscription $selected.id --output none
        $account = az account show --output json | ConvertFrom-Json
        Write-Ok "Switched to: $($account.name)"
    }
}

$subscriptionId = $account.id
Write-Ok "Subscription: $($account.name) ($subscriptionId)"

# ── Destroy mode ──────────────────────────────────────────────────────────────
if ($Destroy) {
    $deployFile = Join-Path $ScriptDir "deployment-info.json"
    if (Test-Path $deployFile) {
        $info = Get-Content $deployFile | ConvertFrom-Json
        $rg = $info.resourceGroup
    } else {
        $rg = Read-Host "Enter the resource group name to delete"
    }
    Write-Host ""
    Write-Host "  ⚠️  About to DELETE resource group '$rg' and ALL resources in it!" -ForegroundColor Red
    $confirm = Read-Host "  Type 'yes' to confirm"
    if ($confirm -eq "yes") {
        az group delete --name $rg --yes --output none
        Write-Ok "Resource group '$rg' deleted"
        if (Test-Path $deployFile) { Remove-Item $deployFile }
    } else {
        Write-Info "Cancelled."
    }
    exit 0
}

# ── Step 3: Collect configuration ─────────────────────────────────────────────
Write-Header "Configuration..."
Write-Host ""
Write-Host "  MailGuard needs a few details to get started." -ForegroundColor White
Write-Host "  Press Enter to accept defaults shown in [brackets]." -ForegroundColor Gray
Write-Host ""

# Admin password
do {
    $adminPass = Read-Host "  MailGuard dashboard password (min 8 chars)"
    if ($adminPass.Length -lt 8) { Write-Warn "Password must be at least 8 characters" }
} while ($adminPass.Length -lt 8)

# Azure location
$locationInput = Read-Host "  Azure region [eastus]"
if ($locationInput) { $Location = $locationInput }

Write-Host ""
Write-Host "  ── Microsoft 365 Tenant Setup ──" -ForegroundColor Cyan
Write-Host ""
Write-Host "  MailGuard needs an Azure App Registration to audit your M365 tenant." -ForegroundColor White
Write-Host "  [1] Create one automatically (requires Global Admin in your M365 tenant)" -ForegroundColor White
Write-Host "  [2] I already have credentials — I'll paste them in" -ForegroundColor White
Write-Host "  [3] Skip for now — add a tenant from the MailGuard dashboard later" -ForegroundColor White
Write-Host ""
$m365Choice = Read-Host "  Your choice [1/2/3]"

$seedTenantName   = ""
$seedTenantId     = ""
$seedTenantDomain = ""
$seedClientId     = ""
$seedClientSecret = ""

switch ($m365Choice) {
    "1" {
        Write-Header "Creating M365 App Registration automatically..."
        Write-Host ""
        Write-Info "You'll need to sign in with a Global Admin account for your M365 tenant."
        Write-Info "This may be a different account than your Azure subscription."
        Write-Host ""
        Read-Host "  Press Enter when ready"

        # Run the App Registration script
        $appRegScript = Join-Path $ScriptDir "scripts\Setup-AppRegistration.ps1"
        if (-not (Test-Path $appRegScript)) {
            Write-Warn "Setup-AppRegistration.ps1 not found — switching to manual entry"
            $m365Choice = "2"
        } else {
            & $appRegScript
            Write-Host ""
            Write-Info "Copy the credentials printed above, then continue below."
            Write-Host ""
            $seedTenantName   = Read-Host "  Tenant name (e.g. Contoso)"
            $seedTenantDomain = Read-Host "  Domain (e.g. contoso.com)"
            $seedTenantId     = Read-Host "  Tenant ID"
            $seedClientId     = Read-Host "  Client ID"
            $seedClientSecureString = Read-Host "  Client Secret" -AsSecureString
            $seedClientSecret = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($seedClientSecureString))
        }
    }
    "2" {
        Write-Host ""
        Write-Info "Run scripts\Setup-AppRegistration.ps1 first if you haven't already."
        Write-Host ""
        $seedTenantName   = Read-Host "  Tenant name (e.g. Contoso)"
        $seedTenantDomain = Read-Host "  Domain (e.g. contoso.com)"
        $seedTenantId     = Read-Host "  Tenant ID"
        $seedClientId     = Read-Host "  Client ID"
        $seedClientSecureString = Read-Host "  Client Secret" -AsSecureString
        $seedClientSecret = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($seedClientSecureString))
    }
    default {
        Write-Info "Skipping M365 setup — add a tenant from the dashboard after deployment."
    }
}

# ── Step 4: Generate resource names ───────────────────────────────────────────
Write-Header "Generating Azure resource names..."

$suffix      = -join ((48..57) + (97..122) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
$rg          = "mailguard-rg"
$acrName     = "mailguardacr$suffix"
$envName     = "mailguard-env"
$appName     = "mailguard-app"
$storageName = "mailguardst$suffix"
$logName     = "mailguard-logs"
$image       = "${acrName}.azurecr.io/mailguard:latest"

# Generate secure random keys
$secretKey   = -join ((48..57)+(65..90)+(97..122) | Get-Random -Count 64 | ForEach-Object {[char]$_})
$encKeyBytes = [byte[]]::new(32)
[Security.Cryptography.RandomNumberGenerator]::Fill($encKeyBytes)
$encKey = [Convert]::ToBase64String($encKeyBytes)

Write-Ok "Resource Group : $rg"
Write-Ok "Registry       : $acrName"
Write-Ok "Storage        : $storageName"
Write-Ok "App            : $appName"
Write-Ok "Location       : $Location"

# ── Step 5: Create Azure resources ────────────────────────────────────────────
Write-Header "Creating Azure resources (this takes ~3 minutes)..."

# Resource Group
Write-Info "Resource group..."
az group create --name $rg --location $Location --output none
Write-Ok "Resource group '$rg'"

# Container Registry
Write-Info "Container Registry..."
az acr create --resource-group $rg --name $acrName --sku Basic --admin-enabled true --output none
$acrPassword = (az acr credential show --name $acrName --output json | ConvertFrom-Json).passwords[0].value
Write-Ok "Registry '$acrName'"

# Log Analytics (required by Container Apps)
Write-Info "Log Analytics workspace..."
az monitor log-analytics workspace create `
    --resource-group $rg `
    --workspace-name $logName `
    --output none
$workspaceId  = (az monitor log-analytics workspace show `
    --resource-group $rg --workspace-name $logName `
    --output json | ConvertFrom-Json).customerId
$workspaceKey = (az monitor log-analytics workspace get-shared-keys `
    --resource-group $rg --workspace-name $logName `
    --output json | ConvertFrom-Json).primarySharedKey
Write-Ok "Log Analytics workspace"

# Container Apps Environment
Write-Info "Container Apps environment..."
az containerapp env create `
    --name $envName `
    --resource-group $rg `
    --location $Location `
    --logs-workspace-id $workspaceId `
    --logs-workspace-key $workspaceKey `
    --output none
Write-Ok "Container Apps environment '$envName'"

# Storage Account + File Share (for GWS token persistence)
Write-Info "Storage account..."
az storage account create `
    --name $storageName `
    --resource-group $rg `
    --location $Location `
    --sku Standard_LRS `
    --output none
$storageKey = (az storage account keys list `
    --account-name $storageName `
    --resource-group $rg `
    --output json | ConvertFrom-Json)[0].value

az storage share create `
    --name "mailguard-data" `
    --account-name $storageName `
    --account-key $storageKey `
    --output none

az containerapp env storage set `
    --name $envName `
    --resource-group $rg `
    --storage-name "mailguard-storage" `
    --azure-file-account-name $storageName `
    --azure-file-account-key $storageKey `
    --azure-file-share-name "mailguard-data" `
    --access-mode ReadWrite `
    --output none
Write-Ok "Persistent storage configured"

# ── Step 6: Build and push Docker image ───────────────────────────────────────
Write-Header "Building Docker image (3-8 minutes on first build)..."

Push-Location $ScriptDir
try {
    docker build -t $image . --quiet
    if ($LASTEXITCODE -ne 0) { Write-Fail "Docker build failed" }
    Write-Ok "Image built"

    Write-Info "Pushing to registry..."
    az acr login --name $acrName --output none
    docker push $image --quiet
    if ($LASTEXITCODE -ne 0) { Write-Fail "Docker push failed" }
    Write-Ok "Image pushed to $acrName"
} finally {
    Pop-Location
}

# ── Step 7: Deploy Container App ──────────────────────────────────────────────
Write-Header "Deploying MailGuard..."

# Build env vars list dynamically
$envVars = @(
    "DEBUG=false",
    "ALLOWED_ORIGINS=*",
    "SECRET_KEY=$secretKey",
    "ENCRYPTION_KEY=$encKey",
    "ADMIN_PASSWORD=$adminPass"
)

if ($seedTenantDomain) {
    $envVars += @(
        "SEED_TENANT_NAME=$seedTenantName",
        "SEED_TENANT_DOMAIN=$seedTenantDomain",
        "SEED_TENANT_ID=$seedTenantId",
        "SEED_CLIENT_ID=$seedClientId",
        "SEED_CLIENT_SECRET=$seedClientSecret"
    )
}

Write-Info "Creating container app..."
az containerapp create `
    --name $appName `
    --resource-group $rg `
    --environment $envName `
    --image $image `
    --registry-server "${acrName}.azurecr.io" `
    --registry-username $acrName `
    --registry-password $acrPassword `
    --target-port 8000 `
    --ingress external `
    --min-replicas 1 `
    --max-replicas 1 `
    --cpu 0.5 `
    --memory 1Gi `
    --env-vars $envVars `
    --output none
Write-Ok "Container app created"

# Attach /data volume mount (az containerapp create has no --volume-mount flag)
Write-Info "Attaching persistent /data volume..."
$patchBody = @{
    properties = @{
        template = @{
            volumes   = @(@{ name = "mailguard-vol"; storageName = "mailguard-storage"; storageType = "AzureFile" })
            containers = @(@{
                name         = "mailguard"
                image        = $image
                volumeMounts = @(@{ mountPath = "/data"; volumeName = "mailguard-vol" })
            })
        }
    }
} | ConvertTo-Json -Depth 10 -Compress

az rest `
    --method PATCH `
    --uri "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$rg/providers/Microsoft.App/containerApps/${appName}?api-version=2024-03-01" `
    --headers "Content-Type=application/json" `
    --body $patchBody `
    --output none
Write-Ok "Persistent /data volume mounted"

# ── Step 8: Wait for app to start ─────────────────────────────────────────────
Write-Header "Waiting for MailGuard to start..."
Wait-ForRevision -AppName $appName -RG $rg -ExpectedImage $image | Out-Null
Write-Ok "MailGuard is running"

# ── Step 9: Health check ───────────────────────────────────────────────────────
$fqdn   = (az containerapp show --name $appName --resource-group $rg `
    --query "properties.configuration.ingress.fqdn" -o tsv)
$appUrl = "https://$fqdn"

Write-Info "Running health check..."
Start-Sleep -Seconds 5
$healthy = $false
for ($i = 1; $i -le 5; $i++) {
    try {
        $health = Invoke-RestMethod -Uri "$appUrl/api/health" -TimeoutSec 15
        Write-Ok "Health check passed"
        $healthy = $true
        break
    } catch {
        if ($i -lt 5) { Write-Info "Attempt $i/5 — retrying in 10s..."; Start-Sleep 10 }
    }
}
if (-not $healthy) {
    Write-Warn "Health check didn't respond yet — app may still be warming up. Check manually."
}

# ── Step 10: Save deployment info ─────────────────────────────────────────────
$deployInfo = @{
    appName       = $appName
    resourceGroup = $rg
    acrName       = $acrName
    acrServer     = "${acrName}.azurecr.io"
    imageName     = "mailguard"
    appUrl        = $appUrl
    location      = $Location
    subscriptionId= $subscriptionId
    deployedAt    = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
}
$deployFile = Join-Path $ScriptDir "deployment-info.json"
$deployInfo | ConvertTo-Json | Set-Content -Path $deployFile
Write-Ok "Deployment info saved to deployment-info.json"

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║              🎉  Deployment Complete!                 ║" -ForegroundColor Green
Write-Host "  ╚═══════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  MailGuard is live at:" -ForegroundColor White
Write-Host "  $appUrl" -ForegroundColor Yellow
Write-Host ""
if (-not $seedTenantDomain) {
    Write-Host "  Next step — connect your M365 tenant:" -ForegroundColor White
    Write-Host "  1. Run .\scripts\Setup-AppRegistration.ps1" -ForegroundColor Gray
    Write-Host "  2. Add the tenant from the MailGuard dashboard" -ForegroundColor Gray
    Write-Host ""
}
Write-Host "  To redeploy after code changes:" -ForegroundColor White
Write-Host "  .\update.ps1" -ForegroundColor Yellow
Write-Host ""
Write-Host "  To tear everything down:" -ForegroundColor White
Write-Host "  .\deploy.ps1 -Destroy" -ForegroundColor Gray
Write-Host ""

# Open browser
if ($IsWindows) { Start-Process $appUrl }
elseif ($IsMacOS) { open $appUrl }
elseif ($IsLinux) { xdg-open $appUrl 2>$null }
