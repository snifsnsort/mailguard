#!/usr/bin/env pwsh
#Requires -Version 7
<#
.SYNOPSIS
    Deploys MailGuard to Azure from scratch. One command, no configuration needed.

.DESCRIPTION
    This script does EVERYTHING:
      1. Checks/installs required tools (Docker, Azure CLI)
      2. Logs you into Azure
      3. Creates all Azure resources (Resource Group, Container Registry,
         Container Apps Environment, Container App)
      4. Builds and pushes the Docker image
      5. Deploys the app with correct configuration
      6. Opens the app in your browser

    You need:
      - An Azure subscription
      - Docker Desktop running
      - About 10 minutes

.EXAMPLE
    .\deploy.ps1

.EXAMPLE
    .\deploy.ps1 -Location "westeurope"

.NOTES
    Cost estimate: ~$0/month at low usage (Container Apps scale to zero).
    The only cost is the Container Registry Basic (~$5/month).
#>

[CmdletBinding()]
param(
    [string] $Location      = "eastus",
    [string] $Prefix        = "mailguard",
    [string] $ResourceGroup = "",     # auto-generated if empty
    [switch] $Destroy                 # run with -Destroy to tear everything down
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Step  { param($n, $msg) Write-Host "`nStep $n — $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg)     Write-Host "  ✅ $msg" -ForegroundColor Green }
function Write-Info  { param($msg)     Write-Host "  ℹ️  $msg" -ForegroundColor Gray }
function Write-Fail  { param($msg)     Write-Host "  ❌ $msg" -ForegroundColor Red; exit 1 }

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║           MailGuard — Azure Deployment Script             ║" -ForegroundColor Magenta
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""

# ── Step 1: Check required tools ──────────────────────────────────────────────
Write-Step 1 "Checking required tools..."

# Azure CLI
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Host "  Azure CLI not found. Installing..." -ForegroundColor Yellow
    if ($IsWindows) {
        winget install Microsoft.AzureCLI
    } elseif ($IsMacOS) {
        brew install azure-cli
    } else {
        curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
    }
}
$azVersion = (az version --output json | ConvertFrom-Json).'azure-cli'
Write-Ok "Azure CLI $azVersion"

# Docker
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Fail "Docker not found. Please install Docker Desktop from https://docker.com and try again."
}
try {
    docker info | Out-Null
    Write-Ok "Docker is running"
} catch {
    Write-Fail "Docker is installed but not running. Please start Docker Desktop and try again."
}

# ── Step 2: Azure login ────────────────────────────────────────────────────────
Write-Step 2 "Signing in to Azure..."

$account = az account show --output json 2>$null | ConvertFrom-Json
if (-not $account) {
    Write-Info "Opening browser for Azure login..."
    az login | Out-Null
    $account = az account show --output json | ConvertFrom-Json
}
Write-Ok "Logged in as: $($account.user.name)"
Write-Ok "Subscription: $($account.name) ($($account.id))"

# Let user pick subscription if they have multiple
$subs = az account list --output json | ConvertFrom-Json
if ($subs.Count -gt 1) {
    Write-Host ""
    Write-Host "  You have multiple subscriptions:" -ForegroundColor Yellow
    for ($i = 0; $i -lt $subs.Count; $i++) {
        $marker = if ($subs[$i].isDefault) { "* " } else { "  " }
        Write-Host "  $marker[$($i+1)] $($subs[$i].name)" -ForegroundColor White
    }
    Write-Host ""
    $choice = Read-Host "  Press Enter to use '$($account.name)' or enter a number to switch"
    if ($choice -match '^\d+$') {
        $selected = $subs[[int]$choice - 1]
        az account set --subscription $selected.id
        Write-Ok "Switched to: $($selected.name)"
    }
}

$subscriptionId = (az account show --output json | ConvertFrom-Json).id

# ── Destroy mode ──────────────────────────────────────────────────────────────
if ($Destroy) {
    $rg = if ($ResourceGroup) { $ResourceGroup } else { "${Prefix}-rg" }
    Write-Host "`n⚠️  About to DELETE resource group '$rg' and ALL resources inside it!" -ForegroundColor Red
    $confirm = Read-Host "Type 'yes' to confirm"
    if ($confirm -eq "yes") {
        az group delete --name $rg --yes
        Write-Ok "Resource group '$rg' deleted."
    } else {
        Write-Info "Cancelled."
    }
    exit 0
}

# ── Step 3: Generate unique names ─────────────────────────────────────────────
Write-Step 3 "Generating resource names..."

# Use a short random suffix to avoid name collisions globally
$suffix    = -join ((48..57) + (97..122) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
$rg        = if ($ResourceGroup) { $ResourceGroup } else { "${Prefix}-rg" }
$acrName   = "${Prefix}acr${suffix}"   # must be alphanumeric, globally unique
$envName   = "${Prefix}-env"
$appName   = "${Prefix}-app"
$imageName = "${acrName}.azurecr.io/mailguard:latest"

# Generate secure random keys
$secretKey    = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 64 | ForEach-Object { [char]$_ })
$encKeyBytes  = [byte[]]::new(32)
[Security.Cryptography.RandomNumberGenerator]::Fill($encKeyBytes)
$encKey = [Convert]::ToBase64String($encKeyBytes)

Write-Ok "Resource group : $rg"
Write-Ok "Registry       : $acrName"
Write-Ok "App            : $appName"
Write-Info "Location       : $Location"

# ── Step 4: Create resource group ─────────────────────────────────────────────
Write-Step 4 "Creating Azure resources..."

Write-Info "Resource group..."
az group create --name $rg --location $Location --output none
Write-Ok "Resource group '$rg' ready"

# ── Step 5: Container Registry ────────────────────────────────────────────────
Write-Info "Container Registry (this takes ~1 minute)..."
az acr create --resource-group $rg --name $acrName --sku Basic --admin-enabled true --output none
$acrPassword = (az acr credential show --name $acrName --output json | ConvertFrom-Json).passwords[0].value
Write-Ok "Registry '$acrName' ready"

# ── Step 6: Build and push image ──────────────────────────────────────────────
Write-Step 5 "Building Docker image..."
Write-Info "This takes 3-8 minutes on first build (PowerShell + Exchange module are large)..."

Push-Location $ScriptDir
try {
    docker build -t $imageName .
    if ($LASTEXITCODE -ne 0) { Write-Fail "Docker build failed" }
    Write-Ok "Image built"

    Write-Info "Pushing image to registry..."
    az acr login --name $acrName
    docker push $imageName
    if ($LASTEXITCODE -ne 0) { Write-Fail "Docker push failed" }
    Write-Ok "Image pushed to $acrName"
} finally {
    Pop-Location
}

# ── Step 7: Container Apps Environment ────────────────────────────────────────
Write-Step 6 "Creating Container Apps environment..."

# Log Analytics workspace (required by Container Apps)
$workspaceName = "${Prefix}-logs"
az monitor log-analytics workspace create `
    --resource-group $rg `
    --workspace-name $workspaceName `
    --output none

$workspaceId  = (az monitor log-analytics workspace show --resource-group $rg --workspace-name $workspaceName --output json | ConvertFrom-Json).customerId
$workspaceKey = (az monitor log-analytics workspace get-shared-keys --resource-group $rg --workspace-name $workspaceName --output json | ConvertFrom-Json).primarySharedKey

az containerapp env create `
    --name $envName `
    --resource-group $rg `
    --location $Location `
    --logs-workspace-id $workspaceId `
    --logs-workspace-key $workspaceKey `
    --output none

Write-Ok "Container Apps environment ready"

# ── Step 8: Deploy Container App ──────────────────────────────────────────────
Write-Step 7 "Deploying MailGuard..."

# Create Azure Storage Account for persistent DB
$storageAccount = "${Prefix}store${suffix}"
Write-Info "Creating storage account for persistent database..."
az storage account create `
    --name $storageAccount `
    --resource-group $rg `
    --location $Location `
    --sku Standard_LRS `
    --output none

$storageKey = (az storage account keys list --account-name $storageAccount --resource-group $rg --output json | ConvertFrom-Json)[0].value

# Create file share
az storage share create `
    --name "mailguard-data" `
    --account-name $storageAccount `
    --account-key $storageKey `
    --output none

Write-Ok "Storage account '$storageAccount' ready"

# Link storage to Container Apps environment
az containerapp env storage set `
    --name $envName `
    --resource-group $rg `
    --storage-name "mailguard-storage" `
    --azure-file-account-name $storageAccount `
    --azure-file-account-key $storageKey `
    --azure-file-share-name "mailguard-data" `
    --access-mode ReadWrite `
    --output none

Write-Ok "Storage linked to Container Apps environment"

# Deploy the container app (without volume mount first — CLI limitation)
az containerapp create `
    --name $appName `
    --resource-group $rg `
    --environment $envName `
    --image $imageName `
    --registry-server "${acrName}.azurecr.io" `
    --registry-username $acrName `
    --registry-password $acrPassword `
    --target-port 8000 `
    --ingress external `
    --min-replicas 1 `
    --max-replicas 1 `
    --cpu 0.5 `
    --memory 1Gi `
    --env-vars `
        "DEBUG=false" `
        "ALLOWED_ORIGINS=*" `
        "DATABASE_URL=sqlite:////app/backend/mailguard.db" `
        "SECRET_KEY=$secretKey" `
        "ENCRYPTION_KEY=$encKey" `
    --output none

Write-Ok "Container app created"

# Attach the persistent volume via az rest (CLI doesn't support --volume-mount on create)
Write-Info "Attaching persistent volume to container..."
$volumePatch = @{
    properties = @{
        template = @{
            volumes = @(@{ name = "mailguard-vol"; storageName = "mailguard-storage"; storageType = "AzureFile" })
            containers = @(@{
                name = "mailguard"
                image = $imageName
                volumeMounts = @(@{ mountPath = "/app/backend"; volumeName = "mailguard-vol" })
            })
        }
    }
} | ConvertTo-Json -Depth 10 -Compress

$subId = (az account show --output json | ConvertFrom-Json).id
az rest `
    --method PATCH `
    --uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.App/containerApps/${appName}?api-version=2024-03-01" `
    --headers "Content-Type=application/json" `
    --body $volumePatch `
    --output none

Write-Ok "Persistent volume mounted at /app/backend"
Write-Ok "Container app deployed"

# ── Step 9: Get app URL ────────────────────────────────────────────────────────
Write-Step 8 "Getting app URL..."
$appUrl = "https://" + (az containerapp show --name $appName --resource-group $rg --output json | ConvertFrom-Json).properties.configuration.ingress.fqdn

Write-Info "Waiting for app to start (30 seconds)..."
Start-Sleep 30

# Health check
try {
    $health = Invoke-RestMethod -Uri "$appUrl/api/health" -TimeoutSec 15
    Write-Ok "App is healthy — version $($health.version)"
} catch {
    Write-Host "  ⚠️  Health check failed — app may still be starting. Check manually in 1 minute." -ForegroundColor Yellow
}

# ── Save deployment info ───────────────────────────────────────────────────────
$deployFile = Join-Path $ScriptDir "deployment-info.txt"
@"
MailGuard Deployment Info
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
============================================================
App URL          : $appUrl
Resource Group   : $rg
Container App    : $appName
Registry         : ${acrName}.azurecr.io
Subscription     : $subscriptionId
Location         : $Location

To redeploy after code changes:
  az acr login --name $acrName
  docker build -t $imageName .
  docker push $imageName
  az containerapp update --name $appName --resource-group $rg --image $imageName

To tear everything down:
  .\deploy.ps1 -Destroy

============================================================
"@ | Set-Content -Path $deployFile

# ── Done! ─────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                  🎉  Deployment Complete!                 ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  MailGuard is live at:" -ForegroundColor White
Write-Host "  $appUrl" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Next step — add your first tenant:" -ForegroundColor White
Write-Host "  1. Run .\scripts\Setup-AppRegistration.ps1 in your Microsoft 365 tenant" -ForegroundColor Gray
Write-Host "  2. Open MailGuard and paste the credentials" -ForegroundColor Gray
Write-Host "  3. Run your first scan!" -ForegroundColor Gray
Write-Host ""
Write-Host "  Deployment details saved to: deployment-info.txt" -ForegroundColor Gray
Write-Host ""

# Open browser
if ($IsWindows) { Start-Process $appUrl }
elseif ($IsMacOS) { open $appUrl }
