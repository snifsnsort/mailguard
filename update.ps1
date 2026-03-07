#Requires -Version 7
<#
.SYNOPSIS
    Redeploys MailGuard after code changes. No configuration needed.

.DESCRIPTION
    Reads deployment-info.json saved by deploy.ps1, builds a new Docker image,
    pushes it, and updates the running Container App.

    Run this every time you pull new code from GitHub.

.EXAMPLE
    .\update.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Header { param($msg) Write-Host ""; Write-Host "  ── $msg" -ForegroundColor Cyan }
function Write-Ok   { param($msg) Write-Host "  ✅  $msg" -ForegroundColor Green }
function Write-Info { param($msg) Write-Host "  →   $msg" -ForegroundColor Gray }
function Write-Fail { param($msg) Write-Host "  ❌  $msg" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "  ║            MailGuard  —  Update & Redeploy            ║" -ForegroundColor Magenta
Write-Host "  ╚═══════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""

# ── Load deployment info ──────────────────────────────────────────────────────
$deployFile = Join-Path $ScriptDir "deployment-info.json"
if (-not (Test-Path $deployFile)) {
    Write-Fail "deployment-info.json not found. Run .\deploy.ps1 first."
}

$info    = Get-Content $deployFile | ConvertFrom-Json
$appName = $info.appName
$rg      = $info.resourceGroup
$acrName = $info.acrName

Write-Ok "Loaded deployment info"
Write-Info "App      : $appName"
Write-Info "Registry : $acrName"
Write-Info "URL      : $($info.appUrl)"

# ── Build new image ───────────────────────────────────────────────────────────
Write-Header "Building new Docker image..."

$tag      = Get-Date -Format "yyyyMMdd-HHmm"
$image    = "${acrName}.azurecr.io/mailguard:${tag}"
$imageLatest = "${acrName}.azurecr.io/mailguard:latest"

Push-Location $ScriptDir
try {
    docker build -t $image -t $imageLatest . --quiet
    if ($LASTEXITCODE -ne 0) { Write-Fail "Docker build failed" }
    Write-Ok "Image built: $tag"
} finally {
    Pop-Location
}

# ── Push to registry ──────────────────────────────────────────────────────────
Write-Header "Pushing to registry..."

az acr login --name $acrName --output none
docker push $image --quiet
if ($LASTEXITCODE -ne 0) { Write-Fail "Docker push failed" }
docker push $imageLatest --quiet
Write-Ok "Image pushed"

# ── Deactivate old revisions (prevents DB file lock) ──────────────────────────
Write-Header "Deactivating old revisions..."

$activeRevs = az containerapp revision list `
    --name $appName --resource-group $rg `
    --query "[?properties.active].name" -o tsv

$revsToStop = ($activeRevs -split "`n") | Where-Object { $_.Trim() }
foreach ($rev in $revsToStop) {
    az containerapp revision deactivate `
        --name $appName --resource-group $rg `
        --revision $rev.Trim() --output none 2>$null
    Write-Ok "Deactivated $($rev.Trim())"
}

if ($revsToStop) {
    Write-Info "Waiting for old revisions to stop..."
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 4
        $stillRunning = az containerapp revision list `
            --name $appName --resource-group $rg `
            --query "[?properties.active && properties.runningState=='Running'].name" -o tsv
        $stillRunning = ($stillRunning -split "`n") | Where-Object { $_.Trim() }
        if (-not $stillRunning) { Write-Ok "All old revisions stopped"; break }
        Write-Info "  Still stopping: $($stillRunning -join ', ')..."
    }
    Start-Sleep -Seconds 5
}

# ── Update to new image ───────────────────────────────────────────────────────
Write-Header "Deploying new image..."

az containerapp update `
    --name $appName `
    --resource-group $rg `
    --image $image `
    --output none
if ($LASTEXITCODE -ne 0) { Write-Fail "az containerapp update failed" }
Write-Ok "Update submitted"

# ── Wait for new revision ─────────────────────────────────────────────────────
Write-Info "Waiting for new revision to start..."
$deadline = (Get-Date).AddMinutes(4)
$newRev = $null
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 8
    $revs = az containerapp revision list `
        --name $appName --resource-group $rg `
        --query "[].{name:name,state:properties.runningState,image:properties.template.containers[0].image}" `
        | ConvertFrom-Json
    $newRev = $revs | Where-Object { $_.image -eq $image } | Select-Object -First 1
    if ($newRev) {
        Write-Info "  Revision $($newRev.name): $($newRev.state)"
        if ($newRev.state -in @("Running","RunningAtMaxScale")) { break }
        if ($newRev.state -in @("Failed","Stopped")) { Write-Fail "New revision failed — check Azure Portal logs" }
    }
}
if (-not $newRev -or $newRev.state -notin @("Running","RunningAtMaxScale")) {
    Write-Fail "Revision did not reach Running state — check Azure Portal"
}
Write-Ok "Revision $($newRev.name) is running"

# ── Health check ──────────────────────────────────────────────────────────────
Write-Header "Health check..."
Start-Sleep -Seconds 5
$appUrl = $info.appUrl
for ($i = 1; $i -le 5; $i++) {
    try {
        $health = Invoke-RestMethod -Uri "$appUrl/api/health" -TimeoutSec 15
        Write-Ok "Health check passed"
        break
    } catch {
        if ($i -lt 5) { Write-Info "Attempt $i/5 — retrying in 10s..."; Start-Sleep 10 }
        else { Write-Host "  ⚠️  Health check timed out — app may still be warming up." -ForegroundColor Yellow }
    }
}

# ── Update deployment-info.json ───────────────────────────────────────────────
$info.deployedAt = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
$info | ConvertTo-Json | Set-Content -Path $deployFile

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║              ✅  Update Complete!                     ║" -ForegroundColor Green
Write-Host "  ╚═══════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  $appUrl" -ForegroundColor Yellow
Write-Host ""
