# Build-And-Deploy.ps1
# Run from the mailguard directory (where Dockerfile lives)
# Usage: .\Build-And-Deploy.ps1

$ACR      = "mailguardacr7842.azurecr.io"
$IMAGE    = "$ACR/mailguard"
$APP      = "mailguard-app"
$RG       = "mailguard-rg"
$TAG      = (Get-Date -Format "yyyyMMdd-HHmm")
$FULLIMG  = "${IMAGE}:${TAG}"

function Pass($msg) { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "  [!!] $msg" -ForegroundColor Red; exit 1 }
function Info($msg) { Write-Host "  --> $msg" -ForegroundColor Cyan }

Write-Host "`n=== MailGuard Build + Deploy ===" -ForegroundColor Cyan
Write-Host "  Tag: $TAG"
Write-Host "  Image: $FULLIMG"

# 1. Confirm we are in the right directory
if (-not (Test-Path "Dockerfile")) { Fail "Dockerfile not found — run this from the mailguard root directory" }
Pass "Working directory confirmed"

# 2. Confirm index.css has the new muted color (quick sanity check before wasting build time)
$css = Get-Content "frontend\src\index.css" -Raw
if ($css -match "--muted: #8ba4be") { Pass "index.css has updated muted color #8ba4be" }
else { Fail "index.css still has OLD muted color — extract mailguard-full.zip first and re-run" }

# 3. Confirm Dashboard.jsx has 2-column grid not 3-column
$dash = Get-Content "frontend\src\pages\Dashboard.jsx" -Raw
if ($dash -match "240px 1fr'") { Pass "Dashboard.jsx has correct 2-column grid" }
elseif ($dash -match "240px 1fr 260px") { Fail "Dashboard.jsx still has OLD 3-column grid — extract mailguard-full.zip first" }
else { Pass "Dashboard.jsx grid looks updated" }

# 3a. LookalikeScan sort
$ls = Get-Content "frontend\src\pages\LookalikeScan.jsx" -Raw -ErrorAction SilentlyContinue
if (-not $ls)               { Fail "LookalikeScan.jsx missing — extract mailguard-full.zip first" }
elseif ($ls -match "RISK_ORDER") { Pass "LookalikeScan.jsx sort (RISK_ORDER) present" }
else                        { Fail "LookalikeScan.jsx missing RISK_ORDER sort — extract mailguard-full.zip" }

# 3b. Stable encryption key
$sec = Get-Content "backend\app\core\security.py" -Raw -ErrorAction SilentlyContinue
if ($sec -match "sha256")   { Pass "security.py stable key derivation (sha256) present" }
else                        { Fail "security.py missing sha256 key — extract mailguard-full.zip" }

# 3c. GWS token backup
$ga = Get-Content "backend\app\api\google_auth.py" -Raw -ErrorAction SilentlyContinue
if ($ga -match "_backup_gws_token") { Pass "google_auth.py GWS token backup present" }
else                        { Fail "google_auth.py missing _backup_gws_token — extract mailguard-full.zip" }

# 3d. GWS restore on boot
$st = Get-Content "backend\start.py" -Raw -ErrorAction SilentlyContinue
if ($st -match "restore_gws_tokens") { Pass "start.py GWS restore on boot present" }
else                        { Fail "start.py missing restore_gws_tokens — extract mailguard-full.zip" }

# 3e. Database path (must be local /tmp, not SMB mount)
$cfg = Get-Content "backend\app\core\config.py" -Raw -ErrorAction SilentlyContinue
if ($cfg -match "sqlite:////tmp/mailguard.db") { Pass "config.py DATABASE_URL in local /tmp (not SMB — avoids file locking)" }
else                        { Fail "config.py DATABASE_URL incorrect — extract mailguard-full.zip" }

# 3f. Verify script is current
$vf = Get-Content "Verify-Mailguard.ps1" -Raw -ErrorAction SilentlyContinue
if ($vf -match "Files scanned") { Pass "Verify-Mailguard.ps1 is current (has file scan counter)" }
else                        { Fail "Verify-Mailguard.ps1 is outdated — extract mailguard-full.zip" }

# 3g. Setup-Storage.ps1 is present
if (Test-Path "Setup-Storage.ps1") { Pass "Setup-Storage.ps1 present" }
else                               { Fail "Setup-Storage.ps1 missing — extract mailguard-full.zip" }

# 4. Delete any existing frontend/dist to ensure no stale build sneaks in
if (Test-Path "frontend\dist") {
    Remove-Item -Recurse -Force "frontend\dist"
    Pass "Deleted stale frontend/dist"
} else {
    Pass "No stale frontend/dist present"
}

# 5. Build with unique tag (bypasses any layer caching on the image name)
Info "Building Docker image $FULLIMG ..."
docker build --no-cache -t $FULLIMG .
if ($LASTEXITCODE -ne 0) { Fail "docker build failed" }
Pass "Docker build succeeded"

# Also tag as :latest
docker tag $FULLIMG "${IMAGE}:latest"
Pass "Tagged as :latest"

# 6. Login to ACR and push
Info "Logging into ACR..."
az acr login --name mailguardacr7842
if ($LASTEXITCODE -ne 0) { Fail "ACR login failed" }

Info "Pushing $FULLIMG ..."
docker push $FULLIMG
if ($LASTEXITCODE -ne 0) { Fail "docker push failed" }
docker push "${IMAGE}:latest"
Pass "Push complete"

# 7. Update the container image.
#
# Pass ONLY --image. Azure CLI reads the live spec, patches just the image
# field, and writes everything else back unchanged — env vars, secrets,
# volume mounts, resources, scaling rules: all preserved.
#
# NEVER use --set-env-vars here: it replaces the ENTIRE env var set,
# wiping ENCRYPTION_KEY / SECRET_KEY and breaking every stored credential.
#
# Volume mount setup is a one-time operation handled by Setup-Storage.ps1.
# After that the mount is in the spec and survives every --image update.

Info "Checking persistent /data volume mount..."
$currentSpec = az containerapp show --name $APP --resource-group $RG --output json | ConvertFrom-Json
$hasMount    = $currentSpec.properties.template.containers[0].volumeMounts |
               Where-Object { $_.mountPath -eq "/data" }
if ($hasMount) {
    Pass "Volume mount at /data is configured"
} else {
    Write-Host "  [WARN] No /data volume mount found — run .\Setup-Storage.ps1 once to enable persistent storage." -ForegroundColor Yellow
    Write-Host "  [WARN] GWS tokens will not survive container restarts until Setup-Storage.ps1 is run." -ForegroundColor Yellow
}

# Deactivate all currently running revisions BEFORE updating the image.
# SQLite allows only one writer at a time — if the old revision still holds
# the database file open when the new one starts, it gets "database is locked".
# We deactivate first, then POLL until the revision is actually stopped.
Info "Deactivating current revisions before update..."
$currentRevs = az containerapp revision list `
    --name $APP --resource-group $RG `
    --query "[?properties.active].name" -o tsv
$revsToStop = $currentRevs -split "`n" | Where-Object { $_.Trim() }
foreach ($rev in $revsToStop) {
    az containerapp revision deactivate --name $APP --resource-group $RG --revision $rev.Trim() --output none 2>$null
    Pass "Deactivated $($rev.Trim())"
}

if ($revsToStop) {
    # Poll until all deactivated revisions show Deactivated/Stopped state
    Info "Waiting for old revisions to fully stop (releases DB file lock)..."
    $stopDeadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $stopDeadline) {
        Start-Sleep -Seconds 4
        $stillRunning = az containerapp revision list `
            --name $APP --resource-group $RG `
            --query "[?properties.active && properties.runningState=='Running'].name" -o tsv
        $stillRunning = $stillRunning -split "`n" | Where-Object { $_.Trim() }
        if (-not $stillRunning) {
            Pass "All old revisions stopped — database file lock released"
            break
        }
        Info "  Still running: $($stillRunning -join ', ') — waiting..."
    }
    # Extra buffer — Azure File Share SMB locks can lag a few seconds after process exit
    Start-Sleep -Seconds 8
}

Info "Updating image to $FULLIMG ..."
az containerapp update `
    --name $APP `
    --resource-group $RG `
    --image $FULLIMG `
    --output none
if ($LASTEXITCODE -ne 0) { Fail "az containerapp update --image failed" }
Pass "Image updated — new revision provisioning"

# 9. Wait and poll until the new revision is running (up to 3 minutes)
Info "Waiting for new revision to become active..."
$deadline = (Get-Date).AddMinutes(3)
$newRevision = $null
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 8
    $revisions = az containerapp revision list `
        --name $APP --resource-group $RG `
        --query "[].{name:name,active:properties.active,state:properties.runningState,image:properties.template.containers[0].image}" `
        | ConvertFrom-Json
    $newRevision = $revisions | Where-Object { $_.image -eq $FULLIMG } | Select-Object -First 1
    if ($newRevision) {
        Info "Revision $($newRevision.name) state: $($newRevision.state)"
        if ($newRevision.state -eq "Running" -or $newRevision.state -eq "RunningAtMaxScale") { break }
        if ($newRevision.state -eq "Failed" -or $newRevision.state -eq "Stopped") {
            Fail "New revision entered state '$($newRevision.state)' — check Azure Portal logs"
        }
    }
}
if (-not $newRevision) { Fail "New revision never appeared — check Azure Portal" }
if ($newRevision.state -ne "Running" -and $newRevision.state -ne "RunningAtMaxScale") { Fail "Revision did not reach Running state in 3 minutes" }
Pass "New revision $($newRevision.name) is $($newRevision.state)"

# 10. Deactivate old revisions
Info "Deactivating old revisions..."
$revisions = az containerapp revision list `
    --name $APP --resource-group $RG `
    --query "[].{name:name,active:properties.active,image:properties.template.containers[0].image}" `
    | ConvertFrom-Json
foreach ($rev in $revisions) {
    if ($rev.active -and $rev.image -ne $FULLIMG) {
        az containerapp revision deactivate --name $APP --resource-group $RG --revision $rev.name
        Pass "Deactivated old revision $($rev.name)"
    }
}

# 11. Health check
$APP_URL = "https://" + (az containerapp show --name $APP --resource-group $RG --query "properties.configuration.ingress.fqdn" -o tsv)
Info "Running health check at $APP_URL/api/health ..."
Start-Sleep -Seconds 5
try {
    $health = Invoke-RestMethod -Uri "$APP_URL/api/health" -TimeoutSec 20
    Pass "Health check OK — version $($health.version)"
} catch {
    Write-Host "  [WARN] Health check failed: $_ — app may still be warming up, check manually" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Green
Write-Host "  $APP_URL" -ForegroundColor Yellow
