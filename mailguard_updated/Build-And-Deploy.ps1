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

# 7. Force new Container App revision with timestamped image tag
# Using a unique tag forces Azure to pull a new image even if digest hasn't changed
Info "Deploying to Azure Container Apps (forcing new revision)..."
az containerapp update `
    --name $APP `
    --resource-group $RG `
    --image $FULLIMG `
    --set-env-vars DEPLOY_TIME="$TAG"

if ($LASTEXITCODE -ne 0) { Fail "az containerapp update failed" }
Pass "Deployment triggered"

# 8. Wait for revision to become active
Info "Waiting 15s for revision to activate..."
Start-Sleep -Seconds 15

# 9. Show active revision
Info "Active revisions:"
az containerapp revision list --name $APP --resource-group $RG --query "[].{name:name, active:properties.active, image:properties.template.containers[0].image, created:properties.createdTime}" -o table

Write-Host "`n=== Done — verify at https://mailguard-app.delightfulbay-570d5fba.eastus.azurecontainerapps.io ===" -ForegroundColor Green
