# Setup-Storage.ps1
# Run ONCE after initial deployment to attach persistent storage to the container.
# After this runs, every future .\Build-And-Deploy.ps1 preserves the volume mount
# automatically — you never need to run this again unless you re-create the app.
#
# Usage: .\Setup-Storage.ps1

[CmdletBinding()]
param(
    [string] $App           = "mailguard-app",
    [string] $ResourceGroup = "mailguard-rg"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Pass($msg) { Write-Host "  [OK]   $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "  [FAIL] $msg" -ForegroundColor Red; exit 1 }
function Info($msg) { Write-Host "  -->    $msg" -ForegroundColor Cyan }

Write-Host ""
Write-Host "=== MailGuard — Persistent Storage Setup ===" -ForegroundColor Cyan
Write-Host ""

# ── 1. Resolve environment name ───────────────────────────────────────────────
Info "Reading container app details..."
$appJson   = az containerapp show --name $App --resource-group $ResourceGroup --output json
if ($LASTEXITCODE -ne 0) { Fail "Could not read container app — is '$App' in '$ResourceGroup'?" }
$appSpec   = $appJson | ConvertFrom-Json
$envId     = $appSpec.properties.environmentId
$ENV_NAME  = $envId | Split-Path -Leaf

# Current image (we need to pass it through the update)
$curImage  = $appSpec.properties.template.containers[0].image
Pass "App: $App  |  Env: $ENV_NAME  |  Image: $curImage"

# ── 2. Check existing volume mount ────────────────────────────────────────────
$hasMount = $appSpec.properties.template.containers[0].volumeMounts |
            Where-Object { $_.mountPath -eq "/data" }
if ($hasMount) {
    Pass "Volume mount at /data already configured — nothing to do."
    exit 0
}

# ── 3. Find storage account ───────────────────────────────────────────────────
Info "Looking for storage account in $ResourceGroup ..."
$storageAcct = (az storage account list --resource-group $ResourceGroup --query "[0].name" -o tsv 2>$null)
if (-not $storageAcct) { Fail "No storage account found in $ResourceGroup. Run deploy.ps1 first." }
Pass "Storage account: $storageAcct"

# ── 4. Ensure file share exists ───────────────────────────────────────────────
Info "Ensuring file share 'mailguard-data' exists..."
$storageKey = (az storage account keys list --account-name $storageAcct --resource-group $ResourceGroup --query "[0].value" -o tsv)
az storage share create `
    --name "mailguard-data" `
    --account-name $storageAcct `
    --account-key $storageKey `
    --output none 2>$null
Pass "File share: mailguard-data"

# ── 5. Link storage to Container Apps environment ─────────────────────────────
Info "Linking storage to Container Apps environment..."
az containerapp env storage set `
    --name $ENV_NAME `
    --resource-group $ResourceGroup `
    --storage-name "mailguard-storage" `
    --azure-file-account-name $storageAcct `
    --azure-file-account-key $storageKey `
    --azure-file-share-name "mailguard-data" `
    --access-mode ReadWrite `
    --output none
if ($LASTEXITCODE -ne 0) { Fail "Failed to link storage to environment" }
Pass "Storage linked: mailguard-storage → $storageAcct/mailguard-data"

# ── 6. Add /data volume mount via az rest PATCH ───────────────────────────────
# We use az rest PATCH here (not az containerapp update) because we need to set
# both volumes (at template level) AND volumeMounts (at container level) in one
# atomic operation. az containerapp update has no --volume-mount flag.
#
# The PATCH body includes ONLY the fields we are changing:
#   - template.volumes       — declares the AzureFile volume
#   - containers[0].name     — required to identify which container
#   - containers[0].image    — required (Azure rejects a container with no image)
#   - containers[0].volumeMounts — the new /data mount
#
# Env vars, resources, scaling rules are NOT included → Azure preserves them.
# This is safe because Container Apps PATCH merges at the property level, not
# array-element level — any container property we omit keeps its current value.

Info "Writing volume mount patch..."
$patchFile = [System.IO.Path]::GetTempFileName() -replace "\.tmp$", ".json"
$patchBody = '{
  "properties": {
    "template": {
      "volumes": [
        {"name":"mailguard-vol","storageName":"mailguard-storage","storageType":"AzureFile"}
      ],
      "containers": [
        {
          "name": "mailguard",
          "image": "' + $curImage + '",
          "volumeMounts": [
            {"mountPath":"/data","volumeName":"mailguard-vol"}
          ]
        }
      ]
    }
  }
}'
Set-Content -Path $patchFile -Value $patchBody -Encoding UTF8

$subId = (az account show --query id -o tsv)
Info "Patching container app (volumes + /data mount)..."
$response = az rest `
    --method PATCH `
    --uri "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.App/containerApps/${App}?api-version=2024-03-01" `
    --headers "Content-Type=application/json" `
    --body "@$patchFile" `
    --output json 2>&1
$patchExit = $LASTEXITCODE
Remove-Item $patchFile -ErrorAction SilentlyContinue

if ($patchExit -ne 0) {
    Write-Host $response
    Fail "PATCH failed — see output above"
}
Pass "PATCH accepted"

# ── 7. Wait for the new revision to reach Running state ──────────────────────
Info "Waiting for revision to start (up to 3 minutes)..."
$deadline = (Get-Date).AddMinutes(3)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 8
    $revs = az containerapp revision list `
        --name $App --resource-group $ResourceGroup `
        --query "[].{name:name,state:properties.runningState,image:properties.template.containers[0].image}" `
        | ConvertFrom-Json
    $latest = $revs | Sort-Object name -Descending | Select-Object -First 1
    Info "  Revision $($latest.name): $($latest.state)"
    if ($latest.state -eq "Running")  { Pass "Revision $($latest.name) is Running"; break }
    if ($latest.state -eq "Failed")   { Fail "Revision failed — check Azure Portal logs for details" }
    if ($latest.state -eq "Stopped")  { Fail "Revision stopped — check Azure Portal logs for details" }
}

# ── 8. Verify mount is in place ───────────────────────────────────────────────
$updatedSpec = az containerapp show --name $App --resource-group $ResourceGroup --output json | ConvertFrom-Json
$mount = $updatedSpec.properties.template.containers[0].volumeMounts | Where-Object { $_.mountPath -eq "/data" }
if ($mount) {
    Pass "Volume mount confirmed: /data → mailguard-vol"
} else {
    Fail "Volume mount not found in updated spec — check Azure Portal"
}

Write-Host ""
Write-Host "=== Persistent storage is configured ===" -ForegroundColor Green
Write-Host ""
Write-Host "  The database now lives at /data/mailguard.db on the Azure File Share." -ForegroundColor White
Write-Host "  GWS tokens will survive all future container updates." -ForegroundColor White
Write-Host ""
Write-Host "  IMPORTANT: Reconnect Google Workspace once now — the old token was" -ForegroundColor Yellow
Write-Host "  stored in the ephemeral database. After reconnecting, it will be" -ForegroundColor Yellow
Write-Host "  saved to both the database and /data/gws_tokens.json (backup)." -ForegroundColor Yellow
Write-Host "  All future updates will restore it automatically." -ForegroundColor Yellow
Write-Host ""
