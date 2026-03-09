<#
.SYNOPSIS
    MailGuard One-Click Local Setup — Google Workspace
.DESCRIPTION
    Guides you through creating a Google OAuth 2.0 app for MailGuard,
    writes backend\.env with the necessary credentials, and starts
    the Docker container.

    Prerequisites
    ─────────────
    • Docker Desktop running
    • A Google Workspace Super Admin account
    • A Google Cloud project with the Admin SDK API enabled

    What this script does
    ──────────────────────
    1. Verifies Docker is running
    2. Walks you through creating a Google OAuth Client ID
       (opens the Cloud Console in your browser with hints)
    3. Accepts your Client ID, Client Secret, and Admin email
    4. Writes backend\.env
    5. Stops any existing containers and starts a fresh deployment
    6. Opens MailGuard at http://localhost:8000
#>

#region ===== Helpers =====
function Write-Step   { param([string]$M) Write-Host "`n>> $M" -ForegroundColor Cyan }
function Write-Success{ param([string]$M) Write-Host "   OK  $M" -ForegroundColor Green }
function Write-Warn   { param([string]$M) Write-Host "   !!  $M" -ForegroundColor Yellow }
function Write-Info   { param([string]$M) Write-Host "   --  $M" -ForegroundColor Gray }
function Stop-Script  { param([string]$M) Write-Host "`n   FAILED: $M" -ForegroundColor Red; exit 1 }

function Prompt-Required {
    param([string]$Label, [string]$Default = "")
    do {
        $val = Read-Host "   $Label$(if ($Default) { " [$Default]" } else { '' })"
        if (-not $val -and $Default) { $val = $Default }
    } while (-not $val)
    return $val.Trim()
}

function Test-GwsToken {
    param([string]$ClientId, [string]$ClientSecret)
    # We can only verify the shape of the credentials offline; live verification
    # happens during the OAuth flow in the browser.  At minimum, check both are
    # non-empty and look like Google OAuth credentials.
    if ($ClientId -notmatch "\.apps\.googleusercontent\.com$") {
        Write-Warn "Client ID doesn't look like a Google OAuth Client ID (should end in .apps.googleusercontent.com)"
        $ans = Read-Host "   Continue anyway? [y/N]"
        if ($ans -ne 'y') { Stop-Script "Aborted." }
    }
    Write-Success "Credentials accepted (will be verified during OAuth flow)"
}
#endregion

Write-Host ""
Write-Host " ============================================================" -ForegroundColor Magenta
Write-Host "   MailGuard — Local Setup for Google Workspace              " -ForegroundColor Magenta
Write-Host " ============================================================" -ForegroundColor Magenta
Write-Host ""

# ── Step 1: Docker ───────────────────────────────────────────────────────────
Write-Step "Checking Docker"
try {
    $dockerInfo = docker info 2>&1
    if ($LASTEXITCODE -ne 0) { Stop-Script "Docker is not running. Start Docker Desktop and re-run this script." }
    Write-Success "Docker is running"
} catch {
    Stop-Script "Docker not found. Install Docker Desktop from https://www.docker.com/products/docker-desktop/"
}

# ── Step 2: Google OAuth setup instructions ──────────────────────────────────
Write-Step "Google Cloud Console — OAuth Client setup"
Write-Host ""
Write-Host "   You need a Google OAuth 2.0 Client ID to allow MailGuard to" -ForegroundColor White
Write-Host "   connect to your Workspace tenant. Follow these steps:" -ForegroundColor White
Write-Host ""
Write-Host "   1. Open: https://console.cloud.google.com/apis/credentials" -ForegroundColor Yellow
Write-Host "      (Create a project if you don't have one already)" -ForegroundColor Gray
Write-Host ""
Write-Host "   2. Enable the Admin SDK API:" -ForegroundColor Yellow
Write-Host "      https://console.cloud.google.com/apis/library/admin.googleapis.com" -ForegroundColor Gray
Write-Host ""
Write-Host "   3. Click 'Create Credentials' → 'OAuth client ID'" -ForegroundColor Yellow
Write-Host "      • Application type : Web application" -ForegroundColor Gray
Write-Host "      • Name             : MailGuard Local" -ForegroundColor Gray
Write-Host "      • Authorized redirect URIs — add exactly:" -ForegroundColor Gray
Write-Host "          http://localhost:8000/api/v1/google/callback" -ForegroundColor Cyan
Write-Host ""
Write-Host "   4. Click 'Create'. Copy the Client ID and Client Secret." -ForegroundColor Yellow
Write-Host ""
Write-Host "   5. Configure the OAuth Consent Screen:" -ForegroundColor Yellow
Write-Host "      • User type        : Internal  (Workspace accounts only)" -ForegroundColor Gray
Write-Host "      • App name         : MailGuard" -ForegroundColor Gray
Write-Host "      • Scopes needed (add all):" -ForegroundColor Gray
Write-Host "          .../auth/admin.reports.audit.readonly" -ForegroundColor Gray
Write-Host "          .../auth/admin.directory.user.readonly" -ForegroundColor Gray
Write-Host "          .../auth/admin.directory.domain.readonly" -ForegroundColor Gray
Write-Host "          .../auth/admin.directory.orgunit.readonly" -ForegroundColor Gray
Write-Host "          openid  email  profile" -ForegroundColor Gray
Write-Host ""

$openBrowser = Read-Host "   Open Google Cloud Console now? [Y/n]"
if ($openBrowser -ne 'n') {
    Start-Process "https://console.cloud.google.com/apis/credentials"
    Write-Info "Browser opened. Complete the steps above, then press Enter to continue."
    Read-Host "   Press Enter when you have your Client ID and Secret ready"
}

# ── Step 3: Collect credentials ──────────────────────────────────────────────
Write-Step "Enter your Google OAuth credentials"

$GwsClientId     = Prompt-Required "Google OAuth Client ID"
$GwsClientSecret = Prompt-Required "Google OAuth Client Secret"
$AdminPassword   = Prompt-Required "MailGuard dashboard password (you choose)"
$TenantName      = Prompt-Required "Organisation friendly name (e.g. Contoso Inc)"

Test-GwsToken -ClientId $GwsClientId -ClientSecret $GwsClientSecret

# ── Step 4: Generate a random secret key ─────────────────────────────────────
Write-Step "Generating secure keys"
Add-Type -AssemblyName System.Security
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = New-Object byte[] 48
$rng.GetBytes($bytes)
$SecretKey = [Convert]::ToBase64String($bytes)
Write-Success "Secret key generated"

# ── Step 5: Write backend\.env ────────────────────────────────────────────────
Write-Step "Writing backend\.env"
$envDir = Join-Path $PSScriptRoot "backend"
if (-not (Test-Path $envDir)) { New-Item -ItemType Directory -Path $envDir | Out-Null }
$envPath = Join-Path $envDir ".env"

$envContent = @"
# MailGuard — Google Workspace local deployment
# Generated by Deploy-MailGuard-Local-GWS.ps1 on $(Get-Date -Format 'yyyy-MM-dd HH:mm')
# DO NOT commit this file to git.

# ── Authentication ────────────────────────────────────────────────────────────
SECRET_KEY=$SecretKey
ADMIN_PASSWORD=$AdminPassword

# ── Google Workspace OAuth ─────────────────────────────────────────────────────
# GWS_* are the canonical env var names used in both local and Azure deployments.
GWS_CLIENT_ID=$GwsClientId
GWS_CLIENT_SECRET=$GwsClientSecret
GWS_REDIRECT_URI=http://localhost:8000/api/v1/google/callback

# ── Tenant (GWS-only — no M365 seed required) ─────────────────────────────────
# SEED_TENANT_* can be left empty for a GWS-only deployment.
# The tenant is created automatically on first Google OAuth callback.
SEED_TENANT_NAME=$TenantName

# ── Optional ──────────────────────────────────────────────────────────────────
# DATABASE_URL=sqlite:////data/mailguard.db
# ALLOWED_ORIGINS=*
"@

Set-Content -Path $envPath -Value $envContent -Encoding UTF8
Write-Success "Written to: $envPath"

# ── Step 6: Start containers ──────────────────────────────────────────────────
Write-Step "Starting MailGuard containers"

$composeFile = Join-Path $PSScriptRoot "docker-compose.yml"
if (-not (Test-Path $composeFile)) {
    Stop-Script "docker-compose.yml not found in $PSScriptRoot. Make sure you are running this script from the mailguard folder."
}

Write-Info "Stopping any existing containers..."
docker compose -f $composeFile down 2>&1 | Out-Null

Write-Info "Building and starting (this takes a minute on first run)..."
docker compose -f $composeFile up --build -d
if ($LASTEXITCODE -ne 0) { Stop-Script "docker compose up failed. Check the output above for details." }

Write-Success "Containers started"

# ── Step 7: Wait and open browser ─────────────────────────────────────────────
Write-Step "Waiting for MailGuard to be ready"
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 2
    try {
        $resp = Invoke-WebRequest -Uri "http://localhost:8000/api/health" -UseBasicParsing -ErrorAction Stop -TimeoutSec 3
        if ($resp.StatusCode -eq 200) { $ready = $true; break }
    } catch {}
    Write-Host "   ." -NoNewline
}
Write-Host ""

if (-not $ready) {
    Write-Warn "MailGuard did not respond within 60 seconds. Check logs with: docker compose logs app"
} else {
    Write-Success "MailGuard is running at http://localhost:8000"
}

Write-Host ""
Write-Host " ============================================================" -ForegroundColor Green
Write-Host "   Setup complete!" -ForegroundColor Green
Write-Host " ============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "   URL      : http://localhost:8000" -ForegroundColor White
Write-Host "   Username : admin" -ForegroundColor White
Write-Host "   Password : (the one you entered above)" -ForegroundColor White
Write-Host ""
Write-Host "   Next steps:" -ForegroundColor Cyan
Write-Host "   1. Open http://localhost:8000 and log in" -ForegroundColor White
Write-Host "   2. Click 'Connect Google Workspace' — sign in with a Super Admin account" -ForegroundColor White
Write-Host "   3. After OAuth completes, click 'Sync Domains' to discover all GWS domains" -ForegroundColor White
Write-Host "   4. Click 'Scan' to run your first security scan" -ForegroundColor White
Write-Host ""
Write-Host "   To stop: docker compose down" -ForegroundColor Gray
Write-Host "   To view logs: docker compose logs app" -ForegroundColor Gray
Write-Host ""
