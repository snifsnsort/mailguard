<#
.SYNOPSIS
    MailGuard One-Click Local Setup
.DESCRIPTION
    Creates an Entra app registration, adds read-only application permissions,
    opens admin consent in the browser, generates a client secret, verifies it
    works BEFORE writing backend\.env, then optionally starts Docker Compose.
#>

param(
    [string]$TenantDomain,
    [string]$TenantName,
    [string]$AdminPassword
)

#region ===== Helper Functions =====
function Write-Step   { param([string]$Message) Write-Host "`n>> $Message" -ForegroundColor Cyan }
function Write-Success{ param([string]$Message) Write-Host "   OK  $Message" -ForegroundColor Green }
function Write-Warn   { param([string]$Message) Write-Host "   !!  $Message" -ForegroundColor Yellow }
function Write-Info   { param([string]$Message) Write-Host "   --  $Message" -ForegroundColor Gray }

function Stop-Script {
    param([string]$Message)
    Write-Host "`n   FAILED: $Message" -ForegroundColor Red
    exit 1
}

function Invoke-AzCli {
    param([string[]]$Arguments)
    $output = & az @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        $text = ($output | Out-String).Trim()
        Stop-Script "az $($Arguments -join ' ') failed:`n$text"
    }
    $text = ($output | Out-String).Trim()
    if (-not $text) { return $null }
    try   { return $text | ConvertFrom-Json }
    catch { return $text }
}

function Test-GraphToken {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$Label = ""
    )
    $body = @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
    }
    try {
        $resp = Invoke-RestMethod `
            -Method Post `
            -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
            -Body $body `
            -ContentType "application/x-www-form-urlencoded" `
            -ErrorAction Stop
        if ($resp.access_token) {
            Write-Success "Token acquired $Label"
            return $true
        }
        Write-Host "   Token response missing access_token $Label" -ForegroundColor Red
        return $false
    }
    catch {
        $detail = $_.ErrorDetails.Message
        Write-Host "   Token test FAILED $Label" -ForegroundColor Red
        Write-Host "   $detail" -ForegroundColor Yellow
        return $false
    }
}

function Get-ServicePrincipal {
    param([string]$AppId)
    $sp = Invoke-AzCli @("ad","sp","list","--filter","appId eq '$AppId'","-o","json")
    if (-not $sp -or $sp.Count -eq 0) { return $null }
    return $sp[0]
}

function Ensure-ServicePrincipal {
    param([string]$AppId, [string]$DisplayName)
    $sp = Get-ServicePrincipal -AppId $AppId
    if ($sp) { Write-Success "$DisplayName SP found"; return $sp }
    Write-Warn "$DisplayName SP not found, creating..."
    Invoke-AzCli @("ad","sp","create","--id",$AppId,"-o","json") | Out-Null
    Start-Sleep -Seconds 10
    $sp = Get-ServicePrincipal -AppId $AppId
    if (-not $sp) { Stop-Script "Could not create SP for $DisplayName" }
    Write-Success "$DisplayName SP created"
    return $sp
}

function Add-AppPermission {
    param($ClientAppId, $ResourceSP, [string]$PermissionValue)
    $role = $ResourceSP.appRoles | Where-Object {
        $_.value -eq $PermissionValue -and $_.allowedMemberTypes -contains "Application"
    } | Select-Object -First 1
    if (-not $role) { Write-Warn "  skipped (not found): $PermissionValue"; return }
    Write-Info "  + $($ResourceSP.displayName) -> $PermissionValue"
    Invoke-AzCli @(
        "ad","app","permission","add",
        "--id",$ClientAppId,
        "--api",$ResourceSP.appId,
        "--api-permissions","$($role.id)=Role"
    ) | Out-Null
    Start-Sleep -Milliseconds 300
}
#endregion

Clear-Host
Write-Host "`n  MailGuard One-Click Local Setup`n ================================`n" -ForegroundColor Magenta
Write-Host " Created by George Mikhailov `n`n" -ForegroundColor Magenta
Write-Host " Questions? george@cloud4you.ca | Linkedin: https://www.linkedin.com/in/stayprotected/`n =====================================================================================`n" -ForegroundColor Magenta

#region ===== Prerequisites =====
Write-Step "Checking prerequisites"
if ($PSVersionTable.PSVersion.Major -lt 5) { Stop-Script "PowerShell 5+ required." }
Write-Success "PowerShell $($PSVersionTable.PSVersion)"

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    $wg = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $wg) { Stop-Script "Azure CLI not found. Install from https://aka.ms/installazurecliwindows then rerun." }
    Write-Warn "Azure CLI not found. Installing via winget..."
    winget install -e --id Microsoft.AzureCLI --accept-source-agreements --accept-package-agreements
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path","User")
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        Stop-Script "Azure CLI installed but not in PATH. Restart terminal and rerun."
    }
}
Write-Success "Azure CLI found"

$dockerFound = $null -ne (Get-Command docker -ErrorAction SilentlyContinue)
if ($dockerFound) { Write-Success "Docker found" }
else              { Write-Warn "Docker not found. Install Docker Desktop before starting the container." }

if (-not (Test-Path "docker-compose.yml")) {
    Stop-Script "docker-compose.yml not found. Run this script from the MailGuard root folder."
}
Write-Success "MailGuard root folder confirmed"
#endregion

#region ===== Inputs =====
Write-Step "Collecting configuration"
if (-not $TenantDomain) { $TenantDomain = Read-Host "Your Microsoft 365 domain (e.g. contoso.com)" }
if (-not $TenantDomain) { Stop-Script "Tenant domain is required." }

if (-not $TenantName) {
    $default = ($TenantDomain -split '\.')[0]
    $in = Read-Host "Friendly name for this tenant [$default]"
    $TenantName = if ($in) { $in } else { $default }
}

if (-not $AdminPassword) {
    $sp = Read-Host "Set MailGuard admin password" -AsSecureString
    $b  = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($sp)
    try     { $AdminPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($b) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}
if (-not $AdminPassword) { Stop-Script "Admin password is required." }
#endregion

#region ===== Azure Login =====
Write-Step "Logging into Azure"
az login --allow-no-subscriptions | Out-Null
if ($LASTEXITCODE -ne 0) { Stop-Script "Azure login failed." }
$account  = Invoke-AzCli @("account","show","-o","json")
$tenantId = $account.tenantId
if (-not $tenantId) { Stop-Script "Could not determine tenant ID from Azure account." }
Write-Success "Logged in. Tenant ID: $tenantId"
#endregion

#region ===== Create App Registration =====
$appName     = "MailGuardLocal-$((Get-Date).ToString('yyyyMMdd-HHmm'))"
$redirectUri = "http://localhost:8000/api/auth/callback"

Write-Step "Creating app registration: $appName"
$app = Invoke-AzCli @(
    "ad","app","create",
    "--display-name",$appName,
    "--sign-in-audience","AzureADMyOrg",
    "--web-redirect-uris",$redirectUri,
    "-o","json"
)
$clientId = $app.appId
if (-not $clientId) { Stop-Script "App creation returned no appId." }
Write-Success "App created. Client ID: $clientId"

Write-Info "Waiting 20 seconds for propagation..."
Start-Sleep -Seconds 20
#endregion

#region ===== Permissions =====
Write-Step "Adding read-only application permissions"

$graphSp    = Ensure-ServicePrincipal -AppId "00000003-0000-0000-c000-000000000000" -DisplayName "Microsoft Graph"
$exchangeSp = Ensure-ServicePrincipal -AppId "00000002-0000-0ff1-ce00-000000000000" -DisplayName "Office 365 Exchange Online"

@(
    "Directory.Read.All","Domain.Read.All","Organization.Read.All",
    "User.Read.All","UserAuthenticationMethod.Read.All","AuditLog.Read.All",
    "Policy.Read.All","Reports.Read.All","Mail.ReadBasic.All",
    "IdentityRiskyUser.Read.All","IdentityRiskEvent.Read.All"
) | ForEach-Object { Add-AppPermission -ClientAppId $clientId -ResourceSP $graphSp -PermissionValue $_ }

@("ReportingWebService.Read.All") `
    | ForEach-Object { Add-AppPermission -ClientAppId $clientId -ResourceSP $exchangeSp -PermissionValue $_ }

Write-Success "Permissions added"
#endregion

#region ===== Admin Consent =====
Write-Step "Admin consent required"
$consentUrl = "https://login.microsoftonline.com/$tenantId/adminconsent?client_id=$clientId"
Write-Host ""
Write-Host "   Opening browser for admin consent..." -ForegroundColor Yellow
Write-Host "   URL: $consentUrl" -ForegroundColor Cyan
Write-Host ""
Write-Host "   Sign in as a Global Admin and click Accept." -ForegroundColor White
Write-Host "   The redirect page afterward may look broken — that is normal." -ForegroundColor Gray
Write-Host ""
Start-Process $consentUrl
Read-Host "Press Enter after you have granted admin consent"
Write-Success "Admin consent acknowledged"
#endregion

#region ===== Generate Client Secret =====
Write-Step "Generating client secret (valid 1 year)"

# Use -o json and parse the password field from structured output.
# This is the only reliable method — TSV mixes with CLI warnings in the output stream.
$credRaw = & az ad app credential reset `
    --id $clientId `
    --display-name "MailGuard-Secret" `
    --end-date (Get-Date).AddYears(1).ToString("yyyy-MM-dd") `
    -o json 2>$null

if ($LASTEXITCODE -ne 0) {
    Stop-Script "Secret generation failed. Run manually to see error: az ad app credential reset --id $clientId -o json"
}

try {
    $credObj = $credRaw | ConvertFrom-Json
} catch {
    Stop-Script "Could not parse secret response as JSON. Raw output: $credRaw"
}

$clientSecret = $credObj.password
if (-not $clientSecret)          { Stop-Script "Parsed JSON had no 'password' field. Full object: $($credObj | Out-String)" }
if ($clientSecret.Length -lt 10) { Stop-Script "Secret too short ($($clientSecret.Length) chars). Value: [$clientSecret]" }
if ($clientSecret.Length -gt 80) { Stop-Script "Secret too long ($($clientSecret.Length) chars) — something is wrong. Value: [$clientSecret]" }

Write-Success "Secret captured ($($clientSecret.Length) characters)"

Write-Info "Waiting 15 seconds for credential propagation..."
Start-Sleep -Seconds 15
#endregion

#region ===== Token Test 1 — Raw Variables =====
Write-Step "Token test 1 of 2 — raw captured values"
if (-not (Test-GraphToken -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret -Label "(raw)")) {
    Stop-Script "Token test failed. Admin consent may be incomplete, or the secret has not propagated yet. Wait 1 minute and rerun the script."
}
#endregion

#region ===== Write .env =====
Write-Step "Writing backend\.env"

New-Item -ItemType Directory -Force -Path "backend" | Out-Null

$keyBytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($keyBytes)
$secretKey = -join ($keyBytes | ForEach-Object { $_.ToString("x2") })

# Build lines array — no heredoc, no hidden whitespace
$envLines = @(
    "# MailGuard environment - generated $(Get-Date -Format 'yyyy-MM-dd HH:mm')",
    "SECRET_KEY=$secretKey",
    "ADMIN_PASSWORD=$AdminPassword",
    "DATABASE_URL=/data/mailguard.db",
    "ALLOWED_ORIGINS=http://localhost:8000,http://127.0.0.1:8000",
    "MULTI_TENANT_MODE=false",
    "",
    "SEED_TENANT_NAME=$TenantName",
    "SEED_TENANT_ID=$tenantId",
    "SEED_TENANT_DOMAIN=$TenantDomain",
    "SEED_CLIENT_ID=$clientId",
    "SEED_CLIENT_SECRET=$clientSecret"
)

$envPath = (Join-Path (Get-Location).Path "backend\.env")
[System.IO.File]::WriteAllText($envPath, ($envLines -join "`n"), [System.Text.UTF8Encoding]::new($false))
Write-Success ".env written to $envPath"
#endregion

#region ===== Token Test 2 — Read Back from .env =====
Write-Step "Token test 2 of 2 — values as read from .env (exactly what the container sees)"

$parsed = @{}
Get-Content $envPath | Where-Object { $_ -match "^[A-Z]" -and $_ -match "=" } | ForEach-Object {
    $kv = $_ -split "=", 2
    $parsed[$kv[0].Trim()] = $kv[1].Trim()
}

$p_tenant = $parsed["SEED_TENANT_ID"]
$p_client = $parsed["SEED_CLIENT_ID"]
$p_secret = $parsed["SEED_CLIENT_SECRET"]

Write-Info "Parsed — Tenant: $p_tenant"
Write-Info "Parsed — Client: $p_client"
Write-Info "Parsed — Secret length: $($p_secret.Length) chars"

if ($p_secret.Length -ne $clientSecret.Length) {
    Stop-Script "Secret length mismatch after writing .env ($($clientSecret.Length) raw vs $($p_secret.Length) parsed). Do not proceed — check backend\.env for extra characters."
}

if (-not (Test-GraphToken -TenantId $p_tenant -ClientId $p_client -ClientSecret $p_secret -Label "(from .env)")) {
    Stop-Script ".env was written but the token test using parsed values failed. Check backend\.env manually."
}
#endregion

#region ===== Backup =====
Write-Step "Saving credentials backup"
$backupFile = "MailGuard-credentials-$((Get-Date).ToString('yyyyMMdd-HHmm')).txt"
@"
MailGuard Setup Credentials
============================
Generated   : $(Get-Date)
Tenant Name : $TenantName
Tenant Domain: $TenantDomain
Tenant ID   : $tenantId
Client ID   : $clientId
Client Secret: $clientSecret
App Name    : $appName
"@ | Out-File -FilePath $backupFile -Encoding ascii
Write-Success "Backup: $backupFile"
Write-Warn "Store securely. Do NOT commit to git."
#endregion

#region ===== Summary =====
Write-Host @"

  Setup Complete
  ==============
  App : $appName
  Client ID : $clientId
  Both token tests : PASSED
  .env : backend\.env

"@ -ForegroundColor Green
#endregion

#region ===== Docker =====
if ($dockerFound) {
    # Always stop and wipe the data volume before building.
    # The volume holds the SQLite database — if it has stale credentials
    # from a previous run, the seed tenant will not re-register correctly.
    Write-Step "Stopping containers and removing old data volume"
    docker compose down 2>&1 | Out-Null

    $volumes = docker volume ls --format "{{.Name}}" 2>&1 | Where-Object { $_ -match "mailguard" }
    if ($volumes) {
        $volumes | ForEach-Object {
            docker volume rm $_ 2>&1 | Out-Null
            Write-Success "Removed volume: $_"
        }
    } else {
        Write-Info "No existing mailguard volume found"
    }

    Write-Step "Building and starting containers"
    docker compose up --build -d
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Docker compose returned an error. Run: docker compose logs app"
    } else {
        Write-Info "Waiting for container to start..."
        Start-Sleep -Seconds 8
        Start-Process "http://localhost:8000"
        Write-Success "MailGuard started — opening http://localhost:8000"
        Write-Host "   Login: admin / [the password you set]" -ForegroundColor White
    }
} else {
    Write-Host "`n   Install Docker Desktop, then run:" -ForegroundColor White
    Write-Host "   docker compose down" -ForegroundColor Gray
    Write-Host "   docker volume rm mailguard_mailguard_data" -ForegroundColor Gray
    Write-Host "   docker compose up --build" -ForegroundColor Gray
}
#endregion

#region ===== Cleanup =====
Write-Host ""
Write-Host "   backend\.env is required by the container every time it starts." -ForegroundColor Gray
Write-Host "   Do NOT delete it. Make sure it is listed in .gitignore." -ForegroundColor Gray
Write-Host ""
$del = Read-Host "Delete the plaintext backup file ($backupFile)? (y/n)"
if ($del -eq 'y') {
    Remove-Item $backupFile -Force -ErrorAction SilentlyContinue
    Write-Success "Backup deleted"
} else {
    Write-Warn "Keep it somewhere safe and do not commit it to git."
}
Write-Host ""
#endregion
