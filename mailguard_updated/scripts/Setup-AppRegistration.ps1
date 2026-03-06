#Requires -Version 7
<#
.SYNOPSIS
    Sets up the Azure AD App Registration for MailGuard in your Microsoft 365 tenant.

.DESCRIPTION
    This script does everything automatically:
      1. Creates an App Registration in your Azure AD / Entra ID
      2. Grants the required Microsoft Graph API permissions
      3. Grants the Exchange Online API permission
      4. Assigns the Exchange Administrator role
      5. Creates a client secret
      6. Prints the credentials you need to paste into MailGuard

    Run this script ONCE per tenant you want to monitor.
    You must be a Global Administrator or Privileged Role Administrator to run it.

.EXAMPLE
    .\Setup-AppRegistration.ps1

.NOTES
    Requirements:
      - PowerShell 7+  (winget install Microsoft.PowerShell)
      - Az PowerShell  (Install-Module Az -Scope CurrentUser)
      - Microsoft.Graph (Install-Module Microsoft.Graph -Scope CurrentUser)
#>

[CmdletBinding()]
param(
    [string] $AppName = "MailGuard Security Scanner",
    [int]    $SecretExpiryMonths = 12
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Colours ───────────────────────────────────────────────────────────────────
function Write-Step   { param($msg) Write-Host "`n▶  $msg" -ForegroundColor Cyan }
function Write-Ok     { param($msg) Write-Host "   ✅ $msg" -ForegroundColor Green }
function Write-Warn   { param($msg) Write-Host "   ⚠️  $msg" -ForegroundColor Yellow }
function Write-Fail   { param($msg) Write-Host "   ❌ $msg" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║        MailGuard — App Registration Setup            ║" -ForegroundColor Magenta
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""

# ── Step 0: Check modules ─────────────────────────────────────────────────────
Write-Step "Checking required PowerShell modules..."

$missing = @()
foreach ($mod in @("Microsoft.Graph", "Az.Accounts", "Az.Resources")) {
    if (-not (Get-Module -ListAvailable -Name $mod)) { $missing += $mod }
}
if ($missing) {
    Write-Host "   Installing missing modules: $($missing -join ', ')" -ForegroundColor Yellow
    foreach ($mod in $missing) {
        Install-Module $mod -Scope CurrentUser -Force -AllowClobber
    }
}
Write-Ok "All modules available"

# ── Step 1: Connect ───────────────────────────────────────────────────────────
Write-Step "Connecting to Microsoft Graph (sign in with a Global Admin account)..."
Connect-MgGraph -Scopes `
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Directory.ReadWrite.All" `
    -NoWelcome

$context   = Get-MgContext
$tenantId  = $context.TenantId
$tenantDomain = ($context.Account -split "@")[1]
Write-Ok "Connected to tenant: $tenantId ($tenantDomain)"

# ── Step 2: Create or reuse app registration ──────────────────────────────────
Write-Step "Creating app registration '$AppName'..."

$existing = Get-MgApplication -Filter "displayName eq '$AppName'" -All
if ($existing) {
    Write-Warn "App '$AppName' already exists — reusing it."
    $app = $existing | Select-Object -First 1
} else {
    $app = New-MgApplication -DisplayName $AppName -SignInAudience "AzureADMyOrg"
    Write-Ok "App created: $($app.AppId)"
}

$clientId = $app.AppId
$objectId = $app.Id

# ── Step 3: Create service principal ─────────────────────────────────────────
Write-Step "Creating service principal..."
$sp = Get-MgServicePrincipal -Filter "appId eq '$clientId'"
if (-not $sp) {
    $sp = New-MgServicePrincipal -AppId $clientId
    Write-Ok "Service principal created: $($sp.Id)"
} else {
    Write-Warn "Service principal already exists — reusing it."
}
$spId = $sp.Id

# ── Step 4: API permissions ───────────────────────────────────────────────────
Write-Step "Configuring API permissions..."

# Microsoft Graph permissions needed
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$graphPerms = @(
    "Directory.Read.All",           # Read tenant directory data
    "Policy.Read.All",              # Read conditional access policies
    "AuditLog.Read.All",            # Read sign-in logs for MFA check
    "Organization.Read.All",        # Read org/security defaults
    "User.Read.All",                # Read user MFA status
    "Domain.Read.All"               # Read domain DNS records
)

$requiredGraphRoles = $graphSp.AppRoles | Where-Object { $_.Value -in $graphPerms }

# Exchange Online permission
$exoSp = Get-MgServicePrincipal -Filter "appId eq '00000002-0000-0ff1-ce00-000000000000'"
$exoRole = $exoSp.AppRoles | Where-Object { $_.Value -eq "Exchange.ManageAsApp" }

# Build required resource access
$resourceAccess = @(
    @{
        ResourceAppId  = "00000003-0000-0000-c000-000000000000"  # Graph
        ResourceAccess = @($requiredGraphRoles | ForEach-Object {
            @{ Id = $_.Id; Type = "Role" }
        })
    },
    @{
        ResourceAppId  = "00000002-0000-0ff1-ce00-000000000000"  # Exchange
        ResourceAccess = @(
            @{ Id = $exoRole.Id; Type = "Role" }
        )
    }
)

Update-MgApplication -ApplicationId $objectId -RequiredResourceAccess $resourceAccess
Write-Ok "API permissions configured"

# ── Step 5: Grant admin consent ───────────────────────────────────────────────
Write-Step "Granting admin consent for all permissions..."

# Graph roles
foreach ($role in $requiredGraphRoles) {
    $existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spId |
        Where-Object { $_.AppRoleId -eq $role.Id }
    if (-not $existing) {
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spId `
            -PrincipalId $spId `
            -ResourceId $graphSp.Id `
            -AppRoleId $role.Id | Out-Null
    }
}

# Exchange role
$exoExisting = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spId |
    Where-Object { $_.AppRoleId -eq $exoRole.Id }
if (-not $exoExisting) {
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spId `
        -PrincipalId $spId `
        -ResourceId $exoSp.Id `
        -AppRoleId $exoRole.Id | Out-Null
}
Write-Ok "Admin consent granted"

# ── Step 6: Exchange Administrator role ───────────────────────────────────────
Write-Step "Assigning Exchange Administrator role..."

$exchangeAdminRoleId = "29232cdf-9323-42fd-ade2-1d097af3e4de"  # well-known role template ID

$roleAssignment = Get-MgRoleManagementDirectoryRoleAssignment -All |
    Where-Object { $_.RoleDefinitionId -eq $exchangeAdminRoleId -and $_.PrincipalId -eq $spId }

if (-not $roleAssignment) {
    New-MgRoleManagementDirectoryRoleAssignment `
        -RoleDefinitionId $exchangeAdminRoleId `
        -PrincipalId $spId `
        -DirectoryScopeId "/" | Out-Null
    Write-Ok "Exchange Administrator role assigned"
} else {
    Write-Warn "Exchange Administrator role already assigned"
}

# ── Step 7: Create client secret ──────────────────────────────────────────────
Write-Step "Creating client secret (valid for $SecretExpiryMonths months)..."

$secretResult = Add-MgApplicationPassword -ApplicationId $objectId -PasswordCredential @{
    DisplayName = "MailGuard Secret $(Get-Date -Format 'yyyy-MM-dd')"
    EndDateTime = (Get-Date).AddMonths($SecretExpiryMonths)
}
$clientSecret = $secretResult.SecretText
Write-Ok "Client secret created (expires: $($secretResult.EndDateTime.ToString('yyyy-MM-dd')))"

# ── Done — print credentials ──────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║              ✅  Setup Complete!                      ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Copy these values into MailGuard when adding your tenant:" -ForegroundColor White
Write-Host ""
Write-Host "  Tenant ID     : " -NoNewline; Write-Host $tenantId     -ForegroundColor Yellow
Write-Host "  Domain        : " -NoNewline; Write-Host $tenantDomain  -ForegroundColor Yellow
Write-Host "  Client ID     : " -NoNewline; Write-Host $clientId     -ForegroundColor Yellow
Write-Host "  Client Secret : " -NoNewline; Write-Host $clientSecret  -ForegroundColor Yellow
Write-Host ""
Write-Host "  ⚠️  Save the Client Secret now — it won't be shown again!" -ForegroundColor Red
Write-Host ""
Write-Host "  Note: Exchange permissions can take up to 15 minutes to propagate." -ForegroundColor Gray
Write-Host ""

# Save to file for convenience
$outputFile = Join-Path $PSScriptRoot "mailguard-credentials.txt"
@"
MailGuard Tenant Credentials
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
============================================
Tenant ID     : $tenantId
Domain        : $tenantDomain
Client ID     : $clientId
Client Secret : $clientSecret
============================================
DELETE THIS FILE after adding the tenant to MailGuard.
"@ | Set-Content -Path $outputFile
Write-Host "  Credentials also saved to: $outputFile" -ForegroundColor Gray
Write-Host "  ⚠️  Delete that file after use!" -ForegroundColor Red
Write-Host ""
