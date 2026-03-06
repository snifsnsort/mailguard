# Fix-Permissions.ps1
# Grants the required app-only permissions to the MailGuard app in PFPTDEV tenant
# Run once to fix the existing connection

$TenantId     = "283b1764-e180-43e0-8fd5-0c8de8b889d7"
$ClientId     = "6d2885d8-921f-45f6-914c-9b606ff25bbc"

Write-Host "Logging into PFPTDEV tenant..." -ForegroundColor Cyan
az login --tenant $TenantId --allow-no-subscriptions

Write-Host "Finding MailGuard service principal..." -ForegroundColor Cyan
$sp = az ad sp show --id $ClientId 2>$null | ConvertFrom-Json
if (-not $sp) {
    Write-Host "ERROR: MailGuard SP not found. Re-run the /connect flow first." -ForegroundColor Red
    exit 1
}
$SpId = $sp.id
Write-Host "Found SP: $SpId" -ForegroundColor Green

# Graph permissions needed
$GraphPerms = @(
    "246dd0d5-5bd0-4def-940b-0421030a5b68",  # Policy.Read.All
    "7ab1d382-f21e-4acd-a863-ba3e13f7da61",  # Directory.Read.All
    "b0afded3-3588-46d8-8b3d-9842eff778da",  # AuditLog.Read.All
    "38d9df27-64da-44fd-b7c5-a6fbac20248f",  # UserAuthenticationMethod.Read.All
    "e1fe6dd8-ba31-4d61-89e7-88639da4683d",  # User.Read.All
    "dbb9058a-0e50-45d7-ae91-66909b5d4664",  # Organization.Read.All
    "bac3b9c2-b516-4ef4-bd3b-c2ef73d8d804"   # Domain.Read.All
)

Write-Host "Granting Graph API permissions..." -ForegroundColor Cyan
foreach ($perm in $GraphPerms) {
    az ad app permission grant --id $ClientId --api 00000003-0000-0000-c000-000000000000 2>$null
    Write-Host "  Granted: $perm"
}

Write-Host "Granting admin consent for all permissions..." -ForegroundColor Cyan
az ad app permission admin-consent --id $ClientId 2>$null

Write-Host "Assigning Exchange Administrator role..." -ForegroundColor Cyan
$RoleId = az rest --method GET --url "https://graph.microsoft.com/v1.0/directoryRoles?`$filter=roleTemplateId eq '29232cdf-9323-42fd-ade2-1d097af3e4de'" --query "value[0].id" -o tsv 2>$null
if ($RoleId) {
    az rest --method POST `
        --url "https://graph.microsoft.com/v1.0/directoryRoles/$RoleId/members/`$ref" `
        --body "{`"@odata.id`": `"https://graph.microsoft.com/v1.0/directoryObjects/$SpId`"}" 2>$null
    Write-Host "Exchange Admin role assigned." -ForegroundColor Green
}

Write-Host ""
Write-Host "Done! Wait 30-60 seconds for permissions to propagate, then run a scan." -ForegroundColor Green
