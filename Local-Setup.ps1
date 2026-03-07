# MailGuard Local Setup Script
# Run this once after cloning the repo.
# It creates backend\.env from the template and generates a secure secret key.

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  MailGuard Local Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$envFile = "backend\.env"
$exampleFile = "backend\.env.example"

# Step 1: Create .env from template
if (Test-Path $envFile) {
    Write-Host "✅ backend\.env already exists — skipping copy" -ForegroundColor Green
} else {
    if (-not (Test-Path $exampleFile)) {
        Write-Host "❌ backend\.env.example not found. Are you in the mailguard root folder?" -ForegroundColor Red
        exit 1
    }
    Copy-Item $exampleFile $envFile
    Write-Host "✅ Created backend\.env from template" -ForegroundColor Green
}

# Step 2: Generate a secure SECRET_KEY
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$secretKey = -join ($bytes | ForEach-Object { $_.ToString("x2") })
(Get-Content $envFile) -replace '^SECRET_KEY=.*', "SECRET_KEY=$secretKey" | Set-Content $envFile
Write-Host "✅ Generated secure SECRET_KEY" -ForegroundColor Green

# Step 3: Set admin password
Write-Host ""
$adminPw = Read-Host "🔑 Set your admin password (press Enter to keep default 'changeme')"
if ($adminPw -ne "") {
    (Get-Content $envFile) -replace '^ADMIN_PASSWORD=.*', "ADMIN_PASSWORD=$adminPw" | Set-Content $envFile
    Write-Host "✅ Admin password set" -ForegroundColor Green
} else {
    Write-Host "⚠️  Using default password 'changeme' — change this before sharing access" -ForegroundColor Yellow
}

# Done
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Next Steps" -ForegroundColor Cyan
Write-Host "========================================"
Write-Host ""
Write-Host "1. Edit backend\.env and fill in your credentials:" -ForegroundColor White
Write-Host "     Microsoft 365 : SEED_TENANT_ID, SEED_CLIENT_ID, SEED_CLIENT_SECRET, SEED_TENANT_DOMAIN" -ForegroundColor Gray
Write-Host "     Google         : GWS_CLIENT_ID, GWS_CLIENT_SECRET, GWS_REDIRECT_URI" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Start MailGuard:" -ForegroundColor White
Write-Host "     docker compose up --build" -ForegroundColor Gray
Write-Host ""
Write-Host "3. Open http://localhost:8000 and log in" -ForegroundColor White
Write-Host ""
Write-Host "See docs\M365_SETUP.md and docs\GWS_SETUP.md for credential setup guides." -ForegroundColor DarkGray
Write-Host ""
