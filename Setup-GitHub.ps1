# Setup-GitHub.ps1
# Run this from inside your mailguard folder
# Creates the GitHub repo and pushes all your code in one shot

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  MailGuard GitHub Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Get GitHub credentials ───────────────────────────────────────────
$username = Read-Host "Enter your GitHub username"
$token    = Read-Host "Enter your GitHub Personal Access Token" -AsSecureString
$tokenPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($token)
)

# ── Step 2: Create the repo via GitHub API ────────────────────────────────────
Write-Host ""
Write-Host "Creating repository on GitHub..." -ForegroundColor Yellow

$headers = @{
    Authorization = "Bearer $tokenPlain"
    Accept        = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
}

$body = @{
    name        = "mailguard"
    description = "Free email security posture management for Microsoft 365 and Google Workspace"
    private     = $false
    auto_init   = $false
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod `
        -Uri "https://api.github.com/user/repos" `
        -Method POST `
        -Headers $headers `
        -Body $body `
        -ContentType "application/json"
    Write-Host "Repository created: $($response.html_url)" -ForegroundColor Green
} catch {
    $msg = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
    if ($msg.errors[0].message -like "*already exists*" -or $_.Exception.Message -like "*422*") {
        Write-Host "Repository already exists — continuing with push." -ForegroundColor Yellow
    } else {
        Write-Host "Failed to create repo: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# ── Step 3: Initialize git and push ──────────────────────────────────────────
Write-Host ""
Write-Host "Setting up git and pushing code..." -ForegroundColor Yellow

$repoUrl = "https://${username}:${tokenPlain}@github.com/${username}/mailguard.git"

# Remove any existing git init from failed attempts
if (Test-Path ".git") {
    Write-Host "Existing .git folder found — resetting remote..." -ForegroundColor Yellow
    git remote remove origin 2>$null
    git remote add origin $repoUrl
} else {
    git init
    git remote add origin $repoUrl
}

# Stage everything (respects .gitignore)
git add .

# Commit
$commitMsg = "Initial commit"
git commit -m $commitMsg 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    # If nothing to commit, still try to push
    Write-Host "Nothing new to commit — attempting push anyway..." -ForegroundColor Yellow
}

# Rename branch to main and push
git branch -M main
git push -u origin main --force

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  SUCCESS!" -ForegroundColor Green
    Write-Host "  https://github.com/$username/mailguard" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
} else {
    Write-Host "Push failed. Check the error above." -ForegroundColor Red
}

Write-Host ""
