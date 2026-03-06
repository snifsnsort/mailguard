# Verify-Mailguard.ps1
# Run from the root of your mailguard repo directory (where Dockerfile lives)
# Usage: .\Verify-Mailguard.ps1

$ErrorCount = 0
$WarnCount  = 0

function Pass($msg)  { Write-Host "  [PASS] $msg" -ForegroundColor Green }
function Fail($msg)  { Write-Host "  [FAIL] $msg" -ForegroundColor Red;    $script:ErrorCount++ }
function Warn($msg)  { Write-Host "  [WARN] $msg" -ForegroundColor Yellow; $script:WarnCount++ }
function Section($t) { Write-Host "`n--- $t ---" -ForegroundColor Cyan }

# ── Helper: file exists ───────────────────────────────────────────────────────
function Check-File($path) {
    if (Test-Path $path) { Pass "EXISTS   $path" }
    else                 { Fail "MISSING  $path" }
}

# ── Helper: file contains string ─────────────────────────────────────────────
function Check-Contains($path, $needle, $label) {
    if (-not (Test-Path $path)) { Fail "FILE MISSING — cannot check '$label' in $path"; return }
    $content = Get-Content $path -Raw
    if ($content -match [regex]::Escape($needle)) { Pass "FOUND    $label" }
    else                                           { Fail "MISSING  $label  (in $path)" }
}

function Check-NotContains($path, $needle, $label) {
    if (-not (Test-Path $path)) { Fail "FILE MISSING — cannot check '$label' in $path"; return }
    $content = Get-Content $path -Raw
    if ($content -match [regex]::Escape($needle)) { Fail "STILL PRESENT  $label  (in $path)" }
    else                                           { Pass "REMOVED  $label" }
}

# =============================================================================
Section "Working directory"
# =============================================================================
$cwd = (Get-Location).Path
Write-Host "  CWD: $cwd" -ForegroundColor White
if (-not (Test-Path "Dockerfile")) { Fail "Not in mailguard root — Dockerfile not found. cd to correct directory first." ; exit 1 }
else { Pass "Dockerfile present — looks like mailguard root" }

# =============================================================================
Section "File tree — critical files must exist"
# =============================================================================
$requiredFiles = @(
    "Dockerfile",
    "deploy.ps1",
    "frontend\index.html",
    "frontend\package.json",
    "frontend\vite.config.js",
    "frontend\src\index.css",
    "frontend\src\App.jsx",
    "frontend\src\main.jsx",
    "frontend\src\components\Sidebar.jsx",
    "frontend\src\components\CheckRow.jsx",
    "frontend\src\components\ConnectModal.jsx",
    "frontend\src\components\DetailPanel.jsx",
    "frontend\src\pages\Dashboard.jsx",
    "frontend\src\pages\Checks.jsx",
    "frontend\src\pages\History.jsx",
    "frontend\src\pages\Connect.jsx",
    "frontend\src\pages\LoginPage.jsx",
    "frontend\src\utils\api.js",
    "backend\start.py",
    "backend\requirements.txt",
    "backend\app\main.py",
    "backend\app\core\auth.py",
    "backend\app\core\config.py",
    "backend\app\core\database.py",
    "backend\app\api\tenants.py",
    "backend\app\api\scans.py",
    "backend\app\api\reports.py",
    "backend\app\api\auth.py",
    "backend\app\services\scan_engine.py",
    "backend\app\services\mx_analyzer.py",
    "backend\app\services\report_generator.py",
    "backend\app\services\graph_client.py",
    "backend\app\services\lookalike_detector.py"
)
foreach ($f in $requiredFiles) { Check-File $f }

# =============================================================================
Section "index.css — UI colour fixes"
# =============================================================================
Check-Contains    "frontend\src\index.css" "--muted: #8ba4be"        "muted colour upgraded to #8ba4be (was #5a7290)"
Check-Contains    "frontend\src\index.css" "--muted-dim: #5a7290"    "old muted kept as --muted-dim"
Check-Contains    "frontend\src\index.css" "DM Sans"                 "DM Sans font reference"
Check-Contains    "frontend\src\index.css" "Space Mono"              "Space Mono font reference"

# =============================================================================
Section "frontend\index.html — Google Fonts"
# =============================================================================
Check-Contains    "frontend\index.html" "fonts.googleapis.com"       "Google Fonts link tag"
Check-Contains    "frontend\index.html" "DM+Sans"                    "DM Sans loaded from Google Fonts"
Check-Contains    "frontend\index.html" "Space+Mono"                 "Space Mono loaded from Google Fonts"

# =============================================================================
Section "Sidebar.jsx — nav link colour fix"
# =============================================================================
Check-Contains    "frontend\src\components\Sidebar.jsx" "color:'var(--text)'" "navItem uses var(--text) not var(--muted)"
Check-NotContains "frontend\src\components\Sidebar.jsx" "color:'var(--muted)',cursor:'pointer'" "old muted cursor:pointer style removed from navItem"
Check-Contains    "frontend\src\components\Sidebar.jsx" "Switch tenant" "Switch tenant button present"

# =============================================================================
Section "Dashboard.jsx — UI fixes"
# =============================================================================
Check-NotContains "frontend\src\pages\Dashboard.jsx" "gridTemplateColumns:'240px 1fr 260px'" "phantom 3rd grid column removed"
Check-Contains    "frontend\src\pages\Dashboard.jsx" "gridTemplateColumns:'240px 1fr'"       "correct 2-column grid"
Check-Contains    "frontend\src\pages\Dashboard.jsx" "Last scan:"                            "last scan timestamp shown"
Check-Contains    "frontend\src\pages\Dashboard.jsx" "finished_at"                           "finished_at used for timestamp"

# =============================================================================
Section "mx_analyzer.py — new SEG fingerprints"
# =============================================================================
Check-Contains    "backend\app\services\mx_analyzer.py" "iphmx.com"             "Cisco iphmx.com fingerprint"
Check-Contains    "backend\app\services\mx_analyzer.py" "fortimail.com"         "Fortinet FortiMail fingerprint"
Check-Contains    "backend\app\services\mx_analyzer.py" "hornetsecurity.com"    "Hornetsecurity fingerprint"
Check-Contains    "backend\app\services\mx_analyzer.py" "in.trend-net.net"      "Trend Micro trend-net.net fingerprint"
Check-Contains    "backend\app\services\mx_analyzer.py" "ROUTING_MULTI_SEG"     "ROUTING_MULTI_SEG constant"
Check-Contains    "backend\app\services\mx_analyzer.py" "ROUTING_SPLIT"         "ROUTING_SPLIT constant"
Check-Contains    "backend\app\services\mx_analyzer.py" "ROUTING_INCONSISTENT"  "ROUTING_INCONSISTENT constant"
Check-Contains    "backend\app\services\mx_analyzer.py" "multi_seg_conflict"    "multi_seg_conflict field on MxAnalysis"
Check-Contains    "backend\app\services\mx_analyzer.py" "is_google"             "is_google field on MxRecord"
Check-Contains    "backend\app\services\mx_analyzer.py" "_resolve_a_records"    "A-record resolver function"

# =============================================================================
Section "scan_engine.py — MX, SPF, DMARC improvements"
# =============================================================================
Check-Contains    "backend\app\services\scan_engine.py" "ROUTING_MULTI_SEG"              "scan_engine uses ROUTING_MULTI_SEG"
Check-Contains    "backend\app\services\scan_engine.py" "ROUTING_INCONSISTENT"           "scan_engine uses ROUTING_INCONSISTENT"
Check-Contains    "backend\app\services\scan_engine.py" "Multiple conflicting SEG"       "multi-SEG conflict message"
Check-Contains    "backend\app\services\scan_engine.py" "spf_records = [r for r"         "SPF multiple-record detection"
Check-Contains    "backend\app\services\scan_engine.py" "Multiple SPF records found"     "multiple SPF records error message"
Check-Contains    "backend\app\services\scan_engine.py" "lookup_count"                   "SPF DNS lookup counter"
Check-Contains    "backend\app\services\scan_engine.py" "Too many DNS lookups"           "SPF too-many-lookups message"
Check-Contains    "backend\app\services\scan_engine.py" "syntax_errors"                  "DMARC syntax error detection"
Check-Contains    "backend\app\services\scan_engine.py" "Multiple DMARC records found"   "multiple DMARC records error message"
Check-Contains    "backend\app\services\scan_engine.py" "Unlimited (not configured)"     "anti-spam 0=unlimited fix"
Check-Contains    "backend\app\services\scan_engine.py" "bypass risk not applicable"     "SEG bypass N/A description fix"

# =============================================================================
Section "Clerk removal"
# =============================================================================
Check-NotContains "backend\app\core\auth.py"   "clerk"              "Clerk removed from auth.py"
Check-NotContains "backend\app\core\config.py" "CLERK_SECRET_KEY"   "CLERK_SECRET_KEY removed from config"
Check-NotContains "frontend\package.json"       "@clerk/clerk-react" "Clerk npm package removed"
Check-NotContains "Dockerfile"                  "CLERK"              "Clerk ARG/ENV removed from Dockerfile"

# =============================================================================
Section "Summary"
# =============================================================================
Write-Host ""
if ($ErrorCount -eq 0 -and $WarnCount -eq 0) {
    Write-Host "ALL CHECKS PASSED — safe to docker build" -ForegroundColor Green
} elseif ($ErrorCount -eq 0) {
    Write-Host "$WarnCount warning(s), 0 errors — review warnings then build" -ForegroundColor Yellow
} else {
    Write-Host "$ErrorCount FAILURE(S), $WarnCount warning(s) — DO NOT BUILD until failures are fixed" -ForegroundColor Red
    Write-Host ""
    Write-Host "To fix: download mailguard-full.zip from Claude outputs and extract it here," -ForegroundColor Yellow
    Write-Host "replacing this directory entirely, then re-run this script." -ForegroundColor Yellow
}
