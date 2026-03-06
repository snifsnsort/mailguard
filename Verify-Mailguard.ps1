# Verify-Mailguard.ps1
# Run from the root of your mailguard directory (where Dockerfile lives)
# Usage: .\Verify-Mailguard.ps1

$ErrorCount   = 0
$WarnCount    = 0
$CheckCount   = 0
$FilesScanned = [System.Collections.Generic.HashSet[string]]::new()

function Pass($msg)  { Write-Host "  [PASS] $msg" -ForegroundColor Green;  $script:CheckCount++ }
function Fail($msg)  { Write-Host "  [FAIL] $msg" -ForegroundColor Red;    $script:ErrorCount++; $script:CheckCount++ }
function Warn($msg)  { Write-Host "  [WARN] $msg" -ForegroundColor Yellow; $script:WarnCount++;  $script:CheckCount++ }
function Section($t) { Write-Host "`n--- $t ---" -ForegroundColor Cyan }

function Track-File($path) {
    $null = $script:FilesScanned.Add($path.ToLower().TrimStart(".\").Replace("/","\"))
}
function Check-File($path) {
    Track-File $path
    if (Test-Path $path) { Pass "EXISTS   $path" }
    else                 { Fail "MISSING  $path" }
}
function Check-Contains($path, $needle, $label) {
    Track-File $path
    if (-not (Test-Path $path)) { Fail "FILE MISSING — cannot check '$label' in $path"; return }
    $content = Get-Content $path -Raw
    if ($content -match [regex]::Escape($needle)) { Pass "FOUND    $label" }
    else                                           { Fail "MISSING  $label  (in $path)" }
}
function Check-NotContains($path, $needle, $label) {
    Track-File $path
    if (-not (Test-Path $path)) { Fail "FILE MISSING — cannot check '$label' in $path"; return }
    $content = Get-Content $path -Raw
    if ($content -match [regex]::Escape($needle)) { Fail "STILL PRESENT  $label  (in $path)" }
    else                                           { Pass "REMOVED  $label" }
}

# =============================================================================
Section "Working directory"
# =============================================================================
Write-Host "  CWD: $((Get-Location).Path)" -ForegroundColor White
if (-not (Test-Path "Dockerfile")) { Fail "Not in mailguard root — Dockerfile not found"; exit 1 }
else { Pass "Dockerfile present" }

# =============================================================================
Section "File tree — all required files"
# =============================================================================
@(
    "Dockerfile",
    "Build-And-Deploy.ps1",
    "Setup-Storage.ps1",
    "Verify-Mailguard.ps1",
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
    "frontend\src\pages\LookalikeScan.jsx",
    "frontend\src\utils\api.js",
    "backend\start.py",
    "backend\requirements.txt",
    "backend\app\main.py",
    "backend\app\core\auth.py",
    "backend\app\core\config.py",
    "backend\app\core\database.py",
    "backend\app\core\security.py",
    "backend\app\api\tenants.py",
    "backend\app\api\scans.py",
    "backend\app\api\reports.py",
    "backend\app\api\auth.py",
    "backend\app\api\google_auth.py",
    "backend\app\api\aggressive_scan.py",
    "backend\app\models\scan.py",
    "backend\app\models\tenant.py",
    "backend\app\models\aggressive_scan.py",
    "backend\app\services\scan_engine.py",
    "backend\app\services\mx_analyzer.py",
    "backend\app\services\report_generator.py",
    "backend\app\services\graph_client.py",
    "backend\app\services\lookalike_detector.py",
    "backend\app\services\aggressive_lookalike.py"
) | ForEach-Object { Check-File $_ }

# =============================================================================
Section "Dockerfile"
# =============================================================================
Check-Contains    "Dockerfile" "mkdir -p /data"   "/data directory created in image"
Check-NotContains "Dockerfile" "CLERK"             "Clerk removed"

# =============================================================================
Section "Build-And-Deploy.ps1"
# =============================================================================
Check-Contains    "Build-And-Deploy.ps1" "Deactivating current revisions"      "deactivates old revisions before image update"
Check-Contains    "Build-And-Deploy.ps1" "containerapp update"                 "uses az containerapp update"
Check-Contains    "Build-And-Deploy.ps1" "--image"                             "--image flag present"
Check-Contains    "Build-And-Deploy.ps1" "runningState"                        "revision state polling present"
Check-Contains    "Build-And-Deploy.ps1" "api/health"                          "health check after deploy"
Check-Contains    "Build-And-Deploy.ps1" "Setup-Storage"                       "warns to run Setup-Storage.ps1"
Check-Contains    "Build-And-Deploy.ps1" "RISK_ORDER"                          "LookalikeScan sort sanity check"
Check-Contains    "Build-And-Deploy.ps1" "sha256"                              "security.py stable key sanity check"
Check-Contains    "Build-And-Deploy.ps1" "restore_gws_tokens"                  "GWS restore sanity check"
Check-NotContains "Build-And-Deploy.ps1" "--set-env-vars"                      "dangerous --set-env-vars absent"

# =============================================================================
Section "Setup-Storage.ps1"
# =============================================================================
Check-Contains    "Setup-Storage.ps1" "mailguard-storage"          "storage link step present"
Check-Contains    "Setup-Storage.ps1" "mountPath.*\/data"           "volume mounts at /data"
Check-Contains    "Setup-Storage.ps1" "az rest"                    "uses az rest PATCH for mount"
Check-Contains    "Setup-Storage.ps1" "runningState"               "waits for revision state"
Check-Contains    "Setup-Storage.ps1" "Reconnect Google Workspace"  "reconnect reminder present"

# =============================================================================
Section "config.py — database path + bool fix"
# =============================================================================
Check-Contains    "backend\app\core\config.py" "sqlite:////tmp/mailguard.db"     "DATABASE_URL in local /tmp (not SMB mount)"
Check-Contains    "backend\app\core\config.py" "MULTI_TENANT_MODE: str"          "MULTI_TENANT_MODE is str (pydantic v2 empty-string fix)"
Check-Contains    "backend\app\core\config.py" "multi_tenant_mode"               "multi_tenant_mode bool property present"

# =============================================================================
Section "security.py — stable encryption key"
# =============================================================================
Check-Contains    "backend\app\core\security.py" "sha256"                  "SHA-256 key derivation"
Check-Contains    "backend\app\core\security.py" "SECRET_KEY"              "SECRET_KEY as key source"
Check-NotContains "backend\app\core\security.py" "Fernet.generate_key()"  "random per-process key removed"

# =============================================================================
Section "google_auth.py — GWS token backup"
# =============================================================================
Check-Contains    "backend\app\api\google_auth.py" "_backup_gws_token"   "backup function present"
Check-Contains    "backend\app\api\google_auth.py" "gws_tokens.json"     "backup file path"
Check-Contains    "backend\app\api\google_auth.py" "os.replace"          "atomic write"
Check-Contains    "backend\app\api\google_auth.py" "failed to decrypt"   "decrypt error caught"



# =============================================================================
Section "database.py"
# =============================================================================
Check-Contains    "backend\app\core\database.py" "aggressive_scan"    "aggressive_scan in init_db"
Check-Contains    "backend\app\core\database.py" "os.makedirs"        "mkdir before create_engine (volume mount safety)"
Check-Contains    "backend\app\core\database.py" "journal_mode=WAL"   "WAL mode enabled (prevents db locked on revision overlap)"
Check-Contains    "backend\app\core\database.py" "busy_timeout"       "busy_timeout set (retry on lock contention)"

# =============================================================================
Section "start.py — startup resilience"
# =============================================================================
Check-Contains    "backend\start.py" "restore_gws_tokens"    "restore function defined"
Check-Contains    "backend\start.py" "gws_tokens.json"       "reads backup file"
Check-Contains    "backend\start.py" "restore_gws_tokens()"  "restore called at startup"
Check-Contains    "backend\start.py" "attempt"               "init_db retry loop present"

# =============================================================================
Section "main.py"
# =============================================================================
Check-Contains    "backend\app\main.py" "aggressive-scan"            "aggressive-scan router"
Check-Contains    "backend\app\main.py" "app.models.aggressive_scan" "aggressive_scan model imported"

# =============================================================================
Section "index.css"
# =============================================================================
Check-Contains    "frontend\src\index.css" "--muted: #8ba4be"     "muted #8ba4be"
Check-Contains    "frontend\src\index.css" "--muted-dim: #5a7290" "--muted-dim"
Check-Contains    "frontend\src\index.css" "DM Sans"              "DM Sans font"
Check-Contains    "frontend\src\index.css" "Space Mono"           "Space Mono font"

# =============================================================================
Section "index.html"
# =============================================================================
Check-Contains    "frontend\index.html" "fonts.googleapis.com"  "Google Fonts link"
Check-Contains    "frontend\index.html" "DM+Sans"               "DM Sans loaded"
Check-Contains    "frontend\index.html" "Space+Mono"            "Space Mono loaded"

# =============================================================================
Section "Sidebar.jsx"
# =============================================================================
Check-Contains    "frontend\src\components\Sidebar.jsx" "color:'var(--text)'" "navItem uses var(--text)"
Check-Contains    "frontend\src\components\Sidebar.jsx" "Switch tenant"        "Switch tenant button"
Check-Contains    "frontend\src\components\Sidebar.jsx" "lookalike-scan"       "Lookalike Scanner link"
Check-Contains    "frontend\src\components\Sidebar.jsx" "Crosshair"            "Crosshair icon"

# =============================================================================
Section "Dashboard.jsx"
# =============================================================================
Check-NotContains "frontend\src\pages\Dashboard.jsx" "gridTemplateColumns:'240px 1fr 260px'" "phantom 3rd column gone"
Check-Contains    "frontend\src\pages\Dashboard.jsx" "gridTemplateColumns:'240px 1fr'"       "correct 2-column grid"
Check-Contains    "frontend\src\pages\Dashboard.jsx" "finished_at"                           "finished_at timestamp"

# =============================================================================
Section "LookalikeScan.jsx"
# =============================================================================
Check-Contains    "frontend\src\pages\LookalikeScan.jsx" "exportCSV"     "CSV export"
Check-Contains    "frontend\src\pages\LookalikeScan.jsx" "exportPDF"     "PDF export"
Check-Contains    "frontend\src\pages\LookalikeScan.jsx" "RISK_ORDER"    "risk category sort"
Check-Contains    "frontend\src\pages\LookalikeScan.jsx" "sortKey"       "sortKey state"
Check-Contains    "frontend\src\pages\LookalikeScan.jsx" "handleSort"    "handleSort function"
Check-Contains    "frontend\src\pages\LookalikeScan.jsx" "SortIcon"      "SortIcon component"

# =============================================================================
Section "mx_analyzer.py"
# =============================================================================
Check-Contains    "backend\app\services\mx_analyzer.py" "iphmx.com"            "Cisco iphmx.com"
Check-Contains    "backend\app\services\mx_analyzer.py" "fortimail.com"        "Fortinet FortiMail"
Check-Contains    "backend\app\services\mx_analyzer.py" "hornetsecurity.com"   "Hornetsecurity"
Check-Contains    "backend\app\services\mx_analyzer.py" "ROUTING_MULTI_SEG"    "ROUTING_MULTI_SEG"
Check-Contains    "backend\app\services\mx_analyzer.py" "ROUTING_INCONSISTENT" "ROUTING_INCONSISTENT"
Check-Contains    "backend\app\services\mx_analyzer.py" "_resolve_a_records"   "A-record resolver"

# =============================================================================
Section "scan_engine.py"
# =============================================================================
Check-Contains    "backend\app\services\scan_engine.py" "skip_mx_routing=self._has_m365" "GWS MX routing skipped"
Check-Contains    "backend\app\services\scan_engine.py" "Multiple conflicting SEG"        "multi-SEG conflict"
Check-Contains    "backend\app\services\scan_engine.py" "Multiple SPF records found"      "multiple SPF detection"
Check-Contains    "backend\app\services\scan_engine.py" "Too many DNS lookups"            "SPF lookup limit"
Check-Contains    "backend\app\services\scan_engine.py" "Multiple DMARC records found"    "multiple DMARC detection"
Check-Contains    "backend\app\services\scan_engine.py" "Unlimited (not configured)"      "anti-spam 0=unlimited"
Check-Contains    "backend\app\services\scan_engine.py" "bypass risk not applicable"      "SEG bypass N/A"

# =============================================================================
Section "lookalike_detector.py"
# =============================================================================
Check-Contains    "backend\app\services\lookalike_detector.py" "fetch_rdap"                "RDAP enrichment"
Check-Contains    "backend\app\services\lookalike_detector.py" "fetch_ct_crtsh"            "CT lookup"
Check-Contains    "backend\app\services\lookalike_detector.py" "detect_subdomain_takeover"  "takeover detection"
Check-Contains    "backend\app\services\lookalike_detector.py" "has_any_signal"             "no-signal low rule"
Check-Contains    "backend\app\services\lookalike_detector.py" "age_days <= 365"            "1-year critical threshold"
Check-Contains    "backend\app\services\lookalike_detector.py" "age_days > 1095"            "3-year low threshold"
Check-Contains    "backend\app\services\lookalike_detector.py" "has_aaaa"                   "AAAA records"
Check-Contains    "backend\app\services\lookalike_detector.py" "has_ns"                     "NS records"

# =============================================================================
Section "aggressive_lookalike.py"
# =============================================================================
Check-Contains    "backend\app\services\aggressive_lookalike.py" "run_aggressive_scan"             "orchestrator present"
Check-Contains    "backend\app\services\aggressive_lookalike.py" "base_domain_set"                 "base domains filtered"
Check-Contains    "backend\app\services\aggressive_lookalike.py" "-r.enriched_score, r.candidate"  "sort: score desc, alpha"

# =============================================================================
Section "Auth — login loop fixes"
# =============================================================================
Check-Contains    "frontend\src\App.jsx"         "stay logged in even if tenants fail"  "logout-on-tenant-fail removed"
Check-Contains    "backend\app\api\auth.py"      "hardcoded_default"                    "must_change only for literal changeme"
Check-NotContains "backend\app\api\auth.py"      "except Exception:\n        pass"      "silent exception swallow removed from _set_stored_password"

# =============================================================================
Section "Clerk removal"
# =============================================================================
Check-NotContains "backend\app\core\auth.py"   "clerk"              "Clerk removed from auth"
Check-NotContains "backend\app\core\config.py" "CLERK_SECRET_KEY"   "CLERK_SECRET_KEY gone"
Check-NotContains "frontend\package.json"       "@clerk/clerk-react" "Clerk npm package gone"

# =============================================================================
Section "Summary"
# =============================================================================
$passed = $CheckCount - $ErrorCount - $WarnCount
Write-Host ""
Write-Host ("  " + ("=" * 52)) -ForegroundColor DarkGray
Write-Host "  Files scanned : $($FilesScanned.Count)" -ForegroundColor White
Write-Host "  Checks run    : $CheckCount"             -ForegroundColor White
Write-Host "  Passed        : $passed"                 -ForegroundColor Green
if ($WarnCount  -gt 0) { Write-Host "  Warnings      : $WarnCount"  -ForegroundColor Yellow }
if ($ErrorCount -gt 0) { Write-Host "  Failures      : $ErrorCount" -ForegroundColor Red    }
Write-Host ("  " + ("=" * 52)) -ForegroundColor DarkGray
Write-Host ""

if ($ErrorCount -eq 0 -and $WarnCount -eq 0) {
    Write-Host "  ALL CHECKS PASSED — safe to run .\Build-And-Deploy.ps1" -ForegroundColor Green
} elseif ($ErrorCount -eq 0) {
    Write-Host "  $WarnCount warning(s), 0 errors — review then build" -ForegroundColor Yellow
} else {
    Write-Host "  $ErrorCount FAILURE(S) — DO NOT BUILD until fixed" -ForegroundColor Red
    Write-Host ""
    Write-Host "  To fix: extract mailguard-full.zip from Claude outputs," -ForegroundColor Yellow
    Write-Host "  replace this directory, then re-run .\Verify-Mailguard.ps1" -ForegroundColor Yellow
}
Write-Host ""
