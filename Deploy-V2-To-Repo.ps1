# =============================================================================
# Deploy-V2-To-Repo.ps1
#
# Purpose:
#   Copies all V2 scaffold and implementation files from the working V2 folder
#   into the real MailGuard repo, then patches main.py to include the V2 router.
#
# Run from:
#   C:\Users\gmikhailov\Downloads\mailguard    (the REAL repo root)
#
# Usage:
#   .\Deploy-V2-To-Repo.ps1
#
# Safety:
#   - Never modifies V1 files (except one additive patch to main.py)
#   - Checks for existing files before copying
#   - Creates all missing directories
#   - The main.py patch is guarded — only applied if not already present
# =============================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Adjust this if your V2 working folder is somewhere else
$V2Root   = "C:\Users\gmikhailov\Downloads\mailguard\V2"
$RepoRoot = "C:\Users\gmikhailov\Downloads\mailguard"

# =============================================================================
# HELPERS
# =============================================================================

function New-SafeDirectory {
    param([string]$Path)
    if (!(Test-Path -Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        Write-Host "  [created dir]  $Path"
    } else {
        Write-Host "  [exists]       $Path"
    }
}

function Copy-SafeFile {
    param([string]$Source, [string]$Destination)
    if (!(Test-Path -Path $Source)) {
        Write-Host "  [missing src]  $Source — skipped"
        return
    }
    # Always overwrite — these are V2 files we own, not V1
    Copy-Item -Path $Source -Destination $Destination -Force
    Write-Host "  [copied]       $(Split-Path $Source -Leaf) -> $Destination"
}

function New-SafeFile {
    param([string]$Path, [string]$Content = "")
    if (!(Test-Path -Path $Path)) {
        Set-Content -Path $Path -Value $Content -Encoding UTF8
        Write-Host "  [created file] $Path"
    } else {
        Write-Host "  [exists]       $Path"
    }
}

# =============================================================================
# SECTION 1 — Create all V2 directory structure in the real repo
# =============================================================================

Write-Host "`n[STEP 1] Creating V2 directory structure in real repo"

$dirs = @(
    # Backend — API
    "backend\app\api\v2",

    # Backend — Models
    "backend\app\models\v2",

    # Backend — Services
    "backend\app\services\v2",
    "backend\app\services\v2\scan_orchestrator",
    "backend\app\services\v2\posture",
    "backend\app\services\v2\posture\microsoft365",
    "backend\app\services\v2\posture\google_workspace",
    "backend\app\services\v2\public_intel",
    "backend\app\services\v2\public_intel\microsoft365",
    "backend\app\services\v2\public_intel\google_workspace",
    "backend\app\services\v2\exposure",
    "backend\app\services\v2\exposure\routing_analysis",
    "backend\app\services\v2\exposure\connector_analysis",
    "backend\app\services\v2\exposure\mx_analysis",
    "backend\app\services\v2\exposure\mailflow_graph",
    "backend\app\services\v2\exposure\microsoft365",
    "backend\app\services\v2\exposure\google_workspace",
    "backend\app\services\v2\simulation",
    "backend\app\services\v2\simulation\microsoft365",
    "backend\app\services\v2\simulation\google_workspace",
    "backend\app\services\v2\lookalike",
    "backend\app\services\v2\lookalike\algorithms",
    "backend\app\services\v2\external_intel",
    "backend\app\services\v2\assets",
    "backend\app\services\v2\reporting",

    # Backend — Shared
    "backend\app\shared",
    "backend\app\shared\graph",
    "backend\app\shared\workers",

    # Frontend
    "frontend\src\v2",
    "frontend\src\v2\api",
    "frontend\src\v2\types",
    "frontend\src\v2\layout",
    "frontend\src\v2\components",
    "frontend\src\v2\services",
    "frontend\src\v2\store",
    "frontend\src\v2\pages",
    "frontend\src\v2\pages\overview",
    "frontend\src\v2\pages\posture",
    "frontend\src\v2\pages\public_intel",
    "frontend\src\v2\pages\exposure",
    "frontend\src\v2\pages\simulation",
    "frontend\src\v2\pages\lookalikes",
    "frontend\src\v2\pages\assets",
    "frontend\src\v2\pages\history",
    "frontend\src\v2\pages\reports",
    "frontend\src\v2\pages\settings"
)

foreach ($dir in $dirs) {
    New-SafeDirectory (Join-Path $RepoRoot $dir)
}

# =============================================================================
# SECTION 2 — Copy backend Python files from V2 working folder
# =============================================================================

Write-Host "`n[STEP 2] Copying backend Python files"

# Models
Copy-SafeFile "$V2Root\backend\app\models\v2\finding.py"      "$RepoRoot\backend\app\models\v2\finding.py"
Copy-SafeFile "$V2Root\backend\app\models\v2\scan_request.py" "$RepoRoot\backend\app\models\v2\scan_request.py"
Copy-SafeFile "$V2Root\backend\app\models\v2\scan_result.py"  "$RepoRoot\backend\app\models\v2\scan_result.py"
Copy-SafeFile "$V2Root\backend\app\models\v2\__init__.py"     "$RepoRoot\backend\app\models\v2\__init__.py"

# API V2
Copy-SafeFile "$V2Root\backend\app\api\v2\router.py"          "$RepoRoot\backend\app\api\v2\router.py"
Copy-SafeFile "$V2Root\backend\app\api\v2\__init__.py"        "$RepoRoot\backend\app\api\v2\__init__.py"

# Scan orchestrator
Copy-SafeFile "$V2Root\backend\app\services\v2\scan_orchestrator\orchestrator.py"    "$RepoRoot\backend\app\services\v2\scan_orchestrator\orchestrator.py"
Copy-SafeFile "$V2Root\backend\app\services\v2\scan_orchestrator\module_registry.py" "$RepoRoot\backend\app\services\v2\scan_orchestrator\module_registry.py"
Copy-SafeFile "$V2Root\backend\app\services\v2\scan_orchestrator\run_scan.py"        "$RepoRoot\backend\app\services\v2\scan_orchestrator\run_scan.py"
Copy-SafeFile "$V2Root\backend\app\services\v2\scan_orchestrator\scan_families.py"   "$RepoRoot\backend\app\services\v2\scan_orchestrator\scan_families.py"
Copy-SafeFile "$V2Root\backend\app\services\v2\scan_orchestrator\scan_job_model.py"  "$RepoRoot\backend\app\services\v2\scan_orchestrator\scan_job_model.py"
Copy-SafeFile "$V2Root\backend\app\services\v2\scan_orchestrator\__init__.py"        "$RepoRoot\backend\app\services\v2\scan_orchestrator\__init__.py"

# Public intel
Copy-SafeFile "$V2Root\backend\app\services\v2\public_intel\microsoft365\tenant_discovery.py" "$RepoRoot\backend\app\services\v2\public_intel\microsoft365\tenant_discovery.py"
Copy-SafeFile "$V2Root\backend\app\services\v2\public_intel\microsoft365\__init__.py"         "$RepoRoot\backend\app\services\v2\public_intel\microsoft365\__init__.py"
Copy-SafeFile "$V2Root\backend\app\services\v2\public_intel\__init__.py"                      "$RepoRoot\backend\app\services\v2\public_intel\__init__.py"

# External intel
Copy-SafeFile "$V2Root\backend\app\services\v2\external_intel\base_provider.py" "$RepoRoot\backend\app\services\v2\external_intel\base_provider.py"
Copy-SafeFile "$V2Root\backend\app\services\v2\external_intel\whois_lookup.py"  "$RepoRoot\backend\app\services\v2\external_intel\whois_lookup.py"
Copy-SafeFile "$V2Root\backend\app\services\v2\external_intel\ip_reputation.py" "$RepoRoot\backend\app\services\v2\external_intel\ip_reputation.py"
Copy-SafeFile "$V2Root\backend\app\services\v2\external_intel\domain_age.py"    "$RepoRoot\backend\app\services\v2\external_intel\domain_age.py"
Copy-SafeFile "$V2Root\backend\app\services\v2\external_intel\breach_lookup.py" "$RepoRoot\backend\app\services\v2\external_intel\breach_lookup.py"
Copy-SafeFile "$V2Root\backend\app\services\v2\external_intel\asn_lookup.py"    "$RepoRoot\backend\app\services\v2\external_intel\asn_lookup.py"
Copy-SafeFile "$V2Root\backend\app\services\v2\external_intel\__init__.py"      "$RepoRoot\backend\app\services\v2\external_intel\__init__.py"

# Exposure
Copy-SafeFile "$V2Root\backend\app\services\v2\exposure\base_analyzer.py" "$RepoRoot\backend\app\services\v2\exposure\base_analyzer.py"
Copy-SafeFile "$V2Root\backend\app\services\v2\exposure\__init__.py"      "$RepoRoot\backend\app\services\v2\exposure\__init__.py"

# Lookalike algorithms
Copy-SafeFile "$V2Root\backend\app\services\v2\lookalike\algorithms\registry.py"        "$RepoRoot\backend\app\services\v2\lookalike\algorithms\registry.py"
Copy-SafeFile "$V2Root\backend\app\services\v2\lookalike\algorithms\load_algorithms.py" "$RepoRoot\backend\app\services\v2\lookalike\algorithms\load_algorithms.py"
Copy-SafeFile "$V2Root\backend\app\services\v2\lookalike\algorithms\levenshtein.py"     "$RepoRoot\backend\app\services\v2\lookalike\algorithms\levenshtein.py"
Copy-SafeFile "$V2Root\backend\app\services\v2\lookalike\algorithms\homoglyph.py"       "$RepoRoot\backend\app\services\v2\lookalike\algorithms\homoglyph.py"
Copy-SafeFile "$V2Root\backend\app\services\v2\lookalike\algorithms\keyboard_swap.py"   "$RepoRoot\backend\app\services\v2\lookalike\algorithms\keyboard_swap.py"
Copy-SafeFile "$V2Root\backend\app\services\v2\lookalike\algorithms\tld_swap.py"        "$RepoRoot\backend\app\services\v2\lookalike\algorithms\tld_swap.py"
Copy-SafeFile "$V2Root\backend\app\services\v2\lookalike\algorithms\__init__.py"        "$RepoRoot\backend\app\services\v2\lookalike\algorithms\__init__.py"
Copy-SafeFile "$V2Root\backend\app\services\v2\lookalike\__init__.py"                   "$RepoRoot\backend\app\services\v2\lookalike\__init__.py"

# Assets
Copy-SafeFile "$V2Root\backend\app\services\v2\assets\asset_types.py" "$RepoRoot\backend\app\services\v2\assets\asset_types.py"
Copy-SafeFile "$V2Root\backend\app\services\v2\assets\__init__.py"    "$RepoRoot\backend\app\services\v2\assets\__init__.py"

# Shared graph + workers
Copy-SafeFile "$V2Root\backend\app\shared\graph\asset_graph.py"         "$RepoRoot\backend\app\shared\graph\asset_graph.py"
Copy-SafeFile "$V2Root\backend\app\shared\graph\attack_path_engine.py"  "$RepoRoot\backend\app\shared\graph\attack_path_engine.py"
Copy-SafeFile "$V2Root\backend\app\shared\graph\__init__.py"            "$RepoRoot\backend\app\shared\graph\__init__.py"
Copy-SafeFile "$V2Root\backend\app\shared\workers\job_queue.py"         "$RepoRoot\backend\app\shared\workers\job_queue.py"
Copy-SafeFile "$V2Root\backend\app\shared\workers\scan_worker.py"       "$RepoRoot\backend\app\shared\workers\scan_worker.py"
Copy-SafeFile "$V2Root\backend\app\shared\workers\__init__.py"          "$RepoRoot\backend\app\shared\workers\__init__.py"
Copy-SafeFile "$V2Root\backend\app\shared\__init__.py"                  "$RepoRoot\backend\app\shared\__init__.py"

# Remaining service __init__ files
New-SafeFile "$RepoRoot\backend\app\services\v2\__init__.py"                             "# MailGuard V2 services"
New-SafeFile "$RepoRoot\backend\app\services\v2\posture\__init__.py"                     "# Posture scan family"
New-SafeFile "$RepoRoot\backend\app\services\v2\posture\microsoft365\__init__.py"        "# Posture — Microsoft 365 adapter"
New-SafeFile "$RepoRoot\backend\app\services\v2\posture\google_workspace\__init__.py"    "# Posture — Google Workspace adapter (stub)"
New-SafeFile "$RepoRoot\backend\app\services\v2\public_intel\google_workspace\__init__.py" "# Public Intel — Google Workspace (stub)"
New-SafeFile "$RepoRoot\backend\app\services\v2\exposure\routing_analysis\__init__.py"   "# Placeholder - routing analysis"
New-SafeFile "$RepoRoot\backend\app\services\v2\exposure\connector_analysis\__init__.py" "# Placeholder - connector analysis"
New-SafeFile "$RepoRoot\backend\app\services\v2\exposure\mx_analysis\__init__.py"        "# Placeholder - MX analysis"
New-SafeFile "$RepoRoot\backend\app\services\v2\exposure\mailflow_graph\__init__.py"     "# Placeholder - mailflow graph"
New-SafeFile "$RepoRoot\backend\app\services\v2\exposure\microsoft365\__init__.py"       "# Exposure — Microsoft 365"
New-SafeFile "$RepoRoot\backend\app\services\v2\exposure\google_workspace\__init__.py"   "# Exposure — Google Workspace (stub)"
New-SafeFile "$RepoRoot\backend\app\services\v2\simulation\__init__.py"                  "# Attack Simulation — scaffold only"
New-SafeFile "$RepoRoot\backend\app\services\v2\simulation\microsoft365\__init__.py"     "# Simulation — Microsoft 365 (not implemented)"
New-SafeFile "$RepoRoot\backend\app\services\v2\simulation\google_workspace\__init__.py" "# Simulation — Google Workspace (not implemented)"
New-SafeFile "$RepoRoot\backend\app\services\v2\reporting\__init__.py"                   "# Reporting service"

# feature_flags — only if missing (V1 core is shared)
New-SafeFile "$RepoRoot\backend\app\core\feature_flags.py" @"
# Feature Flags — controls which V2 modules are active

FEATURE_FLAGS = {
    "v2_posture":       False,
    "v2_public_intel":  False,
    "v2_exposure":      False,
    "v2_simulation":    False,
    "v2_lookalike":     False,
    "v2_reporting":     False,
}
"@

# =============================================================================
# SECTION 3 — Copy frontend files
# =============================================================================

Write-Host "`n[STEP 3] Copying frontend files"

Copy-SafeFile "$V2Root\frontend\src\v2\api\client.ts"                  "$RepoRoot\frontend\src\v2\api\client.ts"
Copy-SafeFile "$V2Root\frontend\src\v2\types\Finding.ts"               "$RepoRoot\frontend\src\v2\types\Finding.ts"
Copy-SafeFile "$V2Root\frontend\src\v2\types\ScanResult.ts"            "$RepoRoot\frontend\src\v2\types\ScanResult.ts"
Copy-SafeFile "$V2Root\frontend\src\v2\types\Tenant.ts"                "$RepoRoot\frontend\src\v2\types\Tenant.ts"
Copy-SafeFile "$V2Root\frontend\src\v2\types\PublicIntelResult.ts"     "$RepoRoot\frontend\src\v2\types\PublicIntelResult.ts"
Copy-SafeFile "$V2Root\frontend\src\v2\pages\public_intel\PublicIntelPage.tsx" "$RepoRoot\frontend\src\v2\pages\public_intel\PublicIntelPage.tsx"

# =============================================================================
# SECTION 4 — Patch main.py to include the V2 router (additive only)
# =============================================================================

Write-Host "`n[STEP 4] Patching main.py to include V2 router"

$mainPy     = "$RepoRoot\backend\app\main.py"
$mainContent = Get-Content $mainPy -Raw

$importLine = "from app.api.v2 import v2_router"
$routerLine = "app.include_router(v2_router, prefix=""/api/v2"", tags=[""V2""])"

if ($mainContent -notmatch "v2_router") {

    # Insert import after the last existing "from app.api import ..." line
    $importBlock = "from app.api import tenants, scans, reports, onboarding, vendor_pdfs, auth, google_auth, aggressive_scan"
    $newImportBlock = $importBlock + "`nfrom app.api.v2 import v2_router  # MailGuard V2 router"
    $mainContent = $mainContent.Replace($importBlock, $newImportBlock)

    # Insert router registration after the last app.include_router line in the API routes block
    $lastRouter = 'app.include_router(aggressive_scan.router,  prefix="/api/v1/aggressive-scan",  tags=["Aggressive Scan"])'
    $newLastRouter = $lastRouter + "`napp.include_router(v2_router, prefix=""/api/v2"", tags=[""V2""])  # MailGuard V2"
    $mainContent = $mainContent.Replace($lastRouter, $newLastRouter)

    Set-Content -Path $mainPy -Value $mainContent -Encoding UTF8
    Write-Host "  [patched]      main.py — V2 router added"
} else {
    Write-Host "  [exists]       main.py already contains v2_router — skipped"
}

# =============================================================================
# SECTION 5 — Install httpx if needed
# =============================================================================

Write-Host "`n[STEP 5] Ensuring httpx is in requirements.txt"

$reqFile = "$RepoRoot\backend\requirements.txt"
$reqContent = Get-Content $reqFile -Raw

if ($reqContent -notmatch "httpx") {
    Add-Content -Path $reqFile -Value "`nhttpx>=0.27.0"
    Write-Host "  [added]        httpx>=0.27.0 to requirements.txt"
} else {
    Write-Host "  [exists]       httpx already in requirements.txt"
}

# =============================================================================
# DONE
# =============================================================================

Write-Host "`n=============================================="
Write-Host " Deploy complete."
Write-Host ""
Write-Host " Next steps:"
Write-Host "   cd $RepoRoot\backend"
Write-Host "   python -m uvicorn app.main:app --reload"
Write-Host ""
Write-Host " Then test:"
Write-Host "   curl http://localhost:8000/api/v2/health"
Write-Host "   curl http://localhost:8000/api/v2/public-intel/microsoft.com"
Write-Host "=============================================="
