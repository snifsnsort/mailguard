param(
  [string]$Message,
  [bool]$Push = $true,
  [bool]$CreateTag = $false
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

& docker compose build
if ($LASTEXITCODE -ne 0) {
  throw "docker compose build failed with exit code $LASTEXITCODE"
}

$checkpointScript = Join-Path $PSScriptRoot 'Checkpoint.ps1'
& $checkpointScript -Message $Message -Push:$Push -CreateTag:$CreateTag
