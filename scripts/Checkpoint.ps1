param(
  [string]$Message,
  [bool]$Push = $true,
  [bool]$CreateTag = $false,
  [string]$TagPrefix = 'checkpoint'
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

function Invoke-Git {
  param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
  & git @Args
  if ($LASTEXITCODE -ne 0) {
    throw "git $($Args -join ' ') failed with exit code $LASTEXITCODE"
  }
}

$status = & git status --porcelain
if (-not $status) {
  Write-Host 'No changes to checkpoint.'
  exit 0
}

Invoke-Git @('add', '-A')

# Keep transient build logs out of checkpoints even if they slip in locally.
if (Test-Path 'build-log.txt') {
  & git reset -- build-log.txt | Out-Null
}

$staged = & git diff --cached --name-only
if (-not $staged) {
  Write-Host 'No staged changes after filtering transient files.'
  exit 0
}

$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm'
$commitMessage = if ([string]::IsNullOrWhiteSpace($Message)) {
  "checkpoint: $timestamp"
} else {
  $Message
}

Invoke-Git @('commit', '-m', $commitMessage)

$createdTag = $null
if ($CreateTag) {
  $createdTag = "$TagPrefix-$(Get-Date -Format 'yyyyMMdd-HHmm')"
  Invoke-Git tag $createdTag
}

if ($Push) {
  try {
    Invoke-Git @('push', 'origin', 'HEAD')
    if ($createdTag) {
      Invoke-Git @('push', 'origin', $createdTag)
    }
  } catch {
    Write-Warning "Checkpoint commit created locally, but push failed: $($_.Exception.Message)"
  }
}

Write-Host "Checkpoint saved: $commitMessage"
if ($createdTag) {
  Write-Host "Tag created: $createdTag"
}
