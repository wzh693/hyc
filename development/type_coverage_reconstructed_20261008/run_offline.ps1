param(
    [string]$Python = (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe'),
    [string]$OutputDir = '',
    [switch]$Frozen
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$baseline = Join-Path $projectRoot 'baselines\type_coverage_reconstructed_20261008'
$sourceRoot = Join-Path $PSScriptRoot 'src'
if ($Frozen) { $sourceRoot = Join-Path $baseline 'src' }
if (-not $OutputDir) {
    $OutputDir = Join-Path $PSScriptRoot ('offline_audit_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
}
if (Test-Path -LiteralPath $OutputDir) { throw 'Use a new output directory.' }
Push-Location $projectRoot
try {
    & $Python -B 'evaluation\audit_type_coverage_baseline.py' --baseline $baseline --code-root $sourceRoot --output $OutputDir
    if ($LASTEXITCODE -ne 0) { throw ('Offline audit failed: ' + $LASTEXITCODE) }
}
finally { Pop-Location }
