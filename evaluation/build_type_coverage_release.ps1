param([string]$ReleaseName = 'type_coverage_reconstructed_20261008')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if ($ReleaseName -notmatch '^[a-z][a-z0-9_]+$') { throw 'Invalid release name.' }
$releaseRoot = Join-Path $projectRoot ('releases\' + $ReleaseName)
$baseline = Get-Content -LiteralPath (Join-Path $projectRoot 'baselines\type_coverage_reconstructed_20261008\baseline.json') -Raw | ConvertFrom-Json
$realRun = Join-Path $projectRoot 'output\reconstructed_llm60_eval_20261008'
$report = Get-Content -LiteralPath (Join-Path $realRun 'report.json') -Raw | ConvertFrom-Json
$audit = Get-Content -LiteralPath (Join-Path $realRun 'audit.json') -Raw | ConvertFrom-Json
if (-not $report.github_upload_eligible -or -not $audit.passed) { throw 'Conditional publication gate failed.' }
$sourceRoot = Join-Path $projectRoot 'development\type_coverage_reconstructed_20261008\src'
$hashes = [ordered]@{}
foreach ($property in $baseline.code_hashes.PSObject.Properties) {
    $relative = $property.Name.Replace('\','/')
    $source = Join-Path $sourceRoot $relative
    $target = [IO.Path]::GetFullPath((Join-Path (Join-Path $releaseRoot 'src') $relative))
    if (-not $target.StartsWith((Join-Path $releaseRoot 'src') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Escaping source path.' }
    if ([IO.Path]::GetExtension($relative) -ne '.py' -or (Test-Path -LiteralPath $target)) { throw 'Unexpected file or overwrite.' }
    if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLower() -ne $property.Value) { throw 'Source hash changed.' }
    New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
    Copy-Item -LiteralPath $source -Destination $target
    if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLower() -ne $property.Value) { throw 'Release copy changed.' }
    $hashes[$relative] = $property.Value
}
$profile = [ordered]@{
    name=$ReleaseName
    status='EXPERIMENTAL reconstructed development foundation, not exact historical source'
    settings=$baseline.settings
    source_hashes=$hashes
    graph_token_budget=4096
    output_token_ceiling=150
    max_steps=2
    historical_f1_reference=0.6115107913669064
    historical_score_transferable=$false
    live_smoke=[ordered]@{rows=30;repeats=2;planned_results=60;seed=20261009;exact_sources=26;family_groups=21;report='smoke_summary.json'}
    source_manifest_sha256=$baseline.source_manifest_sha256
}
$profile | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $releaseRoot 'profile.json') -Encoding utf8
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $releaseRoot 'smoke_summary.json') -Encoding utf8
Write-Output ('PACKAGE PASS source_files=' + $hashes.Count + ' no credentials/datasets/weights/raw receipts copied')
