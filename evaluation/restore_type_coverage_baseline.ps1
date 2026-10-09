param(
    [string]$BaselineName = 'type_coverage_reconstructed_20261008'
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if ($BaselineName -notmatch '^[a-z][a-z0-9_]+$') { throw 'Invalid baseline name.' }
$destination = Join-Path $projectRoot ('baselines\' + $BaselineName)
$development = Join-Path $projectRoot ('development\' + $BaselineName)
if ((Test-Path -LiteralPath $destination) -or (Test-Path -LiteralPath $development)) {
    throw 'Refusing to overwrite a baseline or development directory.'
}
$oldSnapshot = Join-Path $projectRoot 'output\sven_full_pipeline_code_snapshot_20261006'
$oldManifestPath = Join-Path $projectRoot 'output\sven_full_pipeline_eval_20261006\manifest.json'
$currentManifestPath = Join-Path $projectRoot 'output\sven_budget_eval_20261008\manifest.json'
$historicalReportPath = Join-Path $projectRoot 'sven_eval\output_type_coverage_full\sven_report.json'
$oldManifest = Get-Content -LiteralPath $oldManifestPath -Raw | ConvertFrom-Json
$currentManifest = Get-Content -LiteralPath $currentManifestPath -Raw | ConvertFrom-Json
$historicalReport = Get-Content -LiteralPath $historicalReportPath -Raw | ConvertFrom-Json

function Assert-SourceHashes($sourceRoot, $hashes) {
    foreach ($property in $hashes.PSObject.Properties) {
        $sourcePath = [IO.Path]::GetFullPath((Join-Path $sourceRoot $property.Name))
        if (-not $sourcePath.StartsWith($sourceRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Manifest path escapes source root.'
        }
        if ((Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLower() -ne $property.Value) {
            throw ('Source hash mismatch: ' + $property.Name)
        }
    }
}
function Copy-VerifiedSources($sourceRoot, $targetRoot, $hashes) {
    foreach ($property in $hashes.PSObject.Properties) {
        if ([IO.Path]::GetExtension($property.Name) -ne '.py') { throw 'Only Python source may be copied.' }
        $targetPath = [IO.Path]::GetFullPath((Join-Path $targetRoot $property.Name))
        if (-not $targetPath.StartsWith($targetRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Manifest path escapes target root.'
        }
        New-Item -ItemType Directory -Path (Split-Path -Parent $targetPath) -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $sourceRoot $property.Name) -Destination $targetPath
    }
    Assert-SourceHashes $targetRoot $hashes
}
Assert-SourceHashes $oldSnapshot $oldManifest.code_hashes
Assert-SourceHashes $projectRoot $currentManifest.code_hashes
New-Item -ItemType Directory -Path $destination | Out-Null
New-Item -ItemType Directory -Path $development | Out-Null
Copy-VerifiedSources $oldSnapshot (Join-Path $destination 'src') $oldManifest.code_hashes
Copy-VerifiedSources $oldSnapshot (Join-Path $development 'src') $oldManifest.code_hashes
Copy-VerifiedSources $projectRoot (Join-Path $destination 'preserved_repaired_src') $currentManifest.code_hashes

$settings = [ordered]@{}
foreach ($property in $historicalReport.configuration.PSObject.Properties) { $settings[$property.Name] = [string]$property.Value }
foreach ($name in @('TYPE_COVERAGE_ROUTING','GRAPH_SECURITY_NET','STRICT_OPERATION_TAGS','USE_BACKWARD_SLICE',
                   'BOUNDED_OUTPUT_CONTRACT','EVIDENCE_EXPANSION','BUDGETED_EVIDENCE_GROUPS',
                   'ACTION_BEFORE_REASONING','OBSERVED_STATE_CANDIDATE')) { $settings[$name] = '0' }
$settings['HGL_ABL'] = ''
$manifest = [ordered]@{
    name = $BaselineName
    status = 'Reconstructed development foundation; NOT the exact historical 61.15% source version'
    source_snapshot = $oldSnapshot
    source_manifest = $oldManifestPath
    source_manifest_sha256 = (Get-FileHash -LiteralPath $oldManifestPath -Algorithm SHA256).Hash.ToLower()
    code_hashes = $oldManifest.code_hashes
    settings = $settings
    graph_token_budget = 4096
    output_token_ceiling = 150
    max_steps = 2
    historical_reference = [ordered]@{
        report = $historicalReportPath
        sha256 = (Get-FileHash -LiteralPath $historicalReportPath -Algorithm SHA256).Hash.ToLower()
        pipeline_fp = $historicalReport.pipeline_fp
        n = $historicalReport.metrics.n
        f1 = $historicalReport.metrics.f1
        accuracy = $historicalReport.metrics.accuracy
        transferable_score = $false
    }
    preserved_repaired_manifest = $currentManifestPath
    preserved_repaired_manifest_sha256 = (Get-FileHash -LiteralPath $currentManifestPath -Algorithm SHA256).Hash.ToLower()
    preserved_repaired_code_hashes = $currentManifest.code_hashes
    frozen_source = Join-Path $destination 'src'
    editable_source = Join-Path $development 'src'
    new_api_calls_authorized = $false
    main_checkout_modified = $false
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $destination 'baseline.json') -Encoding utf8
[ordered]@{
    active_development_baseline = $BaselineName
    source_root = Join-Path $development 'src'
    frozen_baseline = Join-Path $destination 'baseline.json'
    prediction_score = $null
    live_test_authorized = $false
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $development 'ACTIVE_BASELINE.json') -Encoding utf8
Assert-SourceHashes $projectRoot $currentManifest.code_hashes
Write-Output ('RESTORED baseline_files=' + @($oldManifest.code_hashes.PSObject.Properties).Count +
              ' preserved_files=' + @($currentManifest.code_hashes.PSObject.Properties).Count + ' api_calls=0')
Write-Output $development
