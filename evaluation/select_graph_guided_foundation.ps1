param()
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot -Parent
$taskBaseDir = Join-Path $taskRoot 'baselines/type_coverage_reconstructed_20261008'
$taskActive = Join-Path $taskRoot 'development/type_coverage_reconstructed_20261008/src'
$taskRunDir = Join-Path $taskRoot 'output/sven_complete_src_eval_20261008'
$taskBase = Get-Content (Join-Path $taskBaseDir 'baseline.json') -Raw | ConvertFrom-Json
$taskRun = Get-Content (Join-Path $taskRunDir 'manifest.json') -Raw | ConvertFrom-Json
$taskAllowed = @('config.py', 'linearization\typed_paths.py')
function Get-TaskHash([string]$path) {
    (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower()
}
# Verify every file before overwriting the two known candidate changes. The tested
# candidate is retained byte-for-byte in code_snapshot; never reset the checkout.
$taskChanged = @()
foreach ($p in $taskBase.code_hashes.PSObject.Properties) {
    $taskFrozen = Join-Path (Join-Path $taskBaseDir 'src') $p.Name
    $taskCurrent = Join-Path $taskActive $p.Name
    $taskTested = $taskRun.code_hashes.PSObject.Properties[$p.Name].Value
    if ((Get-TaskHash $taskFrozen) -ne $p.Value) { throw "Frozen source changed: $($p.Name)" }
    if ((Get-TaskHash (Join-Path (Join-Path $taskRunDir 'code_snapshot') $p.Name)) -ne $taskTested) {
        throw "Candidate archive changed: $($p.Name)"
    }
    $taskHash = Get-TaskHash $taskCurrent
    if ($taskHash -ne $p.Value) {
        if ($p.Name -notin $taskAllowed -or $taskHash -ne $taskTested) {
            throw "Unrecognized editable change; preserve and stop: $($p.Name)"
        }
        $taskChanged += $p.Name
    }
}
$taskPyFiles = @(Get-ChildItem -LiteralPath $taskActive -Recurse -File -Filter '*.py')
if ($taskPyFiles.Count -ne 47 -or @($taskBase.code_hashes.PSObject.Properties).Count -ne 47) {
    throw 'Unexpected source file inventory'
}
foreach ($name in $taskChanged) {
    Copy-Item -LiteralPath (Join-Path (Join-Path $taskBaseDir 'src') $name) -Destination (Join-Path $taskActive $name)
}
foreach ($p in $taskBase.code_hashes.PSObject.Properties) {
    if ((Get-TaskHash (Join-Path $taskActive $p.Name)) -ne $p.Value) { throw 'Restoration verification failed' }
}
[pscustomobject]@{
    active_baseline = $taskBase.name
    restored_files = $taskChanged
    matching_source_files = 47
    rejected_candidate_preserved = (Join-Path $taskRunDir 'code_snapshot')
    new_api_calls = 0
} | ConvertTo-Json -Depth 4
