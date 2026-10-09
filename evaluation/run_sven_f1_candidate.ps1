param(
    [string]$Python = (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe'),
    [int]$Workers = 4,
    [string]$Indices = '',
    [string]$OutputDir = ''
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw 'Python executable not found; pass -Python with the existing environment executable.'
}
if ($Workers -lt 1) { throw 'Workers must be positive.' }
if (-not $OutputDir) {
    $OutputDir = Join-Path $projectRoot ('sven_eval\output_f1_candidate_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
}
$settings = @{
    SVEN_OUTPUT_DIR = $OutputDir; SVEN_RUN_NAME = 'type_coverage_f1_candidate'
    USE_LEARNED_NODE_IMPORTANCE = '0'; USE_LEARNED_SUMMARIZE = '0'; USE_LEARNED_PATH_RANK = '0'
    MAX_REASONING_STEPS = '2'; STEP1_CONFIRM_STOP = '1'; SOURCE_SLICE_ASSIGNMENT_FIX = '0'
    COMPACT_THREE_PART_CONTEXT = '1'; USE_LLM_ARBITRATION = '0'; SELECTIVE_SECOND_PASS = '1'
    USE_ZERO_TOKEN_SECURITY_NET = '1'; SECURITY_NET_THRESHOLD = '4'; SVEN_QUIET = '1'
    F1_EVIDENCE_ROUTING = '0'; STRUCTURED_PRIOR_SUMMARY = '0'; COMPACT_VERDICT_PROMPT = '0'
    FOCUSED_GRAPH_ANCHORS = '0'; TYPE_COVERAGE_PROMPT = '1'; TYPE_COVERAGE_ROUTING = '0'
    RECORD_REASONING_TRACE = '1'; HGL_ABL = ''
    GRAPH_SECURITY_NET = '0'; USE_BACKWARD_SLICE = '0'
    BOUNDED_OUTPUT_CONTRACT = '0'; EVIDENCE_EXPANSION = '0'
    BUDGETED_EVIDENCE_GROUPS = '0'
    ACTION_BEFORE_REASONING = '0'
    OBSERVED_STATE_CANDIDATE = '0'
}
$previous = @{}
foreach ($name in $settings.Keys) {
    $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    [Environment]::SetEnvironmentVariable($name, $settings[$name], 'Process')
}
Push-Location $projectRoot
try {
    $arguments = @('-u', 'sven_eval\data\eval_sven.py', '--workers', $Workers, '--no-resume')
    if ($Indices) { $arguments += @('--indices', $Indices) }
    & $Python @arguments
    if ($LASTEXITCODE -ne 0) { throw "Evaluation failed with exit code $LASTEXITCODE." }
}
finally {
    Pop-Location
    foreach ($name in $settings.Keys) {
        [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process')
    }
}
