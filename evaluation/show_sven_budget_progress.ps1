param([string]$RunPath = 'output/sven_budget_eval_20261008')
# Read complete JSONL rows only; an in-progress last line is not an API failure.
$taskResults = @(Get-Content -LiteralPath (Join-Path $RunPath 'results.jsonl') | ForEach-Object {
    try { ConvertFrom-Json -InputObject $_ -ErrorAction Stop } catch {}
})
$taskCalls = @(Get-Content -LiteralPath (Join-Path $RunPath 'api_receipts.jsonl') | ForEach-Object {
    try { ConvertFrom-Json -InputObject $_ -ErrorAction Stop } catch {}
})
$taskSummary = foreach ($taskGroup in ($taskResults | Group-Object profile,repeat)) {
    $taskProfile = $taskGroup.Group[0].profile
    $taskRepeat = $taskGroup.Group[0].repeat
    $taskObserved = @($taskCalls | Where-Object { $_.profile -eq $taskProfile -and $_.repeat -eq $taskRepeat })
    [pscustomobject]@{
        Arm = "$taskProfile/r$taskRepeat"
        CompletedResults = $taskGroup.Count
        Errors = @($taskGroup.Group | Where-Object { $_.error }).Count
        Uncertain = @($taskGroup.Group | Where-Object { $null -eq $_.prediction -and -not $_.error }).Count
        CompletedCallReceipts = $taskObserved.Count
        FailedCalls = @($taskObserved | Where-Object { $_.error }).Count
        LengthCalls = @($taskObserved | Where-Object { $_.finish_reason -eq 'length' }).Count
        ReturnedTokens = ($taskObserved | Measure-Object total_tokens -Sum).Sum
    }
}
[pscustomobject]@{
    CompletedResults = $taskResults.Count
    ScheduledResults = 1016
    Arms = @($taskSummary)
    Scope = 'Progress only; completed receipts, not final quality or billing.'
} | ConvertTo-Json -Depth 4 -Compress
