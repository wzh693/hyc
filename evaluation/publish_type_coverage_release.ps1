param([switch]$Push)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$releaseRelative = 'releases/type_coverage_reconstructed_20261008'
$releaseRoot = Join-Path $projectRoot $releaseRelative
$branch = 'codex/type-coverage-baseline-20261008'
$ref = 'refs/heads/' + $branch
$audit = Get-Content -LiteralPath (Join-Path $projectRoot 'output\reconstructed_llm60_eval_20261008\audit.json') -Raw | ConvertFrom-Json
if (-not $audit.passed -or -not $audit.github_upload_eligible) { throw 'Publication gate failed.' }
$remote = git remote get-url origin
if ($remote -ne 'https://github.com/wzh693/hyc.git') { throw 'Unexpected destination.' }
$files = @(Get-ChildItem -LiteralPath $releaseRoot -File -Recurse)
$allowedSpecial = @('.gitignore','.gitattributes')
$sensitive = @()
# Read only known local credentials for equality checks; never print their values.
$credentialValues = @()
$envFile = Join-Path $projectRoot '.env'
if (Test-Path -LiteralPath $envFile) {
    foreach ($line in Get-Content -LiteralPath $envFile) {
        if ($line -match '^\s*(?:OPENAI_API_KEY|LLM_API_KEY|GITHUB_TOKEN|GH_TOKEN)\s*=\s*(.+)$') {
            $candidateValue = $Matches[1].Trim().Trim('"').Trim("'")
            if ($candidateValue.Length -gt 8) { $credentialValues += $candidateValue }
        }
    }
}
foreach ($file in $files) {
    if ($file.Length -gt 2MB -or ($file.Extension -notin @('.py','.md','.txt','.json','.c') -and $file.Name -notin $allowedSpecial)) {
        throw ('Disallowed publication file: ' + $file.Name)
    }
    $body = Get-Content -LiteralPath $file.FullName -Raw
    if ($body -match '(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,}|BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|C:[/\\]Users[/\\])') {
        $sensitive += $file.Name
    }
    foreach ($credentialValue in $credentialValues) {
        if ($body -and $body.Contains($credentialValue)) { $sensitive += $file.Name }
    }
}
if ($sensitive.Count) { throw ('Sensitive content detected in file names: ' + ($sensitive -join ',')) }
Write-Output ('PUBLICATION SCAN PASS files=' + $files.Count + ' new raw data/secrets/weights=0')
$gitDirectory = git rev-parse --absolute-git-dir
$realIndex = Join-Path $gitDirectory 'index'
$originalIndexHash = (Get-FileHash -LiteralPath $realIndex -Algorithm SHA256).Hash
$originalHead = git rev-parse HEAD
$previousIndexEnv = [Environment]::GetEnvironmentVariable('GIT_INDEX_FILE','Process')
$tempIndex = Join-Path $gitDirectory ('type-coverage-publish-' + [guid]::NewGuid().ToString('N') + '.index')
if (Test-Path -LiteralPath $tempIndex) { throw 'Unexpected existing temporary index.' }
try {
    [Environment]::SetEnvironmentVariable('GIT_INDEX_FILE',$tempIndex,'Process')
    git read-tree HEAD
    if ($LASTEXITCODE -ne 0) { throw 'Cannot initialize isolated index.' }
    # Root _*.py ignores package __init__.py. Force only the individually scanned
    # allowlisted files, never unrelated working-tree content.
    $publicationPaths = @($files | ForEach-Object {
        $releaseRelative + '/' + $_.FullName.Substring($releaseRoot.Length + 1).Replace('\','/')
    })
    git add -f -- @publicationPaths
    if ($LASTEXITCODE -ne 0) { throw 'Cannot stage isolated source package.' }
    $changed = @(git diff --cached --name-only)
    if ($changed.Count -ne $files.Count -or @(Compare-Object ($publicationPaths | Sort-Object) ($changed | Sort-Object)).Count) {
        throw 'Staged scope differs from source-only package.'
    }
    # Preserve legacy source bytes (including CRLF/whitespace) for provenance.
    # Check new metadata/tests normally; the frozen source is verified bytewise.
    $newPackagePaths = @($publicationPaths | Where-Object { -not $_.StartsWith($releaseRelative + '/src/') })
    git diff --cached --check -- @newPackagePaths
    if ($LASTEXITCODE -ne 0) { throw 'Staged whitespace check failed.' }
    $profile = Get-Content -LiteralPath (Join-Path $releaseRoot 'profile.json') -Raw | ConvertFrom-Json
    foreach ($property in $profile.source_hashes.PSObject.Properties) {
        # git hash-object hashes bytes after applicable index filters: source must not normalize.
        $workingBlob = git hash-object --no-filters -- (Join-Path $releaseRelative ('src/' + $property.Name))
        $stagedBlob = git rev-parse (':' + $releaseRelative + '/src/' + $property.Name)
        if ($workingBlob -ne $stagedBlob) { throw 'Frozen source bytes normalized during staging.' }
    }
    $tree = git write-tree
    if ($LASTEXITCODE -ne 0) { throw 'Cannot write source tree.' }
    git show-ref --verify --quiet $ref
    if ($LASTEXITCODE -eq 0) { throw 'Ref already exists; will not overwrite an existing branch.' }
    $commit = git commit-tree $tree -p $originalHead -m 'Add isolated experimental type-coverage baseline with audited real LLM smoke'
    if ($LASTEXITCODE -ne 0) { throw 'Cannot create scoped commit.' }
    git update-ref $ref $commit ('0' * 40)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot register new branch.' }
    Write-Output ('SCOPED COMMIT ' + $commit)
    Write-Output ('BRANCH ' + $branch)
}
finally {
    [Environment]::SetEnvironmentVariable('GIT_INDEX_FILE',$previousIndexEnv,'Process')
    if ((Get-FileHash -LiteralPath $realIndex -Algorithm SHA256).Hash -ne $originalIndexHash -or (git rev-parse HEAD) -ne $originalHead) {
        throw 'Original staging/HEAD changed unexpectedly.'
    }
    # Exact verified generated index only; never remove the real index or a directory.
    if ($tempIndex.StartsWith($gitDirectory + '\',[StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path -Leaf $tempIndex) -match '^type-coverage-publish-[0-9a-f]{32}\.index$' -and
        (Test-Path -LiteralPath $tempIndex)) { Remove-Item -LiteralPath $tempIndex }
}
if ($Push) {
    $previousPrompt = [Environment]::GetEnvironmentVariable('GIT_TERMINAL_PROMPT','Process')
    $previousInteractive = [Environment]::GetEnvironmentVariable('GCM_INTERACTIVE','Process')
    try {
        [Environment]::SetEnvironmentVariable('GIT_TERMINAL_PROMPT','0','Process')
        [Environment]::SetEnvironmentVariable('GCM_INTERACTIVE','never','Process')
        git -c http.proxy= -c https.proxy= push origin ($ref + ':' + $ref)
        if ($LASTEXITCODE -ne 0) { throw 'Push failed; local scoped commit retained, no force or alternate destination attempted.' }
        $remoteHead = git -c http.proxy= -c https.proxy= ls-remote origin $ref
        if ($LASTEXITCODE -ne 0 -or -not $remoteHead.StartsWith($commit)) { throw 'Remote commit could not be verified.' }
        Write-Output ('GITHUB VERIFIED ' + $commit)
    }
    finally {
        [Environment]::SetEnvironmentVariable('GIT_TERMINAL_PROMPT',$previousPrompt,'Process')
        [Environment]::SetEnvironmentVariable('GCM_INTERACTIVE',$previousInteractive,'Process')
    }
}
