# Label-independent completeness and response-truncation audit

Offline audit of the frozen grouped-development run, not a new evaluation.
Artifacts: `output/devign_completeness_audit60_20261007/report.json`,
`rows.json`, `calls.json`. Script: `evaluation/audit_grouped_completeness.py`.
No model calls, relabelling, prediction changes, outcome-driven rules or threshold
tuning.132 local regressions passed. Original360 results and raw receipts kept.

## Verification and limits

Prediction files match the frozen manifest.360 sample/profile/repeat results
are unique and complete; every returned API answer matches its reasoning trace.
Sources match saved SHA256; valid graph node/edge counts match preparation;
recorded node IDs are checked, synthetic compressed nodes separately counted.
Graph bytes were not independently frozen in the evaluation manifest, so this
audit records current graph hashes rather than claiming historical byte identity.

60 selected samples remain in the report:57 valid,3 preparation errors. Evidence
counts use57 valid sources once, not two repeats as independent samples. SRC
text is identical across repeats. Plain/grouped slices use recorded exact source
line IDs, checked against actual first-request SRC. Standard/fallback coverage is
an exact stripped-whole-line proxy; repeated original lines remain ambiguous and
are excluded from directional loss claims. Categories use masked comments/strings
and regexes, not semantic proofs. Missing SRC lines may appear in PATHS/STATE.

## Information preservation

| SRC change relative to standard | Condition candidates lost/gained | Allocation/free lost/gained | Exit lost/gained | Access candidates lost/gained |
|---|---|---|---|---|
| Plain slice | 88/37 | 1/6 | 14/0 | 174/81 |
| Grouped slice | 88/36 | 1/6 | 13/11 | 177/77 |

Relative to plain, grouped adds12 exit candidate lines, loses0 exits or existing
allocation/free lines, but loses1 condition and7 access candidate lines. Thus
atomic mapped groups are not equivalent to preservation of all useful evidence.
This audit does not show which lost statements determine vulnerability.

Both slicing arms:7 empty-slice fallbacks,0 node-cap hits,31 unmapped visited
nodes across valid samples. Selected-line omissions occur on30 plain/36 grouped
samples (grouped selection includes proposed exit/dependence groups, so these
counts do not mean equivalent targets). Criterion-line omissions remain on2
samples in both arms:003502 (lines19,22,23,36..39),014154 (line91). Their plain
payloads are600 and597 chars. Priority is not an unconditional criterion-retention
guarantee. The group allocator protects criterion lines already kept by plain,
not every criterion excluded by the plain budget. No evidence that traversal's
2048-node cap explains these omissions.

Graph line-coverage proxy, distinct from edge/path semantic preservation:

| Category | Source lines | Absent from full graph line mapping | Full-mapped but absent from compressed-original-node line mapping |
|---|---|---|---|
| Condition candidates | 440 | 36 | 48 |
| Allocation/free | 15 | 3 | 0 |
| Exit candidates | 230 | 10 | 164 |
| Access candidates | 816 | 52 | 50 |

Exit coverage is especially sparse after compression, although slicing already
uses the full graph and may recover some lines. Lack of a retained original node
does not prove lack of all summarized information. No CFG reachability is treated
as control dependence or evidence that a guard protects an operation.

## Response truncation

351 invocations,350 successful responses,1 connection failure with unknown usage.
All350 successful responses contain a nonempty HYPOTHESIS and a line terminator.
305 responses finish with `length`; among these,2 have a complete ACTION JSON
and303 do not. The45 `stop` responses all have complete ACTION JSON. No narrow,
unqualified standard-vocabulary positive was missed by the existing type parser.
This is not a guarantee over qualified/ambiguous text or all vulnerability terms.

| Arm/repeat | Length-finished calls | Complete ACTION among length calls | Stop-finished calls |
|---|---|---|---|
| Standard/r1 | 51 | 0 | 7 |
| Plain/r1 | 53 | 0 | 6 |
| Grouped/r1 | 49 | 2 | 10 |
| Standard/r2 | 53 | 0 | 5 |
| Plain/r2 | 50 | 0 | 9 |
| Grouped/r2 | 49 | 0 | 8 |

The default prompt places REASONING before ACTION. With150 output tokens,
reasoning can consume the budget before the action completes. The planner falls
back to keywords when it cannot parse a JSON action; its adaptive behavior is
therefore not generally driven by a complete model-authored action here.
This structural vulnerability of the protocol is visible without labels, but
does NOT establish that truncation caused wrong classifications, or that raising
max_tokens/forcing a short output contract improves F1. Previously failed bounded
contract remains OFF and is not reintroduced under another name.

## Next gate, not an implemented prediction change

1. Audit-only coverage receipts can identify criterion/dependence omissions and
   missing locations; do not declare a semantically complete slice from these
   proxies. A future fallback/group policy must be specified label-independently,
   then tested on different reserved groups, not retuned on these exposed60.
2. A minimal ACTION-before-REASONING format experiment could preserve the existing
   hypothesis vocabulary, classification policy and150-token limit. Test action
   parseability first and quality separately; field order can still change model
   behavior. Do not revive the failed Benign/Uncertain short contract or raise
   output length merely from this audit. No such prediction change implemented.
3. Preserve raw source/CPG hashes and trace linkage in future experiment manifests
   to strengthen replay verification. No historic run artifacts rewritten.

Default configuration unchanged. This audit identifies evidence tradeoffs and
missing action fields; it does not establish an F1/Accuracy improvement.
