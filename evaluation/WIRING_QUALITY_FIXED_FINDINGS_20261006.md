# Correctly configured wiring factorial — 2026-10-06

Completed development/configuration-repair replay, not independent confirmation
and not an official SVEN result. No candidate promoted. Original bad-configuration
records remain unchanged; see WIRING_QUALITY_FINDINGS_20261006.md.

## Integrity and accounting

Same frozen 60 group-selected development functions, 36 positive / 24 negative;
8 first-repeat profiles and 3 predeclared second-repeat profiles. All 660 receipts
present. 687 observed API invocations, one failed invocation followed by a bounded
retry, zero final pipeline errors. Failed invocation without returned usage has
unknown cost, not proven zero cost. Returned model deepseek-flash (requested alias
deepseek-chat); exact provider weights unknown. Effective expanded type vocabulary
and trace were verified before calls. Prediction code hashes match at completion.
All learned scoring and graph safety-net flags stayed off. All new switches still
default off. 111 local regression tests passed again.

Locked-test manifest SHA256 unchanged:
758d04f55d919b322f7731e082fa58a184c9300e902ba47654ae0590eabc6d08.

Artifacts: output/devign_wiring_quality60_eval_fixed_20261006/{manifest.json,
results.jsonl,api_receipts.jsonl,report.json,analysis.json,verdict_audit.json}.
Do not merge this run with the mismatched legacy-type run or select predictions
between them. Outcomes of the old batch were already seen, so this replay is not
fresh confirmation even though no prompt/threshold was tuned after those outcomes.

## Primary first-repeat results

Full-denominator Accuracy / conservative F1; abstentions count as errors.
Actual mean tokens include every returned usage record, including extra rounds.

| Profile | F1 | Accuracy | Mean actual tokens |
| --- | ---: | ---: | ---: |
| Control | .4746 | .4833 | 903.55 |
| Dependence slice | .5517 | .5667 | 899.43 |
| Bounded output | .0513 | .3833 | 817.97 |
| Enhanced expansion | .4211 | .4500 | 906.90 |
| Combined | .0500 | .3667 | 883.10 |
| Combined without slice | .0500 | .3667 | 918.67 |
| Slice + expansion, without bounded output | .6774 | .6667 | 890.62 |
| Combined without expansion upgrade | .0500 | .3667 | 785.13 |

The slice+expansion profile has TP21 / TN19 / FP5 / FN15, point gains of
20.28 F1 percentage points and 18.33 Accuracy points versus control and 1.43%
fewer tokens. Preserve it as a **development candidate only**. Marginal paired
group bootstrap delta intervals: F1 [.0172,.3918], Accuracy [.0333,.3333]. These
are not adjusted for eight-arm selection and do not capture future provider
variation. This candidate was NOT among the predeclared repeated profiles; do
not append a favorable selective repeat or claim replication.

Always-positive baseline: F1 .75 / Accuracy .60. The candidate improves Accuracy
but not F1 versus this trivial baseline. Exceeding .60 on both point scores is
not, by itself, sufficient paper evidence. No official comparison claim.

Slice-only delta F1 .0771 CI95 [-.1161,.2568]; Accuracy .0833 CI95
[-.0667,.2333]. No robust standalone slice gain established.

## Mechanism audit and important attribution limit

Slice-only and slice+expansion first system/user messages match on all 60 pairs.
Their first answers differ on 59/60 pairs. Final predictions differ on 14 pairs;
12 of these pairs used just one reasoning step on BOTH sides. The candidate
executes only two successful new-path expansion events. Therefore its aggregate
score gain cannot be attributed to expansion alone; unchanged-input model
variability is a major competing explanation. A point score is worth recording,
not sufficient reason to activate an unproven module.

Slice executes real dependence traversal; 3/60 criterion/mapping fallbacks,
26/60 slices have budget-omitted lines, zero traversal cap hits. Evidence is
bounded, not complete program slicing. Enhanced expansion-only has one successful
new-path event. Combined has six events and six second calls; combined without
slice has seven events, six successful new-path events and six second calls.
Combined without enhanced expansion has zero second calls. The factorial zero
retains legacy routing; it is not deletion of all legacy expansion.

Bounded output: 51 Benign / 8 Uncertain / 1 concrete positive hypothesis.
Unambiguous standard-vocabulary hypotheses have zero parser misses; required
contract fields are complete. Thus regression is a semantic decision shift,
not merely parser failure. It changes format AND evidence/uncertainty policy,
so do not assign the effect uniquely to field order. It eliminates truncation
but is rejected for default quality use. Control truncates 57/61 calls;
slice+expansion truncates 53/62. Truncation/routing remains an unresolved issue.

Existing outer SOURCE-based verifier has zero flips in EVERY profile/repeat.
Fixed-answer removal yields identical F1/Accuracy. This verifier is not the
disabled graph safety net, and the replay is not a fresh LLM run.

## Prespecified repeat sensitivity

Control r2: F1 .4561 / Accuracy .4833; 10/60 prediction disagreements.
Bounded-output r2: .0976 / .3833; 5/60 disagreements.
Combined r2: .1000 / .4000; 2/60 disagreements.
First prompts match 60/60 across each repeat; bounded-only first user prompts
also match control 60/60. Repeated calls are not additional independent samples.

## Decision and next gate

Keep bounded output, learned/GAT and graph safety net disabled; no default changes.
Preserve slice+expansion exact settings and code fingerprints as a candidate,
not a stable winner. Next quality gate: preregister a separate, group-disjoint
development confirmation comparing control, slice-only and slice+expansion with
equal repeats, fixed budgets, unchanged-input variability and majority baselines.
No new prompt, threshold or checkpoint tuning on these 60 functions. Do not use
the locked final test to decide whether the candidate should be enabled.
