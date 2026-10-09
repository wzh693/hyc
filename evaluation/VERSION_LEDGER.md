# HGL development version ledger

## Larger development preparation and real-body gate (2026-10-05)

Added `build_development_graph_cache.py`: fixed seed20261006,300 distinct
development groups,lowest-index representative,exclude entire groups from the
previous development30,no label balancing. Selection is frozen before Joern;
all errors retained,no replacement. `output/devign_development300_20261005`
is CPG preparation,not a detection evaluation or a claimed score improvement.
Resumption verifies original manifest/protocol and rechecks earlier successes.

Found `_dot_has_func_method` falsely matching FULL_NAME suffixes as NAME,
including `<includes>:<global>`. It now parses quoted attributes and requires
a non-external,non-synthetic METHOD with a direct AST BLOCK starting with `{`.
METHOD CODE alone is insufficient: Joern truncates long signatures at1000
characters; a real body still passes via BLOCK. A macro stub's `<empty>` BLOCK
fails. The fallback export route applies the same validation.

Full historical cache audit `training_body_audit_20261005.json`:551/600
have real bodies;49 invalid (21positive/28negative). Of these,32 were tiny
global skeletons; additional macro stubs exist. No files deleted. Earlier
GAT600 training included these invalid graphs; preserve its scores as historical
observations but do not claim it trained on600 valid function bodies. Future
training skips them and reports unavailable counts,not silently changing an
evaluation denominator. This gate proves a body exists,not complete semantics.

Training supports repeated `--cache-dir`; duplicate IDs are rejected, each
metadata hash is bound in the saved split. Calibration loads precisely those
caches and refuses changed metadata. Raw checkpoint/defaults remain unchanged.
89 evaluation regression tests pass. No new LLM calls in this expansion.
Exposure inventory now includes new `meta.json` and frozen `manifest.json`,
not only old `metadata.json`, so interrupted preparation/new training caches
cannot silently reappear as unseen data in a future protocol. Existing frozen
partitions were not regenerated or changed.

Completed development300 preparation:293 valid/7failed; selected labels177
positive/123negative,valid174positive/119negative. Exact requested denominator
and all failures remain in `preparation_report.json` and `body_audit.json`.

Expanded candidate `learning/model/gat_expanded_beta0_20261005`:844 valid
graphs from900requested,train689/epoch-selection90/calibration65. Early stopped
after10epochs,best epoch2,selection AUC .5853. Calibration65distinct groups:
AUC .48246,fixed.50 F1 .61538/Acc .53846 (TP24 FP16 FN14 TN11). This is standalone
GAT calibration,NOT HGL system results. Always-positive baseline has F1 .73786 /
Acc .58462 on the same65. No eligible calibrated threshold:reject before any
system evaluation or default activation. Do not describe data expansion as a
proven gain; prior AUC .5602 uses a different selection set. No new LLM calls.
Model and calibration provenance hashes verified; original model unchanged.

## Correction: quoted Joern position metadata (2026-10-05)

`graph/load_graph.py` previously accepted `LINE_NUMBER=3` but not the actual
Joern export `LINE_NUMBER="3"`. This silently dropped source positions. Fixed
quoted/unquoted parsing and COLUMN_NUMBER; values inside CODE cannot spoof
metadata. Regression tests: `evaluation/test_dot_positions.py`.

Earlier **source-window pilots are invalid as tests of evidence-window quality**:
the absent positions caused the candidate to reduce SRC to its first line.
Their token savings and model scores remain archived observations but must not
be interpreted as benefits/tradeoffs of real local windows. These include
`evidence_window_pairs_20261005` and `devign_clean_pilot_20261005/window_pairs`.
The older primary HGL/type-coverage results are not automatically invalidated:
those heuristics do not consume this position attribute; no unchanged-metric
claim is made for other position-dependent consumers.

`devign_clean_pilot_20261005/full_graph_pairs` had zero facts for all 30 rows;
the 60 calls were effectively a repeated identical-input control, NOT graph
augmentation. Cost 102,492 tokens. A new preflight aborts if all graph facts are
empty, preventing repetition of this ineffective intervention.

After the loader fix, `full_graph_pairs_positions_fixed` has facts for 29/30
rows. Both sides F1 .6341 / Acc .5000, with unchanged binary predictions and
mean tokens 1708.20 -> 1967.70. Reject graph augmentation as a gain candidate.
Actual cost 110,277 tokens. No threshold or sample reselection.

Source-window builder now preserves multiline signatures, abstains if no real
window fits, and falls back to the original slice. A fresh position-fixed pilot
is archived separately; do not overwrite or pool prior ineffective pilots.

Position-fixed source windows: `window_positions_fixed_pairs`, F1 .5000 ->
.4706, Acc .5333 -> .4000, mean tokens 944.03 -> 926.23. Genuine changed evidence
on all 30 rows; reject this local-window policy, do not retain it as a gain.

Frozen GAT audit: `frozen_gat_audit`, using the original fixed threshold .55
(no sweep), HGL F1 .5333 -> .5806 / Acc .5333 -> .5667. One additional positive
function recovered (idx24174), no added FP, no LLM calls. Calibration lacks
checkpoint binding; exploratory only, not activated. Standalone GAT .5 gives
F1 .6818 / Acc .5333 and does not beat the always-positive baseline.

GAT attention's mean normalized entropy on the pilot is about .0000965:
extremely concentrated, not evidence of useful localization. Found and fixed
another correctness issue in scorer: zero/equal attentions previously received
different percentile penalties according to node iteration order. Equal values
now receive average-rank penalties; a constant-score graph is neutral. Four
targeted tests cover ties, permutation invariance, neutrality and invalid scores.
Learned summarization/ranking stay OFF until separately validated.

Historical GAT split reconstruction (`gat_split_audit.json`): 8 clone/commit
connected groups cross train/holdout; 9 of 120 holdout rows touch training.
Reconstructed from documented seed/current metadata, not an original split
manifest. Do not treat the old holdout AUC/calibration as independently grouped.
New training saves three group-disjoint partitions (train, epoch selection,
threshold calibration), full split SHA256 inside checkpoint and report, and a
separate candidate directory. Calibration refuses legacy/mismatched provenance
and never overwrites old receipts. One predeclared beta=0 candidate, max20
epochs/patience8, tests whether entropy regularization contributed to collapse.
No pilot/test labels determine training epochs or calibration thresholds.

Completed `learning/model/gat_grouped_beta0_20261005`: train481 / epoch
selection72 / reserved calibration47,20 epochs,best epoch14,selection AUC .5602.
Calibration: no eligible threshold in the predeclared grid; at .50 precision
.375 (6TP/10FP). **Rejected for activation before further pilot/test evaluation.**
No extra LLM calls for this training/calibration. Keep checkpoint,split and
calibration receipts; do not retune threshold on the development30 to rescue it.
Training BCE fell .7260 -> .1019 while selection AUC stayed near chance: clear
memorization/generalization warning, not a reason to add epochs. Removed entropy
penalty did not establish a detection gain. Next development work needs more
group-disjoint functions and a capacity/data audit, not repeated small-pilot sweeps.
75 local regression tests pass after the group/calibration changes.

Do not overwrite baseline outputs. Successful means an observed paired gain,
not proven generalization; never select the best stochastic repeat as the result.

| Version / artifact | Status | Evidence |
| --- | --- | --- |
| Historical low-token control: output_low_token_final | Archived reference | SVEN F1 .5657, Acc .5709, mean 887.76 tokens; historical run, not fresh paired control |
| Type coverage: output_type_coverage_full | Best supported development candidate | Paired SVEN F1 .5476 -> .6115, Acc .5512 -> .5748, tokens 894.04 -> 866.70; independent generalization unproven |
| Type coverage: external_type_check/output_type_pairs | Supporting development check | 30 Devign functions, two repeats; candidate better F1/Acc each repeat, about 9 extra tokens/call; not held-out evaluation |
| Graph safety net: graph_net_fresh_20261005_run2 | Rejected for default use | Reduces one FP but loses three TP across repeated receipts; F1/Acc worse |
| Strict tags: operation_tag_pairs_20261005 | No demonstrated detection gain | Only improved prediction had identical input; changed-input functions unchanged. Default OFF |
| Source windows: evidence_window_pairs_20261005 | Invalid evidence intervention; see correction | Missing positions reduced SRC to function head; do not attribute scores to windows |
| Source windows: output/devign_clean_pilot_20261005/window_pairs | Invalid evidence intervention; see correction | Missing positions reduced SRC to function head; original receipts preserved |
| Full-source direct: output/devign_clean_pilot_20261005/direct_llm | Diagnostic baseline | Same new development30, F1 .6667, Acc .5333, mean1708.23 tokens; later calls, different format, not graph-only ablation |
| Negative-only full-source recovery replay | Feasibility candidate only | Same stored answers: F1 .7273, Acc .6000, estimated1484.50 tokens; post-hoc replay, not live adaptive evaluation, does NOT exceed .60 Acc |

Artifact names are under `sven_eval/` or `sven_eval/external_type_check/` as
indicated. The explicit candidate launcher remains
`evaluation/run_sven_f1_candidate.ps1`. Its settings/receipts are authoritative;
standard defaults are not silently switched. Retain full prompts and receipts,
configuration and source fingerprints, token/error counts and source-group CIs.

Do not retune from locked test or the three selected forensic examples. Keep
near-clone audit and larger held-out validation as outstanding release gates.

## Historical source-window snapshot — invalid intervention (2026-10-05)

Preserved under `sven_eval/external_type_check/`:
`evidence_window_snapshot_20261005/prompts.jsonl` contains both exact inputs;
`evidence_window_pairs_20261005/results.jsonl` contains all 60 fresh receipts;
`evidence_window_pairs_20261005/report.json` contains per-side results;
`evidence_window_summary_20261005.json` contains fixed-receipt grouped F1 CI.
No predictions were selected or recycled from favorable repeats.

Reproduce preparation with `python -m evaluation.build_evidence_window_snapshot
--output NEW_EMPTY_DIRECTORY`; evaluate its prompts using
`evaluation.evaluate_frozen_prompts --variant evidence_windows --repeats 1`,
with the fixed source mapping. The control and candidate share the expanded
type prompt, legacy threshold-4 security net and max output 150. Only SRC differs;
all 30 inputs changed, while PATHS/STATE/exploration text stayed identical.

Intended policy was operation-centered windows using CALL/RETURN positions.
Actual historical candidate lacked positions and reduced SRC to the first line.
It was not a valid test of windows or PDG backward slicing. Character budget is
not a token budget. PATHS/STATE/security tags were unchanged.

Observed FP 8 -> 4, TP 6 -> 5, TN 7 -> 11, FN 9 -> 10. Thus better Acc and
precision cost one true positive. F1 delta .0029 is negligible, with 95% source
cluster CI [-.2212, +.2133]; no stable F1 gain is established. Only one repeat,
not 60 independent examples. Control/candidate truncations 30/26 of 30 calls.
Archive only; no gain-candidate or combined-with-GAT claim is supported.

## Shared pipeline + evidence wiring candidate (2026-10-06)

Integration only; not promoted as a quality winner. See
`evaluation/PIPELINE_WIRING_20261006.md`. Shared production entry and constrained
ablations, optional dependence SRC slice, bounded output contract and full-CPG
evidence expansion implemented. All new switches default off; rejected GAT and
graph net remain off. 105 regressions passed. Two development-only real API smoke
runs preserve 19 call receipts; zero quality claims and no locked-test changes.
The short-output-only smoke used 2581 vs control 2791 tokens (3 calls each), with
0/3 vs 3/3 length finishes. Tiny training-exposed smoke cannot establish F1 gain.

## Wiring quality evaluation / config initialization repair (2026-10-06)

No candidate promoted. 60 new development groups, 660 scheduled paired/repeat
evaluations, 688 actual API invocations, zero pipeline errors. Post-run raw prompt
audit discovered evaluation package eager-import caching: requested expanded
types and trace did not apply. Archive this as legacy-type exploratory evidence,
not the intended control or paper result; original records untouched.
Under actual legacy types: control F1 .4727/Acc .5167; slice .5385/.6000 (CI
crosses zero); bounded output .1000/.4000, repeated .0952/.3667; combined
.2326/.4500, repeated .1905/.4333. Output policy rejected; no source-verifier
flips; failed GAT/graph net never enabled. Parser recognizes unambiguous types;
bounded output produced 52/60 Benign hypotheses, not lost type parsing.
Lazy package exports and effective-config fail-fast checks repaired. 111 tests
pass; corrected 60-input zero-call preflight verifies expanded types/trace true
and learned/graph-net flags false. Correctly configured quality rerun outstanding.
See `evaluation/WIRING_QUALITY_FINDINGS_20261006.md` for limitations and receipts.

## Corrected wiring factorial completion (2026-10-06)

Correct effective type coverage and trace; 660 pairs / 687 real API invocations,
one retried invocation, zero final pipeline errors. Code hashes unchanged during
run; 111 regressions pass; locked-test SHA unchanged. Development/configuration
repair only, not independent confirmation. No default switches changed.

Record candidate `combined_no_contract` (slice+expansion, old output policy):
F1 .677419 / Accuracy .666667, TP21 TN19 FP5 FN15, mean890.62 actual tokens
versus control .474576 / .483333, mean903.55 (1.43% fewer). Exact configuration
and prediction code fingerprints in
`output/devign_wiring_quality60_eval_fixed_20261006/manifest.json`; raw receipts
and all failed arms retained. Candidate not independently repeated/promoted.
Slice-only first prompts match candidate 60/60; 12/14 prediction differences
occur with both sides single-step. Only two candidate expansion events, so do
not attribute the score gain to routing. Marginal CIs unadjusted for selection.
Always-positive F1 .75 exceeds candidate F1, despite lower .60 Accuracy.

Bounded output rejected: F1 .0513 / Accuracy .3833, repeated .0976 / .3833;
51 Benign / 8 Uncertain / 1 positive, no unambiguous parser misses. Combination
with bounded output .05 / .3667, repeated .10 / .40. Source verifier zero flips;
GAT and graph net stayed off. See
`evaluation/WIRING_QUALITY_FIXED_FINDINGS_20261006.md`. Next gate is separately
group-disjoint, equal-repeat development confirmation, not selective same-batch
reruns or locked-test tuning.

## Full SVEN end-to-end replay (2026-10-06)

All254 rows,508 fresh sample/profile results,515 observed API invocations,
zero final pipeline errors/uncertainty. Current type-covered heuristic control:
F1 .588235 / Accuracy .559055,TP80 TN62 FP63 FN49,mean877.54 returned-usage
tokens. Slice+expansion candidate without bounded output:
.523077 / .511811,TP68 TN62 FP63 FN61,mean848.68. Candidate2 failed/retried
attempts have unknown usage;3.29% less returned usage is not exact billing saving.
**Candidate NOT promoted; SVEN replay quality gate failed.** Devign60 good point
score remains archived, not a stable winner. No default/threshold changes.

Full prep discovered wrapper/signature/source-coordinate defects; repaired before
calls, equally for both profiles. New directory with239 validated graph copies,
15 fresh builds, all254 valid; old artifacts untouched.117 tests pass. Source
mapping accepts unique line-preserving whole-source transformations, never fuzzy
body matching. Exact config/code/source/graph hashes and raw prompts saved in
output/sven_full_pipeline_eval_20261006; preparation under
output/sven_full_pipeline_inputs_20261006. Prediction code frozen during calls.

Both profiles execute compression/TopK/source verifier254 times, source flips0;
candidate slice fallbacks30,budget omissions86; enhanced expansion only4 new-path
events. Learned/GAT/graph net/short output inactive.74 exact sources,36 source/
family union groups,8 conflicting-label sources(51 rows). Family bootstrap delta
F1CI[-.18085,+.04554],AccuracyCI[-.12016,+.03030]; no positive gain proven.
Previously exposed benchmark, not independent confirmation, no locked test used.
See evaluation/SVEN_FULL_PIPELINE_FINDINGS_20261006.md for full-CWE/supplementary
metrics, limitations and next evidence-preservation gate.

## Offline evidence preservation and trace lineage (2026-10-06)

Zero API calls/prediction changes on saved254 SVEN pairs. Row-weighted SRC losses
versus control:503 condition/loop candidates,50 exits,4 allocation/free,614
array/member-access candidates. These are masked-regex/whole-line coverage proxies,
not proven protections or absence from all context. TP->FN24 vs FN->TP12;
condition loss18/24 and9/12 respectively, so loss is not a causal discriminator.
Eight predictions differ under identical first messages and single-step on both
sides. No quality improvement or causal regression claim.

Frozen full-SVEN prediction-code snapshot saved before new instrumentation:
output/sven_full_pipeline_code_snapshot_20261006. Offline replay against verified
snapshot matches all category/cohort totals exactly. Original run artifacts kept.
Local-only, trace-gated provenance added: compressed and initial TopK node IDs,
path-graph origin/source offset, slice criterion/visited IDs, pre-budget/omitted
source lines. No prompts/scoring/budgets/defaults changed;122 regressions pass.
See evaluation/EVIDENCE_PRESERVATION_FINDINGS_20261006.md. Next gate is bounded
evidence-group preservation under label-independent invariants and separate
group-disjoint confirmation, not SVEN-label tuning.

## Budgeted atomic evidence offline gate (2026-10-07)

Default-off `BUDGETED_EVIDENCE_GROUPS`: preserve existing criterion/lifetime
lines, admit whole mapped dependence/control-exit groups within both the plain
SRC character and UTF8-byte payload; exact fallback when none fit. No arbitrary
CFG control-dependence claim, no model-token-equivalence claim.126 tests pass.

New development60, seed20261008,390 recorded exposed groups excluded:57 valid
graphs,3 failures retained without replacement. Production-TopK shadow has206
groups,73 admitted,10 control+exit groups across6 samples; SRC changes8/60.
Zero API calls, payload growth, admitted-group splits or protected line losses.
No quality gain established; candidate remains OFF. Locked-test hash unchanged.

Three-arm two-repeat360-result preflight passes. Real LLM run rejected before
process creation: needs explicit source/context-to-endpoint authorization for
`https://api.deepseek.com/v1`. No bypass, no real results or paid calls; evaluation
directory not created. See evaluation/GROUPED_EVIDENCE_FINDINGS_20261007.md
and GROUPED_EVIDENCE_PROTOCOL_20261007.md. Next step is destination/payload
approval and frozen independent development comparison, not rule tuning.

## Completed grouped evidence confirmation (2026-10-07)

After explicit user destination/payload approval, frozen360 scheduled results
completed (all60 per arm/repeat,3 prep failures counted).351 API invocations,
350 successful,1 connection failure retried successfully with unknown usage;
no new final pipeline errors/uncertainty.305/350 length finishes; provider returns
deepseek-flash for deepseek-chat alias.127 local regressions pass.

Standard F1/Acc .655172/.666667 -> repeat2 .526316/.550000;
plain .472727/.516667 -> .481481/.533333;
grouped .509091/.550000 -> .561404/.583333. Returned tokens/sample:
standard866.92/867.30,plain864.97/863.48,grouped862.40/833.65. Not exact billing
savings because failed-attempt usage unknown. Always-positive F1 .666667 exceeds
all arms. Do not keep only the standard's successful first repeat.

Mechanism matches shadow206/73/10 groups; actual prompts change8/57,49 identical.
Grouped primary F1-delta vs plain +.036364 CI[-.087784,+.160955], Accuracy
+ .033333 CI[-.050000,+.133333]: no reliable gain established. Repeat2 aggregate
Accuracy gain occurs entirely on identical-input pairs; cannot attribute it to
grouping. Repeat prediction disagreements control9/plain9/grouped4 under
identical requests; control9 all single-step. Remote prompt tokens increase2 on
one sample even though character/byte budgets shrink; no per-sample token guarantee.
Existing outer source verifier creates same benign false positive twice; no
graph-net candidate activation or threshold tuning. Default unchanged, grouped
OFF. All artifacts at output/devign_grouped_eval60_20261007. See updated
evaluation/GROUPED_EVIDENCE_FINDINGS_20261007.md; independent development pilot,
not official final benchmark. Locked test untouched.

## Label-independent completeness / truncation audit (2026-10-07)

Zero API calls or prediction changes.132 local regressions pass. All360 results
and350 returned answers verified against trace; source hashes and current graph
counts/IDs checked. Audit-time graph hashes recorded; historical graph-byte
identity unavailable from evaluation manifest.57 valid sources measured once,
3 preparation failures retained. Labels not used to select/tune anything.

Plain vs standard loses88 condition candidates,14 exits,1 lifetime,174 access
candidates (SRC-only proxies, gains separately recorded). Grouping vs plain adds
12 exits but loses1 condition and7 access candidates. Both arms7 fallbacks,
0 node-cap hits,31 unmapped visited nodes; criterion-line omissions on2 samples
persist. Protecting existing plain anchors does not guarantee retention of all
criteria. No semantic completeness or causal F1-loss claim.

All350 successful responses have nonempty, newline-terminated HYPOTHESIS.
305 length finishes:303 missing complete ACTION JSON,2 complete.45 stop finishes
all have complete ACTION.0 narrow unqualified-positive parser misses. Default
REASONING-before-ACTION creates an action-budget risk; raising tokens or restoring
the failed short contract is not supported by this audit. Next candidate may
isolate field order without changing hypothesis vocabulary/policy, on new groups.
Prediction behavior/defaults unchanged. See evaluation/COMPLETENESS_FINDINGS_20261007.md
and output/devign_completeness_audit60_20261007. Original raw evaluations unchanged.

## Field-order candidate implemented, external gate pending (2026-10-07)

Default-off ACTION_BEFORE_REASONING only swaps original ACTION/REASONING lines;
same vocabulary, decisions and150-output-token limit; bounded-contract combination
rejected.136 local regressions pass. Previous grouped prediction-code snapshot
saved after manifest verification, no secrets copied. New runner freezes CPG hashes
and per-arm effective config and verifies source/graph identity during evaluation.

Independent development60 seed20261009 excludes450 recorded exposed groups;
all60 CPGs valid,38positive22negative after label-blind selection. Always-positive
F1 .775510/Accuracy .633333. Preflight passes without API calls. Preregistered
control/action_first both twice,240 results; no default promotion or best-repeat.

Real run rejected before creation: reviewer requires explicit new60 source/path/
reasoning payload approval to https://api.deepseek.com/v1, beyond prior grouped
batch approval. No bypass,no API calls,no new scores. See
evaluation/ACTION_ORDER_FINDINGS_20261007.md and ACTION_ORDER_PROTOCOL_20261007.md.

## Completed field-order comparison: reject for quality (2026-10-07)

Explicit approval received for new60 payload;240 results and244 successful API
calls completed,0 failures/errors/uncertainty.136 regressions passed. Standard
F1/Acc .666667/.650000 and .727273/.700000; candidate .509091/.550000 and
.551724/.566667. All60 count per arm/repeat. Always-positive F1 .775510 exceeds
both; development only, not a paper benchmark. Standard archived as reference,
not a claimed new algorithmic gain. No best-repeat selection.

Paired requests60/60 each repeat verify only system field-order changes, identical
user/context/parameters. First-call parsed ACTION6/60 and7/60 ->55/60 both times;
Hypothesis present on all244 responses, no complete-action planner misses.
However FN17->24 and14->22,FP4->3 and4->4. Candidate F1 delta -.157576 CI
[-.313750,-.022599],Accuracy -.10 CI[-.20,0] on preregistered first repeat,
exploratory marginal intervals. Repeat prediction disagreements7 vs9. Better
action parseability does not imply quality/stability benefit.

Returned tokens/sample950.92->906.50 and922.02->907.93 (-4.67%/-1.53%);
legacy second-round samples3/1 vs0/0 account for reduced calls, not pure context
compression. ACTION_BEFORE_REASONING remains OFF; all failed modules kept OFF.
Raw artifacts output/devign_action_order_eval60_20261007, verified code snapshot
output/devign_action_order_code_snapshot_20261007, no secrets copied. Locked-test
hash unchanged. See updated ACTION_ORDER_FINDINGS_20261007.md.

## 2026-10-07 — STATE semantics diagnostic (no prediction changes)

Added label-free synthetic audit and audit-integrity tests. Four normal controls
agree; eleven purpose-selected counterexamples reproduce branch/lifetime/check
order/comment/string/alias/scanf-target problems. Path-only malloc update wrongly
attributes allocation to size argument. First hierarchical prompt demonstrably
receives lexical STATE; predicate helpers primarily affect explanations, not
direct final decisions. No F1/Accuracy causality or improvement claim. Zero real
LLM calls. All 46 previous frozen files hash-match. See
STATE_SEMANTICS_FINDINGS_20261007.md and preserved report_with_controls.json.
All 138 local regression tests passed (mocked inference only).

## 2026-10-07 — conservative observed STATE candidate (default OFF)

Implemented OBSERVED_STATE_CANDIDATE via shared factory, lexical may-event
extraction, correct simple targets/case/scanf arguments, location dedup and
complete-event budget serialization. Predicate APIs return unknown; explanation
generation does not misrepresent unknown as benign. No path-sensitive solver or
F1/Accuracy improvement claim. Zero real API calls. Fifteen OFF prompts match
pre-change records; fifteen ON prompts change only STATE, no character/UTF-8-byte
growth (3840 -> 3280 total synthetic prompt characters, not model tokens).
Previous frozen snapshot matches all 46 old manifest hashes; current prediction
hashes are frozen in output/observed_state_shadow_20261007/report_final.json.
See OBSERVED_STATE_CANDIDATE_20261007.md. No automatic activation or dataset run.
All 150 local regressions passed, including 12 candidate tests (mocked inference).

## 2026-10-07 — STATE independent confirmation frozen, external call blocked

Fresh60 development groups seed20261010,510 recorded groups excluded,38 positive
22 negative selected without balancing;59 valid CPG/1 failure counted in all arms.
155 regressions pass. Production shadow preserves SRC/PATHS/retrieval, no STATE
character/byte growth;1604 source events,423 initial units,317/318 added graph
events unmapped. Preflight and47-file snapshots verified. Three profiles twice
(360 scheduled) NOT launched: automatic review rejected specific external source/
graph/context disclosure despite general LLM permission. Zero actual API calls;
no quality/token result or promotion. Needs explicit user payload+DeepSeek endpoint
authorization. See STATE_CONFIRMATION_PROTOCOL/FINDINGS_20261007.md.

## 2026-10-08 — STATE comparison completed: retain default OFF

Explicit payload/destination authorization received;360 scheduled results,
358 successful API calls,0 failed invocations. One preparation failure retained
per arm/repeat. Actual returned model deepseek-flash (requested deepseek-chat).
Control F1/Acc .491803/.483333 and .533333/.533333; disabled .508475/.516667
and .363636/.416667; observed .508475/.516667 and .548387/.533333. Primary
paired quality intervals cross0. Always-positive .775510/.633333 beats all arms.
No default promotion, no favorable-repeat selection, no >.60 claim.

Actual first inputs verify only STATE changes; repeated inputs identical yet
predictions disagree9/12/11. Candidate true first-prompt tokens grow on44/59
samples (+467 total) each repeat despite character/byte cap compliance. All-call
usage +1.070%/-0.787% versus control does not prove per-sample compression.
358 nonempty hypotheses,330 length finishes, only29 complete ACTION JSON calls.
Added offline actual-request/metrics audit and3 tests;158 regressions pass.
All47 current/snapshot prediction hashes match; locked clone-v2 test unchanged.
Artifacts output/devign_state_eval60_20261007 and
output/devign_state_confirmation_code_snapshot_20261007. Detailed findings:
STATE_CONFIRMATION_FINDINGS_20261007.md. Next-chat file at workspace root:
下个对话交接-20261008.md. Historical blocked record above is superseded in status,
not deleted. No pending real batch; next work must not tune on these exposed60.

## 2026-10-08 — common repairs and single SRC candidate confirmation completed

Historical report figures corrected and full-scheduled conservative metrics unified
across Devign/Direct/compare. Common repairs cover dotenv ordering, budget bisection,
hop limits, fair bidirectional graph capacity/cycles, unsafe graph-cache fallback,
mixed verdicts, main/final decision receipts and restricted straight-line verifier.
These common fixes are NOT evidence for candidate-specific quality improvement.
172 mocked local regressions pass. Lexical/graph heuristics remain non-formal.

Explicit user consent covered 60 new public development groups, DeepSeek endpoint,
two arms twice, bounded steps/retries, no locked test. Seed20261011 excluded570
recorded exposure groups;32 positive/28 negative,58 valid graphs/2 preparation
failures retained without replacement. Shadow:15 SRC changes,0 non-SRC changes.
240 scheduled rows complete;235 successful actual calls,0 failed/unknown usage;
212735 returned tokens,224 length finishes. Requested deepseek-chat, all returned
deepseek-flash. Frozen input/code/receipt audit passed with0 audit API calls.

Control F1/Acc .352941/.450000 and .392857/.433333; assignment_evidence
.301887/.383333 and .482759/.500000. Always-positive .695652/.533333 beats all.
Primary F1 delta -.051054,95% interval[-.231373,+.129630]; accuracy delta
-.066667,[-.183333,+.050000]. Aggregate tokens +1.748%/+0.163% vs control.
Both arms have11 repeated-prediction disagreements; unchanged-input arm pairs
also disagree6/5 times. No robust quality/cost gain; do not choose favorable repeat.
Only documented-input-change gate passes. SOURCE_SLICE_ASSIGNMENT_FIX remains
OFF; separate validation, locked final test and submission NOT performed.
Prior STATE confirmation remains historical evidence, not this repaired code's score.

Artifacts: output/devign_assignment_eval60_20261008/{report,assignment_audit}.json,
code_snapshot and API receipts; output/research_repairs_20261008/history.json.
Protocol SEMANTIC_REPAIR_PROTOCOL_20261008.md; concise findings
SEMANTIC_REPAIR_FINDINGS_20261008.md; workspace root
修复与独立验证执行记录-20261008.md. No pending real batch or automatic promotion.

## 2026-10-08 — newly authorized SVEN budget replay started

User explicitly authorized254 public SVEN slices/graph paths/contexts to DeepSeek,
150 vs512 output tokens, both twice,1016 scheduled results, max2 steps/3 attempts.
175 mocked tests pass;254 validated source/graph inputs and254 zero-call shadows
pass. Only experimental client request max_tokens changes; production default
and all rejected candidates remain untouched. Code snapshot and first prompts
frozen before calls. Exposed SVEN replay, not independent confirmation.
Real batch output/sven_budget_eval_20261008 is in progress; no completed quality
claim yet. Full history/label-blind source visibility audits make0 API calls.
Protocol SVEN_BUDGET_PROTOCOL_20261008.md; root SVEN重测与改进分析-20261008.md.

## 2026-10-08 — SVEN budget replay completed: mechanism yes, quality no

All1016 planned results complete;1020 successful calls,0 failures/unknown usage,
913333 reported tokens. All returned deepseek-flash (requested deepseek-chat).
178 mocked local regressions pass. Complete input/receipt/metric/code/snapshot
audit passes with0 audit API calls; locked Devign test unchanged/unsubmitted.
The started entry above is superseded in status. No pending real batch.

Control F1/Acc .471042/.460630 and .522388/.496063; output512
.478764/.468504 and .507576/.488189.30 abstentions retained across arms/repeats.
All MCC<0 and all arms below always-positive F1 .673629 / Acc .507874.
Primary F1 delta+.007722, family95%CI[-.031990,+.047890]; accuracy+.007874,
[-.033333,+.052632]. Second-repeat deltas negative; tokens+7.03%/+7.00%.
Identical first requests across repeats nevertheless yield42/25 prediction
disagreements. No robust detection gain, no best-repeat selection or promotion.

Length242/254 and240/254 vs0/256 both candidate repeats; ACTION JSON12/254
and14/254 vs256/256 both. Only2 actual tool events per candidate repeat.
Candidate315 planner-recognized first tool requests total:311 suppressed by
confirmed/selective early stop (120+34 first;125+32 second),4 executed.
Mechanism gate passes; all quality gates fail. Production cap150 unchanged.
Three new label-free synthetic tests reproduce stop suppression/endpoint anchors;
not a counterfactual quality demonstration or authorization to enable old routing.

Offline version comparison: fullCPG bytes unchanged;54 compression-count changes,
total30990->32562 nodes;191 user/nonSRC inputs changed, only7 SRC changes,
system0. Multiple repairs/provider time differ; no causal component attribution.
SVEN is exposed development data:254 rows,74 exact sources,36 family-union
groups,8 exact-source label conflicts covering51 rows. Keep all primary rows.
Artifacts output/sven_budget_eval_20261008/{report,audit}.json plus manifests,
code_snapshot/API receipts; SVEN_BUDGET_FINDINGS_20261008.md and root Chinese
report. Next hypothesis should verify target-bound evidence before changing
routing, using new frozen unexposed data; no locked test or submission performed.

## User-selected isolated type-coverage reconstruction (2026-10-08)

User approved rebuilding the historical type-coverage foundation from the nearest
verified snapshot, rather than claiming an exact source rollback.47 manifest
files from output/sven_full_pipeline_code_snapshot_20261006 copied hash-identically
to baselines/type_coverage_reconstructed_20261008/src (frozen) and
development/type_coverage_reconstructed_20261008/src (editable).52 repaired
manifest source files preserved separately; root prediction code unchanged.
Historical configuration restored, TYPE_COVERAGE_PROMPT on, cap150, maxsteps2,
learning/arbitration/later candidates off. AGENTS.md identifies the editable
foundation; root main/evaluation launchers still use the repaired checkout.

Completed offline_audit_v3:508 full pipeline replays,509 saved answers,0 errors,
0 real API calls/network attempts.10/06 control matches254/254 first user/system
inputs, predictions and step counts. Historical type coverage matches254/254
predictions/system prompts/step counts but only240/254 user prompts. All14 input
differences retained. This is NOT the exact historical source version and NOT
a fresh .6115 F1 result; no new LLM score is assigned.184 local regressions pass.

Earlier incomplete attempts preserved as offline_audit/ and offline_audit_v2/:
diagnostic-stack native process failure and a stopped slow replay, respectively.
Final audit uses identical regex-query memoization, not changed scoring logic or
sample omission; its timing is not a production benchmark. New external/paid
testing remains unauthorized; no locked Devign evaluation, rollback of unrelated
changes, checkpoint activation or submission. This is a user-selected engineering
foundation, not automatic promotion based on a new quality gate.

## Reconstructed baseline: real LLM smoke and experimental publication (2026-10-08)

Separate user approval covered30 fixed stratified exposed SVEN rows, two repeats,
60 scheduled results to DeepSeek. All60 results/calls succeeded, no failed calls,
unknown usage or abstentions. Requested deepseek-chat; actual returned model
deepseek-flash on all60. Repeat F1 .580645/.588235, Accuracy .566667/.533333,
MCC .133631/.069171;52118 reported tokens.58 length finishes;3 repeated-prediction
disagreements. Always-positive F1 .666667 exceeds both scores; CWE-125 Accuracy
.30 both repeats. No matched fresh control, no independent final test, no claim
that historical61.15% was reproduced. This batch's authorization is consumed.

Independent offline audit verifies60 actual first requests/receipt identities,
usage/answers/metrics and47 unchanged source hashes.188 local regressions passed;
the portable publication package separately passes5 offline tests, including from
the actual committed ZIP in a new directory. No additional external model calls.
Artifacts output/reconstructed_llm60_eval_20261008/{report,audit}.json.

GitHub experimental branch codex/type-coverage-baseline-20261008 uploaded and
remote SHA verified:67db6e4bfc8a6bc0ac282def77b5e2e7b9daead0. Only55 new files
under releases/type_coverage_reconstructed_20261008:47 frozen prediction sources,
portable profile/tests, synthetic fixture and truthful aggregate summary. No local
dataset,CPG,checkpoint,credential or raw API receipt added. Root main/HEAD and
original index unchanged; no PR or main merge. Ignore-rule/init-file staging and
CRLF checks were corrected only in local publication tooling; prediction bytes
remain frozen. Engineering/sanity gates passing is NOT strong quality evidence.

## Full SVEN complete-provided-SRC comparison started (2026-10-08)

Diagnosed sparse evidence deleting scope delimiters and length/assignment facts;
saved smoke answers include branch/contract misinterpretations. No universal
causal explanation or quality gain claimed. Single default-OFF COMPLETE_SOURCE_SLICE
candidate added only to isolated development config.py/typed_paths.py. Preserve
provided source verbatim <=6000 characters, otherwise explicit legacy fallback;
no invented code/helper contracts, label/CWE routing or graph/prompt/parser/net/
outputcap changes. All254 rows fit,254 frozen candidate inputs differ only in SRC.

Human explicitly approved full254 control/candidate twice,1016 planned results,
public source/path/context to DeepSeek and API fees, max2 steps/3 attempts per
step.193 top-level local tests pass (one includes6 fresh-process isolated checks);
final preflight_v2 verifies47 source/tooling hashes and all source/CPG identities.
First request recipes are checked against actual requests before sending; do not
call recipe generation a full254-row production shadow. Batch RUNNING at
output/sven_complete_src_eval_20261008; no completed new score/gain claimed yet.
All74 sources/36 family groups and duplicate/conflicting labels retained.
Protocol SVEN_COMPLETE_SRC_PROTOCOL_20261008.md; diagnosis/findings
SVEN_COMPLETE_SRC_FINDINGS_20261008.md. No new GitHub push/promotion/locked test.

## Full complete-SRC comparison completed: reject for CWE-125/global goal

1016/1016 results and1017 successful calls,0 failed/unknown usage/error/abstention,
all actual deepseek-flash,1032335 tokens,974 length finishes.193 local regressions
pass. Both offline audits verify all1016 actual first requests,508 SRC-only paired
first inputs,47 candidate hashes,52 root/repaired references and47 frozen/released
source files.74 exact sources/36 family groups;8 conflicts/51 rows retained.
Started entry above superseded in status; authorization consumed, no rerun.

Global control F1/Acc .604982/.562992 and .585185/.559055; candidate .566176/
.535433 and .583942/.551181. CWE-125 control .704762/.659341 and .653061/
.626374; candidate .427184/.351648 and .460000/.406593. Primary CWE-125
Accuracy delta -.307692 family95%CI[-.637681,-.09], F1 -.277577 CI
[-.771710,-.028333]. Small-smoke30% is not a full-set baseline or evidence of
a gain to the newly observed control65.93%/62.64%. Keep matched cohorts separate.

CWE-416 Accuracy .516129/.526882->.709677/.688172, but no post-hoc CWE routing
or global promotion. CWE-190 Acc .500000/.514286->.542857/.557143 while F1
falls. Total candidate tokens +31.80%/+32.30%; first prompt tokens +38.97% both.
Repeat disagreements31 control/24 candidate. Candidate remains default OFF.
All global F1 below always-positive .673629. No locked test/submission/GitHub push.

Post-hoc saved-case diagnosis: CWE-125 losses31/28 vs gains3/8; three families
contribute23/28 net primary losses. Control idx214 gets label right while wrongly
claiming len not updated; candidate infers safety from strchr offsets but misses
the preceding scan's own readable range. Correct labels do not prove correct
reasoning. Next hypothesis is source-read target/capacity/offset/guard binding,
not indiscriminate full SRC or metadata-based routing. No further real calls.
Artifacts report/audit/audit_addendum/failure_diagnosis.json under batch output;
full findings SVEN_COMPLETE_SRC_FINDINGS_20261008.md. Protocol remains frozen.

## Foundation reselected; return to graph-guided evidence (2026-10-09)

User selected the base rather than COMPLETE_SOURCE_SLICE. Verified every current
file matched the tested candidate before restoring only config.py and
linearization/typed_paths.py byte-for-byte from the frozen foundation. All47
editable hashes now match the base; rejected code remains in the tested snapshot.
Root/repaired52, frozen47, release47, Git HEAD/index and old experiment artifacts
preserved. No new API calls, commits/pushes, locked tests or score inheritance.

Archived candidate regressions now import its hash-verified snapshot. Auditor
adds explicit read-only --archived-source mode; original auditor/test bytes remain
in tooling_snapshot. Re-audit verifies1016 first requests/508 paired SRC changes,
recomputes1016 results/1017 invocation accounting and the failed quality gates.
195 top-level local regressions pass (including nested fresh-process suites);
5 published-package tests pass separately. The first new identity test failed
on mixed historical path separators, fixed only in tooling; prediction unchanged.
The slow508-row historical replay was not rerun; previous audit remains intact.

Graph-guided code inspection: default nonfocused anchors collect every qualifying
node of the passed graph, so Top-K additions can be redundant for SRC anchors.
Record this limitation, do not certify it or silently repair the chosen base.
Next is a zero-call read target/offset/capacity/guard provenance audit through graph
compression, candidate/Top-K paths and SRC/DEP. No candidate activated or quality
gain claimed. Plan GRAPH_GUIDED_MAINLINE_20261009.md; restoration/verification
receipt GRAPH_GUIDED_RESELECTION_RECEIPT_20261009.json.

## Graph evidence audit complete; separately authorized SRC smoke (2026-10-09)

All254 exposed SVEN stage audit complete,0 errors/API; independent verifier
matches508 actual saved control SRC/DEP sections,74 sources/36 groups. Base47,
root/repaired52 and published47 preserved. V1 and smoke retained; v2 fixes
metadata-width relation bug and records supplemental API-name/line evidence.
Both versions' stage totals happen to agree on this corpus. Strict unmapped
nodes are not proof of missing operations: DOT escape decoding affects idx214.
Findings GRAPH_READ_EVIDENCE_FINDINGS_20261009.md; v2 verification.json.

Human then approved ONE isolated graph-read-dependency SRC candidate plus120
real results: same30 rows, control/candidate twice,DeepSeek/max2 steps/3 attempts,
cap150, retain failures, no reruns/full254/locked Devign/GitHub. Candidate47 files
cloned from base, only backward_slice.py changed; default foundation unchanged.
Uses existing USE_BACKWARD_SLICE hook, no compression/rank/DEP/STATE/net/parser
change. Source-bound read criteria, dependences/scope boundaries, explicit gaps,
same SRC budget; unknown/missing evidence falls back without invented contracts.

213 top-level regressions pass. Preflight runs60 actual mock pipelines,30
control first inputs exactly reproduce verified foundation, all paired first
inputs differ only in SRC. Only5/30 changed (1/10 CWE-125);25 legacy fallbacks
retained. Source/tool/request freeze at output/graph_read_slice_preflight_20261009.
Real batch started output/graph_read_slice_llm120_20261009. This is RUNNING,
not a completed gain; actual observed alias returns deepseek-flash so far.
Protocol GRAPH_READ_SLICE_LLM_PROTOCOL_20261009.md; no additional authorization.

## Graph-read SRC smoke complete: quality gates fail, keep foundation

Prior RUNNING entry superseded:120/120 rows,120 successful actual calls,0 failures/
unknown usage/abstentions,all deepseek-flash,104087 tokens,111 length finishes.
Independent audit verifies120 first requests,60 SRC-only paired inputs,47 source
and tooling snapshots,trace/usage/full-denominator confusion arithmetic. API
authorization consumed, no reruns/full254/locked test/push or automatic promotion.

Global control F1 .545455/.562500,Acc .500000/.533333; candidate .580645/.428571,
Acc .566667/.466667. CWE125 control F1 .500000/.461538,Acc .400000/.300000;
candidate .333333/.461538,Acc .200000/.300000. All four quality gates fail.
Control repeats differ5/30,candidate7/30; all F1 below always-positive .666667.

Frozen-input decomposition:5 changed rows (12,95,117,123,218) net correct delta
0/-3;25 unchanged-input rows +2/+1,with6/5 prediction differences. R1 global gain
is entirely unchanged-input variation, not credible SRC gain. Keep all30 as
primary denominator; no selected-success scoring. Source policy's Top-K read
criteria cover only5 rows,1 CWE125; next hypothesis is read-target path coverage,
not indiscriminate SRC/metadata routing or multiple simultaneous changes.
Report GRAPH_READ_SLICE_LLM_FINDINGS_20261009.md; audit/effective_pairs in run.
Default/frozen foundation, root repair and published source remain preserved.

## 2026-10-09 — Standing full-dataset evaluation policy

User requires every future model-quality evaluation to cover the entire declared
dataset/split. Current local SVEN:254 rows; baseline-only two repeats:508 planned
results; baseline/candidate two repeats each:1016. Full request preflight and
planned-denominator scoring are mandatory, retaining failures and unchanged-input
pairs. Historical sampled runs and frozen tools remain unchanged. Synthetic unit
checks are engineering validation only. No new API calls, paid authorization,
source changes or GitHub upload occurred for this policy update.
See EVALUATION_SCOPE_POLICY.md; batch-specific external/cost approval remains
required, and locked Devign restrictions remain in force.

## 2026-10-09 — Graph display selection candidate, offline validation RUNNING

User asks to resolve what is selected and actually displayed. New isolated47-file
candidate graph_display_candidate_20261009 changes only retrieval/retrieve_topk.py.
Existing candidate paths, graph compression,35-character node serializer,2/4 DEP
slots,260/300-character body budget,SRC,STATE,output150 and prediction logic are
unchanged. Rank selection prioritizes complete visible read diversity and bound
same-path dependence fact candidates; these are not capacity/dominance proofs.
Full254 paired offline preflight output/graph_display_preflight_20261009; actual
mock request records checked for DEP-only changes and unchanged graph/candidates.
No API authorization/calls, new model quality claims, activation or GitHub upload.
Nine isolated policy tests pass. Full214 top-level regressions first hit Windows
sandbox temp-directory permissions, then pass in the same scoped local rerun.

## 2026-10-09 — Graph display full-scope offline verification COMPLETE

Prior RUNNING entry superseded. Both full254 v1/v2 preflights retained; v2 fixes
ordered visibility of equal expressions behind truncation and selected-path logs.
Source/tool snapshots freeze47 source files, only retrieve_topk.py differs from
foundation (SHA64f942860ba0dce160cac178fa4447976e0b9cf6b223270b7b3ee11aeb4cb938).
Independent v2 verifier checks508 mock request records/calls,508 historical control
first requests and254 pairs,zero errors/external attempts/real API calls.106 DEP-only
actual input changes (CWE12567,CWE19019,CWE41620). Graph nodes/edges,existing candidate
set,SRC/STATE/system/request parameters and display caps unchanged.10 isolated
policy tests and214 top-level tests pass; do not double-count wrapper children.

Complete DEP lexical expression counts:reads33->280,updates24->46,conditions51->95;
gained247/22/44,lost0/0/0. CWE125reads15->201 of466 candidates,NOT201 correct samples.
Source macro9.41%->48.72%,family6.27%->37.50%,distinct denominators. FREE/ALLOC labels
unchanged2/53 rows; this is not lifecycle completeness or non-regression proof.
Total message characters536522->540088; no API Token usage measured. idx214 length
updates still absent; decoder/35-character truncation/capacity remain known limits.
Candidate frozen/not default,not real-LLM tested,no new paid authority,push or paper
claim. See GRAPH_DISPLAY_FINDINGS_20261009.md and full v2 verification/decomposition.

## 2026-10-09 — Authorized graph display real LLM full254 batch RUNNING

Human explicitly approves one254-row control/display-v2 two-repeat comparison,
1016 planned results to DeepSeek,cap150,max2 steps/3 attempts per step,SDK retries0,
record actual returned models,all failures retained. No locked Devign,push,automatic
rerun or promotion. Candidate prediction source unchanged/frozen; source/module
hashes remain those of completed graph-display v2 offline preflight.
New protocol GRAPH_DISPLAY_LLM_PROTOCOL_20261009.md preregisters quality gates.
Runtime preflight v1 retained with tools; v2 adds robust unknown-usage handling and
full preflight artifact hashes. Full254/1016 mock runtime requests match frozen
recipes,219 top-level engineering tests pass. Live output scheduled at
output/graph_display_llm1016_20261009. Pair order counterbalanced/interleaved within
sample,4 workers. Persisted deterministic selection cache requires current graph
and candidate-list hashes; no old answers replayed or retrieval speed claim.

## 2026-10-09 — Graph display real full254 comparison COMPLETE, not selected

Prior RUNNING entry superseded.1016/1016 results,1019 successful actual calls,
0 failures/unknown usage/abstentions,actual deepseek-flash throughout,894462
reported tokens,972 length finishes. Three results used a second step.219
top-level engineering tests passed before paid calls. Independent audit passes
1016 first requests,508 DEP-only pairs,47+47 source/tool snapshots,step/attempt
and actual answer/trace/token/full-denominator arithmetic. Authorization consumed;
no rerun,default activation,locked Devign,GitHub upload or submission claim.

Control overallF1 .593407/.590406,Acc .562992/.562992;display .597122/.593407,
Acc .559055/.562992. CWE125 controlF1 .680000/.610526,Acc .648352/.593407;
displayF1 .615385/.597938,Acc .560440/.571429. Four quality gates fail; only the
predefined CWE190/416 balanced-accuracy2pp non-inferiority gate passes. All global
F1 below always-positive .673629. Model repeats differ24/254 control,27/254 display.
Primaryr1 globalF1 delta+.003716 family95%CI[-.053508,.083027],CWE125Accuracy
delta-.087912 CI[-.137931,-.032000]. Do not claim detection gains from DEP
coverage33->280 or route by the better CWE416 subgroup. Changed106 rows net
correct+4/+2;unchanged148 rows -5/-2;full-denominator net -1/0 remains primary.
idx214 predictions match its positive label but actual contexts still lack
len/line updates and explanations lean on their absence,not correct-reasoning proof.
Candidate/source47 frozen and default foundation47 preserved. Read
GRAPH_DISPLAY_LLM_FINDINGS_20261009.md; runtime manifest SHA
e0fbd15636748c1224e67bc41a1826bf61451bf4074a2a5e183189894bcf0e93.

## 2026-10-09 — Whole graph evidence v2 COMPLETE, foundation retained

User approved offline whole-node/length-update fixes and then explicitly one
full254 real control/candidate batch, two repeats/1016 results/150-output/max2
steps/3 attempts per step. v1 and v2 full254/508-mock offline outputs retained;
v1 found zero true upstream assignment cards. v2 exact unique AST-LHS ownership
restores complete assignments encountered as dependency identifiers, not AST-as-
dataflow or guard proof. No ranking/compression/SRC/STATE/decoder change;48 source
files (one changed foundation module plus one new module),foundation47 unchanged.
v2 independent graph audit52 AST-bound update cards/617 long graph fields, lexical
reads/updates/conditions33/24/51->56/87/95.693 whole-node omission attempts retained.
227 top-level regressions and1016 actual mock runtime requests pass before live.

Live output output/graph_evidence_cards_llm1016_20261009 COMPLETE:1016 results,
1020 successful calls,all actual deepseek-flash,0 errors/unknown usage/abstentions,
876224 reported tokens,974 length finishes. Four candidate results use two steps.
Independent audit passes1016 first requests/508 DEP-only pairs/source48+47/tools/
traces/usage/full denominators. Only1/5 quality gates passes;functional true.
Control F1 .576779/.576642,Accuracy .555118/.543307;candidate F1 .630137/.595890,
Accuracy .574803/.535433. CWE125 Accuracy .659341/.637363->.714286/.648352,
but CWE190 .542857/.514286->.400000/.371429;family intervals cross0 and all
globalF1 below constant.673629. Source/family macroAccuracy also declines.
idx214 now sees firstlen assignment but model reasons remain contradictory or
borrow destination capacity for source safety; not correct-reasoning proof.
Keep default foundation,candidateOFF,no CWE routing/auto-rerun/GitHub/locked
Devign. Authorization consumed. Read GRAPH_EVIDENCE_CARDS_LLM_FINDINGS_20261009.md.
Runtime manifest SHA798a586ada77720979406f6b0dc77a6f753db0777e827586b7c7dbaa20c6c6c3.
