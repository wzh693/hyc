# Budgeted atomic evidence: offline gate (2026-10-07)

Candidate `BUDGETED_EVIDENCE_GROUPS` remains OFF by default. This is a
preservation-mechanism check, not evidence of improved F1/Accuracy.

## Frozen development inputs

`output/devign_grouped_confirmation60_20261007`: 60 newly sampled development
groups, seed20261008, excluding390 recorded exposed development groups and
the protocol quarantine. Selection SHA256:
`96537dcbbfe2e81d9a6b061a1b0ca608a7dfc8d90097d510e81d50cbc67b190a`.
Labels were not used in selection; resulting distribution30/30. Valid CPGs57;
preparation failures3 (indices22636,19019,4020). No replacement or dropping;
all60 must count in every real evaluation arm. Recorded grouping is not a
guarantee of total project separation or zero unrecorded historical exposure.

## Production-TopK zero-call shadow

Receipts: `output/devign_grouped_shadow60_20261007/rows.json` and `report.json`.
The production compression/TopK pipeline used intercepted synthetic answers;
real API creation/calls were blocked. Source hashes and prediction code hashes
were checked. Neither labels nor saved prediction outcomes selected evidence.

- 60 scheduled rows,57 evaluated valid graphs,3 preparation-error rows retained.
- 206 candidate groups,73 admitted whole mapped groups.
- 10 admitted groups include explicit control-parent and exit nodes, across6
  samples. This does not prove a protective guard, reachability, or complete
  semantic dependence coverage.
- Changed SRC on8 samples; other52 include3 failures and49 unchanged valid
  inputs. Mechanism exposure is limited: an aggregate quality change cannot
  automatically be attributed to grouped preservation.
- Zero character/UTF8-byte growth, admitted-group splits, or protected baseline
  criterion/allocation/free line losses. These assertions cover mapped evidence;
  unmapped/capped/rejected groups are separately recorded, not claimed complete.
- No API calls. Character/byte budgets are not exact provider token counts.

126 local regression tests passed. Additional targeted10 tests passed after
extending the offline summary to support the new three-arm repeated protocol.
Locked-test manifest SHA256 unchanged:
`758d04f55d919b322f7731e082fa58a184c9300e902ba47654ae0590eabc6d08`.

## Independent real-call gate: not started

Zero-call preflight passed in `output/devign_grouped_preflight60_20261007`.
Preregistered plan: standard/control, plain slice, grouped slice, each repeated
twice (360 scheduled results); no output-contract/GAT/graph safety-net/enhanced
expansion activation. Existing source verifier and legacy routing are common
to all arms. Full-denominator conservative metrics, majority baselines,
paired-group intervals and returned token usage required; no best-repeat choice.

The real-run command was rejected before process creation by automatic safety
review: it requires explicit authorization for source/context payloads to the
configured endpoint. Read-only endpoint verification found
`https://api.deepseek.com/v1`. Intended payload consists of selected Devign
source evidence, graph paths and reasoning messages, not credentials or `.env`
files. No workaround or alternate endpoint attempted. The real output directory
does not exist; there are no new real predictions, paid calls or F1/Accuracy
results to report. Request explicit user approval for this destination/payload,
then retain the frozen protocol; do not tune rules using this confirmation set.

Conclusion: offline mechanism gate passes with limited exposure; detection
quality/token gate is pending. Candidate not promoted. Prior SVEN/Devign scores
and artifacts unchanged.

## Subsequent authorization and launch

User explicitly approved the stated Devign source/path/reasoning payload to
`https://api.deepseek.com/v1`. The same frozen command was then accepted and
launched in `output/devign_grouped_eval60_20261007` (360 scheduled results).
The preceding refusal describes the initial attempt only. Results remain
pending; no quality claim or default activation follows from launch.

## Completed frozen independent development comparison

All360 scheduled results completed. Each arm/repeat includes all60 original
samples, including3 preparation failures; no replacement/dropping.351 observed
API invocations,350 returned successfully; one `Connection error.` on
sample003804 grouped/r2 was retried successfully, with failed-attempt usage
unknown. No additional final pipeline errors or uncertainty.305/350 successful
calls ended with `length`; this is a major output-budget limitation, not proof
that truncation caused particular misclassifications. Requested alias
`deepseek-chat`, returned name `deepseek-flash`; exact provider weights unknown.
Frozen prediction code was unchanged throughout.127 local regressions pass.

Artifacts: `output/devign_grouped_eval60_20261007/manifest.json`,
`results.jsonl`, `api_receipts.jsonl`, `report.json`, `analysis.json`.

| Arm | Repeat | F1 | Accuracy | TP/TN/FP/FN | Returned tokens/sample |
|---|---|---|---|---|---|
| Standard control | 1 | .655172 | .666667 | 19/21/9/11 | 866.92 |
| Plain slice | 1 | .472727 | .516667 | 13/18/12/17 | 864.97 |
| Grouped slice | 1 | .509091 | .550000 | 14/19/11/16 | 862.40 |
| Standard control | 2 | .526316 | .550000 | 15/18/12/15 | 867.30 |
| Plain slice | 2 | .481481 | .533333 | 13/19/11/17 | 863.48 |
| Grouped slice | 2 | .561404 | .583333 | 16/19/11/14 | 833.65 |

FP/FN include preparation abstentions; denominator60, coverage.95 throughout.
Returned usage includes every returned call, not just first prompts; unknown
failed-attempt usage is not zero and reductions are not exact billing savings.
Always-positive F1 .666667/Accuracy .5; always-negative F1 0/Accuracy .5.
No arm beats the always-positive F1. Standard r1 exceeds .60 on both metrics,
but r2 does not; no best-repeat selection or publication-scale claim.

### Mechanism and provider sensitivity

Both grouped repeats exactly reproduce shadow206 groups/73 admitted/10 with
control+exit.50 valid rows have group audit (others have empty plain slices);
49/57 valid grouped-vs-plain first complete requests are identical,8 differ.
All profiles' repeated first complete requests match57/57. Final prediction
disagreements across repeats: control9, plain9, grouped4. Control all9 occur
with both calls single-step; all57 first returned texts differ despite identical
complete requests. Grouped's lower disagreement on this pilot does not prove
general stability.

Descriptive changed-input cohorts, NOT new evaluation subsets or tuning targets:

| Repeat | Input cohort | n | Plain correct | Grouped correct | Prediction disagreements |
|---|---|---|---|---|---|
| 1 | Changed SRC | 8 | 5 | 6 | 1 |
| 1 | Identical input | 49 | 26 | 27 | 7 |
| 2 | Changed SRC | 8 | 6 | 6 | 0 |
| 2 | Identical input | 49 | 26 | 29 | 5 |

In repeat2 the aggregate Accuracy improvement over plain comes entirely from
identical-input pairs. Repeat1 improvement is split between changed and
unchanged inputs. Therefore aggregate improvement cannot be attributed to atomic
group preservation. Only one changed-input prediction differs in repeat1, with
no repeat2 disagreement; causal benefit remains unproven.

First prompt token totals grouped-minus-plain are -63 across57 paired samples,
the same in each repeat. However sample012855 increases791->793 prompt tokens
despite smaller chars/bytes. Strict per-sample remote-token nonincrease fails;
local character/byte gate remains valid. Do not describe this as exactly equal
token budgets. No provider-specific tokenizer was available.

Existing outer source verifier flips sample012190 (benign)0->1 in BOTH standard
repeats, causing an FP; zero flips in plain/grouped. This is not the disabled
graph safety-net candidate. One repeated case is not sufficient for post-hoc
threshold tuning or a new default, but reinforces the need to audit safeguards.

### Preregistered first-repeat paired group intervals

2000 bootstrap draws, seed20261007; marginal/exploratory, not adjusted for
multiple comparisons or future provider variation:

- Grouped-minus-plain F1 +.036364, CI[-.087784,+.160955];
  Accuracy +.033333, CI[-.050000,+.133333]. Both include0.
- Grouped-minus-control F1 -.146082, CI[-.325677,+.025886];
  Accuracy -.116667, CI[-.266667,+.033333]. Both include0.
- Plain-minus-control F1 -.182445, CI[-.356643,-.025543];
  Accuracy -.150000, CI[-.316667,-.016667]. Negative on primary repeat,
  but not a guarantee over other groups/provider responses.

Decision: quality gate NOT passed; default unchanged and candidate OFF. Keep
implementation/receipts as a bounded preservation experiment, not a proven
F1/Accuracy contribution. Do not tune or repeatedly select winners on these60
now-exposed groups. Next useful development direction is label-independent
slice completeness/coverage auditing and output-truncation measurement, followed
by a separately reserved comparison. No failed GAT/graph-net/short-contract
activation merely to fit the Method draft.
