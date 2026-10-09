# Field-order candidate: implementation and preflight, real calls pending

ACTION_BEFORE_REASONING default OFF. Only swaps the existing ACTION and REASONING
format lines, leaving OBSERVATION/HYPOTHESIS positions, vocabulary, wording,
decision requirements and150 output-token limit unchanged. Does not enable
bounded output, slicing, grouping, GAT, graph-net candidate or enhanced expansion.
Combining with bounded_output raises an error. Standard prompt flag-OFF equality
and flag-ON exact line multiset/byte length preservation verified by unit tests.
136 total local regressions passed; no quality/cost improvement claim.

Previous grouped-run prediction code verified against its manifest and copied to
`output/devign_grouped_code_snapshot_20261007` before modifications. No credential
files copied; old results and analysis unchanged. Runner now records per-profile
effective settings and CPG hashes; verifies effective config before each arm and
source/graph hashes per sample. Offline format audit checks actual paired requests
have identical user evidence and other request parameters, with only system-line
order changes; evaluates action JSON availability separately from F1/Accuracy.

## New independent development preparation

`output/devign_action_order60_20261007`, seed20261009,60 groups,450 recorded
exposed development groups excluded plus existing protocol quarantine. Selection
SHA256 `68b11e52f2506816f2b40e91203514c83e24e23c0428cfc1dbc484736aaa5bbb`.
No label-based selection, rebalancing or replacement;60 valid graphs,0 preparation
errors. Labels revealed after selection:38 vulnerable/22 benign. Always-positive
F1 .775510,Accuracy .633333; always-negative F1 0,Accuracy .366667. Merely exceeding
.60 is not sufficient evidence of useful quality on this distribution. Development
group exclusion is not proof of total project separation or unrecorded exposure.
Locked test and validation not used for tuning.

Zero-call preflight at `output/devign_action_order_preflight60_20261007` passed:
effective config,source/group identities,graph hashes and field-order-only checks.
Preregistered `evaluation/ACTION_ORDER_PROTOCOL_20261007.md`: standard control
versus action_first, both repeated twice,240 scheduled results; first repeat primary,
no best-repeat selection, conservative full-denominator metrics, majority baselines,
paired group intervals, complete usage and action parseability required.

## External-call authorization blocker

Real-run command was rejected before process creation by automatic safety review.
The reviewer requires explicit authorization for this NEW60 Devign sample payload
to `https://api.deepseek.com/v1`; it did not accept prior grouped-batch approval or
the user's general agreement to continue as authorization for the new payload.
Intended payload: source evidence, graph paths,reasoning messages; credentials
files excluded. No bypass/alternate endpoint/retry workaround. The intended real
output directory `output/devign_action_order_eval60_20261007` was not created.
No real model calls, costs or classification scores from this candidate exist.
Ask explicit approval of this new60 payload/destination before proceeding.

Default unchanged. Once authorized, freeze existing candidate/protocol rather
than adjusting after outcomes, run both repeats fully and save unsuccessful arms.

## Subsequent explicit approval and launch

User explicitly approved the new60 sample payload and stated a preference not
to be repeatedly asked. The same frozen real-run command was accepted and
launched at `output/devign_action_order_eval60_20261007` (240 scheduled results).
The earlier refusal describes only the initial attempt. System security review
cannot be disabled/bypassed by the assistant. No quality claim follows from launch.

## Completed independent development comparison: candidate rejected

All240 scheduled results completed,60 per arm/repeat, no dropped or replaced
samples.244 observed successful API invocations,0 failed attempts,0 final
pipeline errors or uncertainty; actual returned model name deepseek-flash for
deepseek-chat alias. Exact provider weights remain unknown.136 local regressions
passed. Prediction-code hashes match the run; verified code snapshot saved at
`output/devign_action_order_code_snapshot_20261007`, no credential files copied.
Locked-test manifest hash unchanged.

Artifacts: `output/devign_action_order_eval60_20261007/manifest.json`,
`results.jsonl`, `api_receipts.jsonl`, `report.json`, `analysis.json`,
`format_audit.json`. No later model calls or outcome-driven prompt edits.

| Arm | Repeat | F1 | Accuracy | TP/TN/FP/FN | Returned tokens/sample |
|---|---|---|---|---|---|
| Standard control | 1 | .666667 | .650000 | 21/18/4/17 | 950.92 |
| ACTION before REASONING | 1 | .509091 | .550000 | 14/19/3/24 | 906.50 |
| Standard control | 2 | .727273 | .700000 | 24/18/4/14 | 922.02 |
| ACTION before REASONING | 2 | .551724 | .566667 | 16/18/4/22 | 907.93 |

First-repeat candidate-minus-control F1 -.157576, marginal group-bootstrap95% CI
[-.313750,-.022599]; Accuracy -.100000, CI[-.200000,0].2000 draws,seed20261007,
exploratory/unadjusted; intervals do not capture all future provider variation.
Second-repeat point deltas F1 -.175549/Accuracy -.133333. Both repeats show worse
quality; candidate not enabled. Standard meets both>.60 on this pilot twice,
but always-positive F1 .775510 remains higher. These are independent recorded-group
development results, NOT a new official benchmark or universal quality guarantee.
Archive standard as reference, not a newly improved algorithm or best-repeat winner.

### Mechanism works, quality does not

Actual paired first requests verify60/60 each repeat: user evidence identical,
all other request parameters identical, system line multiset identical, only
ACTION/REASONING order changes. Within each arm repeated first requests match.
All244 returned answers match reasoning traces. All have nonempty HYPOTHESIS.

| Arm/repeat | First-call valid ACTION/planner parsed | First-call length finishes | Two-step samples |
|---|---|---|---|
| Standard/r1 | 6/60 | 54/60 | 3 |
| Candidate/r1 | 55/60 | 54/60 | 0 |
| Standard/r2 | 7/60 | 54/60 | 1 |
| Candidate/r2 | 55/60 | 54/60 | 0 |

No complete ACTION JSON was missed by the planner. Across all returned calls,
standard63/r1 and61/r2 each have7 parsed actions; candidate60 each has55. Moving
ACTION earlier does recover machine-readable actions despite ongoing truncation,
but does not recover lost evidence or guarantee better semantic decisions.
False negatives rise17->24 and14->22; false positives4->3 and4->4. Thus quality
loss is dominated by fewer true positives, not a favorable precision/recall tradeoff.
Do not claim a specific causal reasoning failure from these counts alone.

Candidate returned token totals are4.67% lower in repeat1 and1.53% lower in repeat2.
Savings accompany fewer second-round calls; do not present them solely as shorter
first-input context. Report full-call usage, not only the150-token completion cap.
Provider caching/prices are unmeasured, so token reductions are not RMB billing
savings. Final prediction disagreements across repeats: standard7,candidate9.
Better action syntax does not establish better stability. Existing source verifier
flips2/3/2/2 rows respectively; GAT and graph safety-net candidate stay OFF.

Decision: retain code/tests and raw receipts, keep ACTION_BEFORE_REASONING OFF;
no short-contract revival, threshold tuning, extra selective repeats or locked-test
changes. Formatting experiments did not meet quality gate. A subsequent primary
direction should audit actual evidence/state consistency and source coverage,
with label-independent counterexamples/tests before new independent evaluation.
