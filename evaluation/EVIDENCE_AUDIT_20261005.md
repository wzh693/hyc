# Evidence completeness and tag audit

Among the 30 existing Devign frozen development prompts, 8 contain safety tags
on BLOCK/CONTROL_STRUCTURE/METHOD nodes. `_node_security_hit` matched complete
body text and enclosing method metadata, not just the current operation. Examples:
11346 tags a do/block as FREE although neither release is visible in SRC;
25952 shows free-containing bodies while omitting allocation/use and middle
control-flow context. The model falsely interprets those bodies as a different
function. This is an evidence presentation failure, not proof of the true label.

`STRICT_OPERATION_TAGS=1` is a default-OFF candidate. It restricts security tags
to CALL nodes whose masked code starts with the actual API invocation. Body
nodes, method metadata, literals, identifiers and outer assignment operators
cannot acquire an API tag. Actual nested call nodes remain eligible. It affects
ranking/anchors as well as presentation, so future testing must report all changed
inputs and cannot claim a serializer-only intervention. This switch participates
in cache fingerprints and SVEN configuration receipts. 48 relevant tests pass.

Three explicitly authorized forensic LLM calls compared full source with the
original input, without labels. Total 10,274 reported tokens; all three hit the
650-token output cap. Receipts: `sven_eval/external_type_check/evidence_audit_20261005/`.
These selected examples cannot estimate accuracy or explain dataset ground truth.

Human source review rejects textual double-free claims at early-return release
branches. Candidate issue: 11346 permits `path_len == PATH_MAX-1` under its local
assertion, yet writes `path2[path_len+1]`; the guard/declaration/writes are not all
preserved in the displayed slice. Caller constraints and assertion-build behavior
remain unverified. For 25952 the full source contains an av_mallocz-to-buffer-use
sequence absent from SRC; callee contracts are needed to confirm an actual bug.

LLM outputs contain errors and are NOT accepted wholesale: they speculate about
pstrcpy behavior without its implementation, and say an unbraced if has no body
even though the next assignment is its C statement body. Ground-truth vulnerability
types require original fix/callee evidence; do not derive them from model stories.

Recent experiments did not enable learned summarization/path ranking. The existing
GAT report gives bag AUC 0.6507 on 120 holdout functions and anchor separation
0.0002 (untrained 0.001). This is not evidence of effective node localization.
The model returns gated MIL readout attention, not GATv2 edge-attention weights;
scorer then applies percentile-rank penalties. Paper wording must distinguish
these mechanisms. Merely enabling the checkpoint is not a justified F1 fix.

Next experiment: unchanged safety net, prompt policy, output cap and model;
strict operation tags as the sole enabled candidate, same development functions,
fresh paired calls. Keep validation/locked test untouched; do not retune from the
three selected error examples or use this audit as a gain claim.

## Strict-tag paired pilot outcome

Preparation regenerated both prompts and verified all control inputs match the
original snapshots. 8/30 candidate inputs changed. API review declined doubling
the earlier 60-call scope to 120; one complete paired repeat (60 fresh calls) was
approved and completed instead. No old responses were reused.

| Metric | Control | Strict operation tags |
| --- | --- | --- |
| F1 | 0.3704 | 0.4286 |
| Accuracy | 0.4333 | 0.4667 |
| Mean actual tokens | 998.13 | 991.37 |
| TP / FP / FN / TN | 5 / 7 / 10 / 8 | 6 / 7 / 9 / 8 |

CRITICAL attribution check: the ONLY prediction disagreement is idx 21990,
whose input is identical on both sides. Every one of the 8 changed-input rows
has identical binary predictions. Thus the apparent improvement is from fresh
API response variation, not demonstrated benefit from strict tagging. Input
token savings average 6.77 total tokens/call (about 0.68%); output variation also
contributes to total tokens. No efficacy claim, no default activation.

Bootstrap delta-F1 CI [0, 0.1944] over fixed receipts cannot establish causality
and does not account for future API variability. One repeat cannot measure
between-repeat stability, even though the generic summary prints zero observed
repeat disagreements. 29/30 control and 28/30 candidate answers hit the 150-token
cap. This is a single-pass development pilot, not full adaptive evaluation.

Artifacts: `operation_tag_snapshot_20261005/`, `operation_tag_pairs_20261005/`
and `operation_tag_summary_20261005.json`, under `sven_eval/external_type_check/`.
Keep candidate OFF. Next priority is completeness of operation-centered source
evidence, not threshold tuning based on this noisy apparent gain. Separate GAT
validation and clean near-clone protocol work remain outstanding.
