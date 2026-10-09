# Full SVEN pipeline findings — 2026-10-06

**Full execution completed. Slice+expansion candidate does not pass the quality
promotion gate. No defaults, thresholds or checkpoints changed.** This is a
previously exposed SVEN benchmark replay, not independent held-out confirmation.

## Frozen setup and integrity

All254 rows (129 vulnerable / 125 benign), two fresh full passes, 508 unique
sample/profile receipts. Same type-covered model prompt, output cap150, graph
budget4096, max2 reasoning rounds, source threshold4 verifier, no arbitration.
Only backward SRC slicing and enhanced full-CPG expansion differ. Control retains
legacy expansion routing. Learned scores/GAT, graph safety net and rejected short
output policy are off in BOTH profiles. Current heuristic baseline is not the
paper's complete learned GAT-plus-graph-net architecture.

117 local tests passed before calls. Prediction/input hashes verified before,
between and after profiles. Dataset unchanged. Locked Devign test unused and
manifest SHA256 unchanged:
758d04f55d919b322f7731e082fa58a184c9300e902ba47654ae0590eabc6d08.
Returned model deepseek-flash, requested alias deepseek-chat; exact provider
weights unknown. Do not claim a controlled comparison with another paper's model.

Artifacts:
- output/sven_full_pipeline_inputs_20261006/preparation.json — all254 graph inputs;
  239 validated copies, 15 fresh Joern builds. Old source/cache files preserved.
- output/sven_full_pipeline_eval_20261006/manifest.json — settings, source/graph
  identities and code hashes; frozen protocol in SVEN_FULL_PIPELINE_PROTOCOL_20261006.md.
- Same output directory: results.jsonl, api_receipts.jsonl, execution.log, report.json.
- Failed zero-call preflights retained separately; no predictions recycled.

SVEN input slices may omit signature parameters/braces. Preflight found the
historical wrapper could place braces in macro arguments or later conditions.
Repaired balanced multiline signatures and incomplete-signature synthetic wrappers
BEFORE calls, equally for both profiles. Original LLM source unchanged. Unique
whole-source line-preserving mapping now validates all254 wrappers; it rejects
ambiguous or altered body mappings. Stub/header text is not original SRC evidence.
This is syntax repair, not reconstruction of missing original program semantics.

## Whole-dataset primary results

Full denominator; no errors/abstentions dropped. Both profiles have coverage1.00,
zero final pipeline errors, zero uncertain predictions.

| Profile | F1 | Accuracy | TP | TN | FP | FN | Mean returned-usage tokens |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Type-covered heuristic control | .588235 | .559055 | 80 | 62 | 63 | 49 | 877.54 |
| Slice + expansion, old output | .523077 | .511811 | 68 | 62 | 63 | 61 | 848.68 |

Candidate-control delta: F1 -6.52 percentage points, Accuracy -4.72 points;
net12 fewer TP, unchanged FP count. Returned-usage tokens -3.29%, not a quality
gain. Candidate has two failed API attempts with unknown usage/billing; do not
treat missing usage as free or claim exact total billing savings.

515 observed invocations: control255 successful; candidate260 including258
successful and2 failed/retried. No hidden SDK retries. All returned usage saved:
control222894 tokens, candidate215565. Truncation: control245/255 successful
calls, candidate231/258. Eliminating a few truncations did not establish benefit;
output truncation still severely restricts explicit expansion requests.

Always-positive baseline F1 .673629 / Accuracy .507874; always-negative
F1 .00 / Accuracy .492126. Neither tested profile meets >.60 on BOTH metrics,
and neither beats the positive baseline on both. Do not declare the publication
quality target achieved or replace historical SVEN scores with Devign60 scores.

## Per-CWE results, all rows retained

| CWE | n | Control F1 | Candidate F1 | Control Accuracy | Candidate Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: |
| CWE-125 | 91 | .6667 | .4878 | .6484 | .5385 |
| CWE-190 | 70 | .6374 | .5747 | .5286 | .4714 |
| CWE-416 | 93 | .4471 | .5055 | .4946 | .5161 |

UAF point gains do not offset OOB-read/integer-overflow losses. No CWE-specific
policy is selected from these outcomes. Historic screenshot counts/other runs
with different denominators, model receipts or code are not matched comparisons.

## Module execution versus demonstrated contribution

Both profiles:254 compression executions,254 TopK executions,254 source-verifier
executions. All254 graphs actually reduce: total nodes108540 ->30990. Counts
include synthetic wrapper/stub graph material and are not a clean token-saving
ablation. TopK empty on1 sample in each profile; that sample remains in metrics.
Same original/compressed node totals in both profiles, so no compression-setting
change explains the candidate contrast. No no-compression/no-TopK ablation in
this run; execution is not proof of either module's quality contribution.

Candidate slicing enabled254/254:30 no-criterion fallbacks,86 budget omissions,
225 graphs have control-dependence availability. First system/user messages
change on214/254 paired samples;40 remain unchanged. Mapping repair solved the
wrapper-coordinate defect but does not guarantee complete dependence evidence.

Enhanced expansion enabled254/254 but only4 successful new-path events and4
second-step samples. Control has1 second-step sample via legacy routing. The
upgrade is rarely triggered; two-arm comparison cannot isolate slice, routing
and provider variability individually. Do not attribute aggregate losses solely
to missing evidence without a separate controlled diagnosis.

Existing SOURCE verifier zero flips on BOTH full passes; no observed contribution
to these predictions. It is not the graph safety net. Learned scoring, graph net
and short-output policy all have zero active samples, verified in receipts.
Do not claim the rejected learned/shared-attention contribution was evaluated.

## Correlated rows and repeat limits

74 exact sources,36 conservative union groups linked by source OR source-family
filename. Eight identical-source groups have conflicting labels (51 rows).
Primary rows retained. Supplement uses lowest-index representative of each of
66 consistently labelled exact-source groups: control F1 .5424 / Accuracy .5909;
candidate .3636 / .4697. This is supplementary, not a replacement benchmark.

Paired family-cluster bootstrap,2000 draws seed20261006:
delta F1 CI95[-.18085,+.04554]; delta Accuracy CI95[-.12016,+.03030]. Both cross
zero, so no robust positive gain and no claim of statistically proven negative
effect.72/254 final prediction disagreements. One fresh run/profile does not
isolate future provider variability; this dataset was already development-exposed.

## Decision

Keep the earlier Devign60 .6774/.6667 result in the ledger as exploratory evidence,
but mark this configuration as **not promoted / SVEN replay quality gate failed**.
No overwrite or best-of-runs selection. Retain heuristic control and leave all
new candidates default off. Full pipeline usability is verified; >.60 F1/Accuracy
and the learned/graph-net paper contributions are NOT established.

Next implementation work should diagnose evidence preservation and bounded
output/routing separately, using fixed-answer/offline evidence checks first and
a preregistered group-disjoint development comparison before activation. Do not
respond to these scores with post-hoc CWE routing, locked-test tuning or a
selective favorable rerun.
