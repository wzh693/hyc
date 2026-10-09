# Pipeline wiring audit — 2026-10-06

Status: integration candidate, **not an F1/Accuracy improvement release**.

## Production entry points

`graph.pipeline.run_hgl_pipeline` now owns CPG loading, compression, retrieval,
reasoning and final verification/arbitration. Single-file analysis, HGL evaluation,
Devign evaluation and robustness evaluation call it. SVEN/compare retain a thin
compatibility wrapper. Constrained ablation configurations also call this pipeline;
`no_constr_reason` remains an explicitly separate flat-LLM baseline, not an HGL
production entry point. All entry points retain their dataset/output adapters.

This changes older entry points that previously bypassed verification. Do not mix
their historical predictions with shared-pipeline results. The original SVEN
receipts and model checkpoints have not been overwritten.

Learned scoring is no longer loaded/computed when neither compression nor retrieval
consumes it. Function/block summaries are skipped for compact SRC/PATHS/STATE.

## Independently controlled candidates

All three new environment switches default to **0**:

- `USE_BACKWARD_SLICE`: Top-K dangerous-call/dereference/index criteria; reverse
  REACHING_DEF/DFG and CDG/CONTROL_DEPENDENCE edges on the complete CPG. CFG
  predecessors are **not** called control dependence. Exact wrapped-source offset
  mapping; whole-line character budget; missing criteria/positions fall back to
  the existing heuristic. Records criteria, edge counts, source lines, missing
  positions and omitted lines. This is bounded evidence, not a complete slice
  when the budget drops lines; character budget is not exact token budget.
- `BOUNDED_OUTPUT_CONTRACT`: HYPOTHESIS, JSON ACTION, short REASONING; same
  150-token API ceiling. Required fields/valid actions checked, finish reason
  saved. Incomplete/Uncertain responses yield `prediction=null`, not Benign.
  No automatic paid retry for truncation. Complete fields with a `length` finish
  retain the verdict but the truncation is still recorded.
- `EVIDENCE_EXPANSION`: explicit action + specific evidence gap, including exit
  or free-path requests, may bypass first-step type confirmation. Expand on the
  full CPG, deduplicate against accumulated evidence, rank new paths, update
  state before the next call. No new evidence -> no second paid call. Incremental
  context shows up to five paths, each at most 100 characters; omitted paths
  remain marked. Expansion flag alone may increase cost, so it is not promoted.

Rejected GAT compression/ranking and graph security net remain off. The existing
source-based zero-token verifier is preserved and accurately named in receipts.
`no_safety_net` removes its outer verification. Do not call it a PDG verifier.

## Local and real-API checks

105 local regression tests passed, including full-CPG expansion, duplicate-only
early stopping, wrapped-line mapping, no fabricated CFG control dependencies,
field truncation/uncertainty, entry delegation and independent removal switches.

First smoke: `output/pipeline_wiring_smoke_20261006/`, 3 graph-size-quantile
samples, 5 profiles, 16 actual calls. These are public development graphs already
exposed to GAT training. They are **not** a paper/generalization benchmark. Labels
were not used for selection and no accuracy/F1 was computed.

| Profile | Calls | Total tokens | Length finishes | Incomplete fields |
| --- | ---: | ---: | ---: | ---: |
| Control | 3 | 2791 | 3 | 3 |
| Slice only | 3 | 2653 | 1 | 1 |
| Output contract only | 3 | 2581 | 0 | 0 |
| Expansion only | 4 | 3822 | 3 | 3 |
| Combined | 3 | 2467 | 0 | 0 |

Real slice receipts: medium graph traversed 16 nodes, 10 CDG and 12 REACHING_DEF
edges; large graph traversed 485 nodes, with 161 source lines omitted by budget.
One criterion-free sample used the recorded fallback. Expansion-only restored
18 new paths in a real call. All receipts show learned scoring and graph net off.

The first combined call requested an exit path with wording not recognized by
the gap detector. Fixed the detector and added a regression. Recheck:
`output/pipeline_wiring_smoke_r2_20261006/`, 3 actual calls, 2458 total tokens,
zero truncations/incomplete fields. All three replies requested Stop; no forced
expansion. The medium sample changed from Memory Leak to Benign between calls.
This instability and tiny sample size prohibit an accuracy/F1 or stable savings
claim. Recheck manifest includes code hashes; first smoke remains historical.

## Quality release gate (still outstanding)

Freeze a label-blind, group-disjoint development evaluation batch not used in
training/calibration; run baseline, each single addition and the combined profile
on exactly the same sources/model/budget, then remove slice/contract/expansion
one at a time from the combined profile. Do not present `no_slice` as informative
when the full profile already has slicing disabled. Keep locked test untouched.
Save actual prompts, answers, model receipts, failure/uncertainty coverage and
token totals; report paired group-bootstrap confidence intervals and seed/repeat
sensitivity. Tune no thresholds on that evaluation batch.

Metrics now additionally expose `coverage`, `accuracy_all` and
`f1_conservative` (abstentions count as FN on positives and FP on negatives).
Conditional legacy F1/Accuracy remain available, but cannot be used alone to
declare gains by dropping uncertain examples. Ablation tables use the conservative
F1 and full-denominator Accuracy; precision/recall remain conditional and labelled.
Only a repeatable, disjoint quality gain justifies promoting any candidate.
