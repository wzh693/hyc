# Full SVEN pipeline replay — frozen before fresh calls

Use every row of existing sven_eval/data/sven_test.json: 254 rows, 129 positive,
125 negative, 74 exact source strings. Previously exposed development benchmark;
NOT an independent final-test/generalization confirmation. No changes to the
reserved Devign validation/locked test. No rebalancing or sample replacement.

Two fresh complete passes: type-covered heuristic control and slice+enhanced
expansion candidate with old output policy. Same model alias, max150 output
tokens, graph budget4096, max2 reasoning rounds. No short-output policy, learned
scoring/GAT, graph safety net or arbitration. Existing source-based threshold4
verifier remains active and its flips separately counted. When expansion upgrade
is off, retain legacy routing. This is a candidate/control pipeline comparison,
not all-module ablation and not evidence that every paper-proposed module helps.

Validate exact deterministic SVEN wrapper identity and unique line-preserving
source mapping (signature may gain a brace, but no body line may change). Preserve
the original malformed slice for LLM input, never expose typedef/stub prefix as
original evidence. This adapter repair is applied equally to both profiles and
completed before fresh calls; the first zero-call preflight failed closed because
214 wrapped sources are not exact contiguous originals. Existing receipts are
retained. Validate cache source/tool
fingerprint, defined function body and graph hash before model creation. Fail
preflight rather than silently reuse stale/missing graphs. Validated Joern CPG
cache reused; no cold-cache runtime claim. Full pipeline parses CPG, compresses,
ranks TopK, constructs SRC/PATHS/STATE, calls LLM and runs source verifier.
Every result keeps graph size/reduction/module/trace receipts; raw API observer
keeps exact requests, answers, model, finish status, usage and observed retries.
No SDK hidden retries; 90s timeout, wrapper at most3 attempts.

All508 scheduled pairs must be represented exactly once. Failed and uncertain
samples remain in full-denominator accuracy/conservative F1, not discarded.
Token accounting uses every returned usage; missing usage is unknown cost.
Report primary whole-dataset F1/Accuracy, conditional precision/recall only when
clearly labelled, confusion counts, coverage, errors, actual tokens, truncations,
CWE metrics and trivial always-positive/negative baselines. Do not present
Devign60 scores as SVEN scores or select predictions between old/new runs.

Correlation audit: exact-source conflicts and consistent lowest-index unique
source supplement. Bootstrap candidate-control deltas over union groups linked
by same exact source OR same file_name source family, 2000draws seed20261006.
No conflicting-label deletion from primary rows. CIs reflect this replay only;
one run/profile does not isolate provider variability, and duplicate rows are
not independent samples. No auto-promotion or prompt/threshold/checkpoint tuning.
Save effective config and code hashes before calls and verify during/after run.

Preparation completion before calls: new inputs under
output/sven_full_pipeline_inputs_20261006. All254 valid; 239 validated graphs
copied and 15 regenerated after wrapper correction (including an additional
deterministic-wrapper difference beyond the14 mapping failures). Old sources/
graphs untouched. Macro multiline signatures now balance the complete signature;
incomplete signatures use a synthetic function and comment only signature lines,
preserving every original body line and original LLM input. This repairs syntax
for graph extraction, not reconstruction of missing program semantics. Mapping
accepts only unique, line-preserving whole-source transformations; ambiguity or
body alteration fails closed. 117 regressions pass before fresh model calls.
