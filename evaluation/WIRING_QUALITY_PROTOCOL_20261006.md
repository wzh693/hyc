# Frozen wiring quality evaluation — 2026-10-06

Predeclared before model calls; exploratory development evidence, not paper test.

Selection: 60 groups from the existing clone/commit/code-disjoint development
manifest, seed 20261007, one lowest-index representative per shuffled group,
without labels or replacement. Exclude the 330 currently recorded newly exposed
development groups, plus the original protocol's historical quarantine.
Selection manifest SHA256:
`676a576b4160cafef68ca37641e49f5c1528fa73cce8f64932822872cbdd1e3c`.
Graph preparation failure remains in all arms; no convenient replacement.
Validation/locked-test manifests, labels, predictions and sources are not used.

Inputs: `output/devign_wiring_quality60_20261006/`; existing Joern and existing
model endpoint, requested alias from config and actual returned model saved.
Control is the type-covered, heuristic HGL profile with the existing source-based
threshold-4 verifier, no arbitration, max two rounds and max 150 output tokens.
All learned compression/ranking and graph security net remain disabled.

First repeat: all eight combinations of dependence slicing, bounded output and
enhanced full-CPG gap routing. When enhanced routing is off, legacy routing is
retained: this measures the upgrade, not deletion of every legacy iteration.
The separately tested `HGL_ABL=no_expansion` disables every expansion; it is not
silently substituted for a factorial zero level.

Second repeat is predeclared for control, contract-only and combined over all
60 groups, regardless of first-repeat ranking. Total scheduled pairs: 660.
No favorable reruns; raw invocations/retries and failed calls recorded. SDK
hidden retries disabled, 90-second timeout, existing wrapper up to three observed
invocations. Actual calls may exceed 660 through bounded second rounds/retries.
The exact same model alias, inputs and budgets are held fixed across arms.

First-repeat full-denominator Accuracy and conservative F1 are primary:
uncertain/error positive -> FN, uncertain/error negative -> FP. Also report
coverage and uncertainty counts; do not show success-only metrics as gains.
Token accounting includes every returned usage record, even if later processing
fails. Failed invocations without usage remain explicitly unknown, not free.

Paired group bootstrap: 2000 draws, seed 20261007, source/commit/clone group as
unit. Report F1 and Accuracy delta intervals against control and three combined
removals; these are exploratory marginal intervals, not corrected significance
after eight-arm selection. Repeated calls are not new independent samples.
Second-repeat disagreement counts and metric deltas quantify provider variation.

Prediction modules and runner hashes frozen before the first call and checked
between arms. No prediction-code changes while evaluation is running. No
checkpoint/threshold selection or default activation based on this batch.
Any apparent candidate needs another disjoint confirmation before promotion;
paper-comparison claims require the previously reserved final protocol.

Preflight also repaired an integration defect: enhanced routing now requires a
complete explicit JSON ACTION, rather than planner keyword fallback on a
truncated answer. 109 regressions passed before this frozen experiment.

After frozen label-blind selection (before any model outcomes): all 60 graphs
prepared, with 36 positive/24 negative labels. Always-positive baseline is
Accuracy .60, F1 .75; always-negative baseline is Accuracy .40, F1 .00. Include
these trivial baselines, not only a >.60 score target. The analysis does not
rebalance this selected batch or treat repeated calls as additional sample size.
