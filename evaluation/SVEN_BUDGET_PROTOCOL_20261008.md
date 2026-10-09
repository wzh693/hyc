# SVEN output-budget mechanism replay — 2026-10-08

Registered before fresh calls. Human explicitly authorized all254 public local
SVEN slices, graph paths and reasoning contexts to https://api.deepseek.com/v1,
requested deepseek-chat,150 versus512 output tokens, two repeats each,1016 planned
results, at most2 steps and3 attempts/step. Record actual returned model. No other
real batches, training, final-test payload or paper submission authorized.

## Scope and hypothesis

This is a previously exposed development benchmark replay, NOT held-out validation.
Use all254 rows, including conflicting labels, duplicate slices and failures.
Report primary row metrics and36 source/family-union bootstrap units; repeats
are not new independent samples. No replacement, best-of-run or CWE routing.

History motivates ONE hypothesis:150 output tokens often truncate the specified
HYPOTHESIS/REASONING/ACTION response, limiting explicit action availability.
Only request max_tokens changes150->512 through an audited experiment client.
No production default changes, prompt rewrite, assignment evidence, backward
slice, enhanced expansion, ACTION-first, output contract, learned/GAT or graph
verifier activation. Both arms share the corrected20261008 production version,
type coverage, legacy routing, max2 steps and conservative source verifier.
Graph/input budget4096 unchanged; this experiment is not a cost-neutral claim.

Freeze source/graph fingerprints, dataset, all prediction/evaluator hashes,
effective configuration, local shadow prompts and code snapshot before calls.
First request for paired arms must match exactly except max_tokens; same-arm
repeat first requests must match exactly. Later requests may differ as a result
of different returned answers; audit rather than force them equal.

## Analysis and decision

Repeat1 primary; repeat2 sensitivity. Full-scheduled Accuracy and conservative
positive F1, MCC, balanced accuracy, constant baselines, confusion counts,
coverage/error/uncertainty, per-CWE metrics all retain every scheduled row.
Family-union paired bootstrap2000 draws seed20261008; no multiplicity-adjusted
significance claims. Report all returned usage, failed/unknown-usage calls,
length finishes, complete ACTION JSON, explicit planner actions, actual execution
events, reasoning steps/stop reasons and same-input prediction variability.

Mechanism support requires lower length-finish rate and higher complete-action
rate in both repeats. Quality support requires nonnegative F1/Accuracy deltas
in BOTH repeats and positive primary lower CI on at least one metric with the
other >=0. Also require candidate to exceed always-positive Accuracy and have
positive MCC in both repeats. These gates are descriptive preregistered filters,
not permission for promotion; any future unexposed confirmation needs a new
protocol and explicit external authorization. Increased costs reported without
retroactively relaxing quality gates. Do not rerun if a gate fails.

Original SVEN is a secure/adversarial code-generation research resource; this
local254-row sliced classification derivative is not claimed identical to all
upstream SVEN evaluation data. Primary upstream references:
https://github.com/eth-sri/sven and https://github.com/qcri/llmxcpg.

## Planned outputs

`output/sven_budget_preflight_20261008`: zero-call validation and shadow.
`output/sven_budget_eval_20261008`: manifest/code snapshot, append-only result/API
receipts, logs, full report and offline audit. Existing SVEN outputs unchanged.
