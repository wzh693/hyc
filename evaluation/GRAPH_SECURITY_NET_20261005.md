# Graph safety-net correctness candidate

`GRAPH_SECURITY_NET=1` selects the experimental verifier in the shared HGL
pipeline. Default is 0: historical standard behavior is unchanged. The flag is
included in prediction fingerprints and SVEN configuration receipts.

Candidate semantics (no model calls, no label-derived threshold changes):

- Use the full CPG, not compressed CFG fragments. Sink must belong to retrieved
  Top-K paths. Only CALL/RETURN operation nodes are matched.
- Free/use and repeated release require directed CFG reachability; paths through
  reassignment of the same expression are blocked.
- Command taint supports only read/recv buffers and getenv-assignment to the same
  simple argument expression, with both CFG and data-dependency reachability.
- API counts alone cannot flip. Missing edges/evidence cause abstention.
- av_freep is excluded because it clears its pointer. Aliases are unsupported.
- Positive main predictions are never reversed. Threshold remains 4.

This is structural reachability, NOT symbolic feasibility or proof of a
vulnerability. Infeasible correlated branches, preprocessor alternatives,
shadowing, aliasing, implicit pointer writes and parser/export limitations remain.
Conservatism can reduce recall. Do not call synthetic correctness tests an F1 gain.

Before adoption: replay old and candidate verifiers on the *same* stored main
predictions and cached graphs from development-only data; report recovered TP,
added FP, lost TP, removed FP, graph-coverage/abstention counts and grouped
uncertainty. No new model calls are needed for verifier-only replay. Do not tune
thresholds or rules on validation/locked test. Clean-protocol near-clone audit is
still pending. GAT activation and context-completeness changes must be separate
experiments, not bundled with this verifier.

## Fresh authorized LLM check

30 previously used Devign development functions, two repeats, 60 shared fresh
calls to the configured DeepSeek endpoint. Both sides use the expanded type-list
prompt, frozen identical first-pass inputs, 150 output tokens and threshold 4.
No adaptive second pass. Results are not comparable to a full adaptive run.

| Repeat | Old F1 | Graph F1 | Old Acc | Graph Acc |
| --- | --- | --- | --- | --- |
| 0 | 0.4828 | 0.3846 | 0.5000 | 0.4667 |
| 1 | 0.4828 | 0.4286 | 0.5000 | 0.4667 |

Zero call errors; 59,869 reported total tokens (997.82 per shared call). Provider
receipts say deepseek-flash; configured model is deepseek-chat. 58/60 responses
hit the output cap, which remains a separately controlled limitation.

Across receipts, graph candidate removes one false positive and loses three true
positives restored by the old verifier; zero new flips. These are 30 independent
source functions, not 60 samples. Pooled F1 0.4828 -> 0.4074; Acc 0.5000 ->
0.4667. Source-cluster fixed-receipt delta-F1 CI [-0.2078, +0.0123]. No evidence
of an improvement. Keep the graph candidate OFF, without threshold retuning.

Difference indices: 11346 (positive), 22923 (negative), 25952 (positive).
Their full cached graphs have 471/603/670 CFG edges, respectively; allowing all
nodes as anchors still produces zero candidate signal. Thus missing CFG edges
or Top-K anchoring alone is not an explanation for those differences. Source
inspection shows early-return release branches: the old textual double-free
heuristic cannot be interpreted as proof of a double-free even where its binary
prediction happens to match the function label. The actual vulnerability type
needs a separate evidence audit; do not restore invalid rules just to fit labels.

Artifacts: `sven_eval/external_type_check/graph_net_fresh_20261005_run2/`
contains protocol, complete receipts, report and clustered summary. The first
attempt stopped during local preparation due to a module import shadowing
issue; no model calls occurred on that attempt. Locked test was untouched.
