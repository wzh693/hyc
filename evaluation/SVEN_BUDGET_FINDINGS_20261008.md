# Full SVEN budget replay — completed2026-10-08

Protocol: `SVEN_BUDGET_PROTOCOL_20261008.md`. Human authorized254 public slices,
150/512 output-token arms twice,1016 scheduled results, bounded steps/retries.
Previously exposed development benchmark, not independent held-out confirmation.
Both arms share repaired production, identical evidence/prompt/settings. Only
experimental client max_tokens differs; production defaults/checkpoints untouched.

| Arm | F1 | Accuracy | MCC | Returned tokens | Abstentions |
|---|---:|---:|---:|---:|---:|
| control/r1 | .471042 | .460630 | -.079144 | 220603 | 9 |
| output512/r1 | .478764 | .468504 | -.063390 | 236103 | 8 |
| control/r2 | .522388 | .496063 | -.009405 | 220591 | 6 |
| output512/r2 | .507576 | .488189 | -.024666 | 236036 | 7 |

Full denominator254 each; no errors,30 abstentions across scheduled results.
Always-positive .673629 F1/.507874 accuracy beats every arm; all MCC negative.
Primary candidate-control F1+.007722,36-family paired95% interval
[-.031990,+.047890]; accuracy+.007874,[-.033333,+.052632]. Both cross0.
Second-repeat quality deltas negative. Tokens+7.03%/+7.00%, no cost saving.
Identical first requests across repeats still change42/25 predictions. No
favorable-repeat selection; repeat calls are not additional independent groups.

1020 successful actual calls,0 failed/unknown usage,913333 returned tokens.
All returned deepseek-flash, requested alias deepseek-chat; provider weights not
identified. Usage receipts are not independently audited currency billing.

Mechanism gate passes: control242/254 and240/254 length finishes vs0/256 both
candidate repeats; complete ACTION JSON12/254 and14/254 vs256/256 both.
Planner recognizes254/256 candidate actions each repeat: syntax completeness is
not action validity or successful evidence retrieval. Each candidate repeat has
only2 actual tool events, all returning paths.315 planner-recognized first tool
requests:311 early-stop suppressed (120+34 first,125+32 second),4 executed.
This identifies a routing bottleneck, not proof that granting requests improves
quality. Prior broad-routing pilot failed its development quality check.

All quality gates fail; no automatic promotion or change to production150 cap.
No independent validation/locked test/submission performed. No pending batch.
178 mocked regressions pass, including3 label-free characterization tests for
benign-gap/type-confirm stop and path-endpoint rather than requested-variable
anchors. These tests preserve frozen behavior, not a newly activated policy.

Audit verifies all1016 first requests against shadow,508 budget-only arm pairs,
508 identical repeat pairs, all metrics/tokens/traces/source/graph/code snapshots.
Audit uses0 API calls and changes0 predictions. Locked test manifest unchanged.
254 rows/129 positive/125 negative:74 exact sources,36 conservative union groups,
8 exact sources with contradictory labels (51 rows). Retain all primary rows.

Historical-input comparison: originalCPG bytes unchanged,54 compressed-node-count
changes, totals30990->32562;191 user/nonSRC context changes, only7 SRC changes,
system unchanged. Several common fixes/provider time differ: no causal attribution
of old-current quality differences or reuse of historical scores as current ones.
Label-blind SRC visibility proxies show missing candidate guards/exits but do not
establish absence from DEP/STATE or semantic causality. Learning/GAT/graph net off.

Artifacts: `output/sven_budget_eval_20261008/{report,audit}.json`, manifest,
code_snapshot, results/API JSONL; preflight/shadow, historical/visibility/version
audits kept separately. Chinese full handoff at workspace root
`SVEN重测与改进分析-20261008.md`.

Next: first validate requested-target/source-node binding and relevant new evidence
offline, then isolate routing with one candidate. Also investigate fixed-SRC graph
evidence ablation and branch/lifetime/type preservation. Require a new frozen
protocol and unexposed groups before fresh external confirmation. Do not tune
rules on these SVEN labels or enable rejected candidates to chase a headline F1.
