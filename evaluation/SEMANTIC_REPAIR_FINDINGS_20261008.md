# Common repairs / single SRC candidate: completed development confirmation

Date: 2026-10-08. This is not a locked final-test result or a submission claim.
See `SEMANTIC_REPAIR_PROTOCOL_20261008.md` for the predeclared protocol and
workspace-root `修复与独立验证执行记录-20261008.md` for the Chinese handoff.

## Evidence and decision

All 172 local mocked regressions pass. Common production repairs and historical
metric corrections are separate from the one candidate's measured effect.
Candidate `SOURCE_SLICE_ASSIGNMENT_FIX` retains assignment/inc/dec/pointer-write
SRC evidence within the existing character budget; all other candidate switches
remain disabled. No formal semantic-preservation or exact token-budget claim.

60 new development groups, seed20261011, selected without label balancing after
excluding570 recorded exposed groups. Labels32/28. Two preparation errors retained
in each arm/repeat. Selection, shadow and code snapshots frozen before calls.

| Arm/repeat | F1 | Accuracy | MCC | Returned total tokens |
|---|---:|---:|---:|---:|
| control/r1 | .352941 | .450000 | -.081393 | 52505 |
| assignment_evidence/r1 | .301887 | .383333 | -.224133 | 53423 |
| control/r2 | .392857 | .433333 | -.122748 | 53360 |
| assignment_evidence/r2 | .482759 | .500000 | .008989 | 53447 |

Denominator60 in every row; failures/abstentions conservatively penalized.
Always-positive F1 .695652 / Accuracy .533333 exceeds all arms. Primary paired
F1 delta -.051054 (95% group interval[-.231373,+.129630]); accuracy delta -.066667
([- .183333,+.050000]). Intervals cross zero: neither robust gain nor statistically
established harm. Second repeat is sensitivity, not a replacement primary result.
Tokens increase1.748%/0.163%. No demonstrated quality/cost advantage.

240 scheduled results,235 actual calls, all successful with known usage;212735
reported tokens. Eight preparation-error rows and two uncertainty rows are retained.
Requested deepseek-chat; all235 responses report deepseek-flash.224/235 finish by
length under the frozen150-output-token ceiling: severe truncation limits reasoning
and tool-loop conclusions. No rerun, budget adjustment or favorable-repeat selection.
An intermediate progress update misread an incomplete receipt as a failed call;
the final complete receipt audit establishes zero failed invocations.

Each repeat compares58 valid first inputs:15 changed SRC and0 non-SRC changes.
Unchanged inputs produce6/5 arm-pair prediction disagreements; each arm changes11
predictions between repeats. Provider variation therefore limits attribution.
Audit recomputes metrics, verifies receipts/inputs/code hashes and makes0 API calls.
Absence of unrecorded historical exposure cannot be proven. Reported tokens are
service usage receipts, not an independent financial bill.

Only the documented-input-change gate passes. Candidate stays OFF. Separate
validation, locked final test, and actual paper submission were not performed.
Locked-test manifest unchanged, never evaluated or sent. No remaining running batch.
Scientific gates must not be bypassed merely to label the workflow complete.

## Reproducibility

- `output/devign_assignment_eval60_20261008/report.json`: original result summary.
- `output/devign_assignment_eval60_20261008/assignment_audit.json`: independent audit.
- Same directory: `manifest.json`, `code_snapshot`, `results.jsonl`, `api_receipts.jsonl`.
- `output/devign_assignment_shadow60_20261008`: label-free input-change check.
- `output/research_repairs_20261008/history.json`: immutable-source historical recomputation.

Next work can diagnose frozen truncation/tool execution/error patterns without
retuning this batch. A genuinely new hypothesis requires a new protocol and new
unexposed development groups; final independent data must remain locked.
