# Observed-STATE independent confirmation — execution record

## Authorized preparation (before real calls)

User explicitly allowed real LLM use after default-OFF implementation. Protocol:
STATE_CONFIRMATION_PROTOCOL_20261007.md. Sixty new Devign development groups,
seed20261010, one representative/group, excluding510 recorded groups (540 rows
including repeated exclusion records). Selection froze before labels were read:
SHA256 `50b393868d7011d0b34393d47812db221ff6e038436fb6317a229b4a99a98124`.
Labels after selection:38 vulnerable,22 benign; no balancing/reselection.
Preparation59 valid,1 failure sample_004756 (Joern no function METHOD).
All scheduled60 count; no failure replacement.

Inputs: output/devign_state_confirmation60_20261007. Three profiles twice:
control, state_disabled, observed_state;360 scheduled rows. Source verifier and
legacy routing identical; other rejected candidates remain OFF. API receipts
will record actual usage; no equivalence claim between characters and tokens.
Candidate remains OFF pending independent evidence, with no automatic promotion.

Locked-test SHA256 checked unchanged before calls:
`758d04f55d919b322f7731e082fa58a184c9300e902ba47654ae0590eabc6d08`.

## Completed offline checks and frozen inputs

155 local regressions pass. Label-free production shadow:
output/devign_state_shadow60_20261007,60 scheduled/59 checked/1 preparation error,
zero real API calls, zero non-STATE changes and character/UTF-8 payload growth.
Source observations1604;423 whole units serialized initially. Full-graph replay
adds318 events,317 lacking reliable source location. This is a conservative,
incomplete may-event renderer, not a proven path-sensitive state solver.
No relation between these coverage counts and classification quality is claimed.

Preflight passes: output/devign_state_preflight60_20261007. Model alias
deepseek-chat, endpoint https://api.deepseek.com/v1,360 planned results, all per-arm
flags/ablation/source/CPG/code hashes frozen. Verified47-file snapshot:
output/devign_state_confirmation_code_snapshot_20261007. Previous candidate
47-file snapshot also preserved and hash-verified at
output/observed_state_candidate_code_snapshot_20261007 (archived runner restored
from prior snapshot plus exact known patch, verified against prior shadow hash).

## External-call review rejection — no execution

Real launch was rejected BEFORE process creation. Review accepted general real-LLM
permission but required explicit human authorization for these specific source,
graph-path and reasoning-context payloads to this specific external DeepSeek
destination. No workaround or indirect execution attempted. Real eval directory
and API receipts do not exist; actual external model calls remain0. No F1/Accuracy
or provider-token results are available. Candidate remains default OFF.

Required next authorization: send the60 selected Devign development groups'
source evidence, graph paths and reasoning context to https://api.deepseek.com/v1
(deepseek-chat), three frozen profiles each twice (360 planned results, recorded
bounded retries). Data leaves the machine for third-party processing; credentials
are used only for normal authentication, never added to prompts/logs. Locked test
is not sent. Do not rerun until explicit trusted user permission resolves this.

## 2026-10-08 — explicit authorization and launch

User explicitly agreed to the immediately preceding concrete60-sample payload /
DeepSeek destination / three-profile two-repeat consent request and requested a
next-chat handoff file after completion. Frozen47 prediction files still match;
locked-test hash unchanged. Same frozen input/shadow/preflight/output names kept
for provenance; no selection/rule change and no model/threshold substitution.
Real evaluation process launched successfully. Results pending at launch;
historical rejection above remains an accurate chronological record, not the
current permission status. Do not run a second overlapping batch.

## 2026-10-08 — completed: no promotion

All360 scheduled rows finished:358 successful API calls,0 failed invocations,
6 preparation-error rows (same sample_004756 in each arm/repeat),0 uncertainty.
First repeat is primary; both repeats reported without selection. Actual returned
model is deepseek-flash on all358 calls, requested alias deepseek-chat; exact
provider weights/version unavailable. Current47 frozen prediction files and
their archived snapshot hash-match. Locked clone-v2 test hash remains unchanged.
All158 local regressions pass; regression inference is mocked, not real API use.

| Profile/repeat | F1 | Accuracy | TP/TN/FP/FN incl. errors | Returned tokens / scheduled sample |
| --- | ---: | ---: | --- | ---: |
| control/r1 | .491803 | .483333 | 15/14/8/23 | 898.733 |
| state_disabled/r1 | .508475 | .516667 | 15/16/6/23 | 842.933 |
| observed_state/r1 | .508475 | .516667 | 15/16/6/23 | 908.350 |
| control/r2 | .533333 | .533333 | 16/16/6/22 | 899.500 |
| state_disabled/r2 | .363636 | .416667 | 10/15/7/28 | 831.200 |
| observed_state/r2 | .548387 | .533333 | 17/15/7/21 | 892.417 |

Denominator60 every row; preparation errors counted as classification errors,
not silently excluded. Always-positive reference F1 .775510 /Accuracy .633333
on the38/22 class distribution exceeds all arms on both metrics. None reaches
the user's F1/Accuracy >.60 target; these development results are not a publishable
final benchmark. Different groups from the previous field-order study preclude
interpreting lower absolute control scores as a code-regression causal effect.

Primary observed-control delta F1+.016671, group-bootstrap95% interval
[-.149829,.184557]; Accuracy+.033333 interval[-.083333,.150000]. Primary
observed-disabled point deltas0/0; intervals F1[-.124470,.121709], Accuracy
[-.083333,.083333]. All cross0; exploratory marginal, not multiplicity-adjusted.
Second-repeat observed-control F1+.015054 /Accuracy0 does not demonstrate
stable simultaneous quality improvement. Disabling STATE lowers cost but repeat2
quality collapses; neither candidate nor no_state is promoted.

### Actual input/cost and output audit

Each repeat59 real first-request triplets differ only in STATE; system, SRC,
PATHS, retrieval and request parameters identical. Each arm's59 repeated first
requests are identical, yet9/12/11 control/disabled/observed predictions disagree
between repeats. This documents provider sensitivity, not causal module benefit.

Character/UTF-8 caps pass but true provider-token no-growth FAILS: candidate first
prompt tokens increase on44/59 samples and total+467 each repeat versus control.
Disabled first prompts total-3199 each repeat. All-call returned usage candidate
54501 vs53924 (+1.070%) in repeat1,53545 vs53970 (-.787%) in repeat2; aggregation
mixes output and second-round-call variation and is not per-sample compression.
No price/billing estimate. Total successful calls354 initial +4 second-round.

All358 successful answers have nonempty HYPOTHESIS;330 finish by length.
Complete ACTION JSON calls: control4/60 and5/60, disabled8/60 and6/59,
observed2/60 and4/59. Format remains a bottleneck but the independently failed
ACTION-first/short-contract candidates must not be reactivated on this evidence.
Fixed-answer outer-source-verifier removal: flips control2/1, disabled1/0,
observed0/0; this is offline replay, not a full independent safety-net ablation.
Source-verifier quality gains are small; do not claim the Method draft's universal
post-verification novelty or causal recall improvement from these data.

Added evaluation/audit_state_confirmation.py and3 audit tests; zero model calls,
no prediction changes. Audit verifies360 unique scheduled keys, trace/receipt
identity, full-denominator metrics, frozen hashes and actual STATE-only changes.
Raw artifacts remain output/devign_state_eval60_20261007/{manifest.json,
results.jsonl,api_receipts.jsonl,report.json,analysis.json,state_audit.json,
execution.log}. Prediction snapshot: output/devign_state_confirmation_code_snapshot_20261007.

Next work should be label-free evidence/provenance and real-token-budget design,
then preregistered independent groups. Do not tune thresholds/prompts on this
now-exposed60, silently drop failed examples, or rerun to select favorable scores.
Default OBSERVED_STATE_CANDIDATE remains OFF. Completed next-chat handoff:
../下个对话交接-20261008.md (relative to repository root).
