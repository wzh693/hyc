# Active development foundation

The user approved returning to the historical type-coverage candidate via an
isolated reconstruction. The active editable prediction source is now:

`development/type_coverage_reconstructed_20261008/src/`

Read `development/type_coverage_reconstructed_20261008/README.md` before changing
prediction logic. Do not silently edit the repaired prediction modules in the
repository root when asked to improve the active baseline. Root evaluation tools
may be extended to support isolated source roots.

- Preserve the frozen `baselines/type_coverage_reconstructed_20261008/src/`, its
  `baseline.json`, and `preserved_repaired_src/` as references.
- The reconstructed source is based on the verified 2026-10-06 snapshot, not an
  exact recovery of the source that produced historical SVEN F1 61.15%.
- Historical scores must not be assigned to reconstructed/candidate code.
- Default verification is offline. Saved-answer replay is not a fresh LLM test.
  No new paid/external model batch is authorized by the reconstruction approval.
  Separately, the user approved the recommended 30-row SVEN/two-repeat real
  DeepSeek smoke (60 planned results) on 2026-10-08. This permission is limited
  to that batch and does not authorize automatic reruns or a full 508-result run.
  That batch is now COMPLETE at output/reconstructed_llm60_eval_20261008;
  its independent audit passed. The authorization is consumed, not recurring.
  On2026-10-08 the human separately approved full local254-row SVEN control and
  COMPLETE_SOURCE_SLICE candidate twice each:1016 scheduled results, to the same
  DeepSeek endpoint, max2 steps/3 attempts per step. Only this batch is authorized;
  no extra variants, automatic reruns, locked Devign test or GitHub publication.
  See evaluation/SVEN_COMPLETE_SRC_PROTOCOL_20261008.md. Candidate remains OFF
  by default and the frozen foundation/released package must not be overwritten.
  That full batch is now COMPLETE at output/sven_complete_src_eval_20261008;
  two offline audits passed but the candidate's quality gates failed. Permission
  is consumed. Keep COMPLETE_SOURCE_SLICE OFF; do not turn it on by CWE metadata,
  repeat the batch or claim complete source improved CWE-125. Read the findings
  before selecting another separately frozen/authorized candidate.
- Keep full scheduled denominators and all failures/abstentions in metrics.
- SVEN is development-exposed. Do not tune on or send the locked Devign test.
- Make one documented candidate change at a time; record its source hashes and
  changed inputs before any separately authorized real-model evaluation.

The root repaired checkout remains intact for comparison; normal root entry
points still run that checkout, not the isolated baseline. Use the explicit
isolated launcher described in the development README.

On 2026-10-09 the user reselected the foundation and graph-guided mainline.
Editable src now matches all47 frozen source hashes; COMPLETE_SOURCE_SLICE has
been removed, not merely disabled. Preserve its tested code/tooling snapshots.
Read evaluation/GRAPH_GUIDED_MAINLINE_20261009.md before the next candidate.
First audit graph/path/source evidence provenance; no prediction change or new
paid evaluation is authorized by this source restoration alone.

Separate human approval on 2026-10-09 authorizes ONE isolated graph-anchored
read-dependency SRC candidate and a frozen30-row SVEN control/candidate smoke,
two repeats each,120 planned results to https://api.deepseek.com/v1, requested
deepseek-chat/record actual model, cap150 output/max2 steps/3 attempts per step.
Only SRC evidence selection may change; do not modify default foundation,
compression/ranking/parser/net or root repaired modules. Implement and freeze
candidate before calls; preserve failures and baseline, no automatic promotion,
reruns, full254 expansion, locked Devign or GitHub upload. Authorization is limited
to this one batch; update status upon completion.

That120-result batch is now COMPLETE at output/graph_read_slice_llm120_20261009.
120 actual successful calls, audit passed, all quality gates failed; authorization
is consumed. Default foundation remains selected; isolated candidate stays OFF.
Read evaluation/GRAPH_READ_SLICE_LLM_FINDINGS_20261009.md. Only5/30 source inputs
changed (1 CWE-125),25 fell back. R1 net improvement arose only in unchanged-input
pairs, so do not claim read-slice benefit, route by CWE or rerun automatically.

Standing user policy (2026-10-09, after the completed120-result batch): every
future model-quality evaluation must cover the entire declared dataset/split,
including full-scope offline request preflight. Current local SVEN is254 rows;
do not use30-row smoke runs as future quality evaluations. Read
evaluation/EVALUATION_SCOPE_POLICY.md. Historical sampled protocols, runners,
snapshots and results stay immutable and explicitly sampled. Synthetic unit
tests remain engineering checks, not dataset-quality evaluations. This policy
does not authorize new paid API calls, locked Devign access or GitHub upload;
obtain batch-specific external-scope/cost approval before new model calls.

User on2026-10-09 authorizes resolving path selection/display offline. One new
isolated candidate lives in development/graph_display_candidate_20261009/src;
only retrieval/retrieve_topk.py changes. It selects existing paths using complete
read nodes visible under unchanged260-character DEP serialization, optimizes two
guaranteed display slots, and retains the legacy tail. Read
evaluation/GRAPH_DISPLAY_PROTOCOL_20261009.md. Full254-row paired offline request
preflight only; no new paid API authorization or activation. Default foundation,
old candidates and all prior frozen artifacts must remain intact.

That offline full254 paired preflight is COMPLETE; v1 and v2 are both retained,
with code/tool snapshots. Current candidate frozen v2 has10 isolated policy tests
and214 top-level regression tests passed. Independent v2 verification passes508
mock requests,106 DEP-only input changes and preserved graph/candidate/non-DEP
fields. DEP lexical reads33->280,updates24->46,conditions51->95 are NOT model
quality scores or certified capacity/guard facts. Read
evaluation/GRAPH_DISPLAY_FINDINGS_20261009.md. Keep current candidate frozen/OFF
as default, do not mix SRC/decoder/prompt fixes into it or call models without
new full254 batch-specific approval. Default foundation still matches47 hashes.

New explicit human approval2026-10-09 authorizes ONE full254 SVEN real-model
control/display-v2 comparison,two repeats each,1016 planned results to
https://api.deepseek.com/v1,requested deepseek-chat/record actual model,150-output,
max2 steps/3 attempts per step,SDK retries0. User accepts this external scope/API
fees. Read evaluation/GRAPH_DISPLAY_LLM_PROTOCOL_20261009.md. Candidate prediction
source stays frozen; freeze new tools and full runtime preflight before calls.
Keep all failures,do not auto-rerun/activate/upload or send locked Devign. This
approval is batch-specific; mark consumed on completion.

That real full254 batch is COMPLETE at output/graph_display_llm1016_20261009.
1016 planned results,1019 successful actual calls (three second steps),zero
failures/unknown usage/abstentions,all actual deepseek-flash,894462 reported
tokens,972 length finishes. Independent audit passes1016 first requests,508
DEP-only pairs,47+47 source snapshots/tooling/traces/usage/full denominators.
Functional gate passes but four of five quality gates fail; candidate stays OFF.
Global control F1 .593407/.590406 vs display .597122/.593407,Accuracy .562992/
.562992 vs .559055/.562992; CWE125 Accuracy .648352/.593407 vs .560440/.571429.
Do not promote based on tiny global F1 or CWE416 subgroup gain,route by CWE,
discard unchanged-input rows or reuse this consumed authorization. Read
evaluation/GRAPH_DISPLAY_LLM_FINDINGS_20261009.md. Default foundation preserved;
next work requires a separately documented candidate and new full-batch approval.

User subsequently approved offline whole-node/length-update work. New isolated
candidate development/graph_evidence_cards_v2_candidate_20261009/src preserves
foundation ranking/compression/SRC/STATE/budgets and only changes DEP packing
(typed_paths.py delegation + new evidence_cards.py;48 files). Full254 paired
offline508 actual mock requests and independent graph/witness audit pass; v1 is
also retained, not overwritten. Read GRAPH_EVIDENCE_CARDS_FINDINGS_20261009.md.
AST ownership restores a complete assignment only for exact unique simple LHS
in incoming dependence ancestry; AST is not dependency/dominance/capacity proof.
52 AST-bound update cards, lexical reads/updates/conditions33/24/51->56/87/95;
coverage is not quality,693 omission attempts and later unselected reads remain.

Separate explicit human approval2026-10-09 now authorizes ONE full254 control/
whole-evidence-v2 real-model batch, two repeats each,1016 planned results to
https://api.deepseek.com/v1, requested deepseek-chat/record actual model, cap150,
max2 steps/3 attempts per step, SDK retries0. User accepts this batch's fees.
Read evaluation/GRAPH_EVIDENCE_CARDS_LLM_PROTOCOL_20261009.md; freeze new tools
and pass1016 actual mock runtime requests first. Keep all failures, no auto-rerun,
activation/GitHub/locked Devign; mark authorization consumed upon completion.

That whole-evidence-v2 batch is COMPLETE at output/graph_evidence_cards_llm1016_20261009:
1016 results,1020 successful calls,zero errors/unknown usage/abstentions,actual
deepseek-flash,876224 reported tokens,974 length finishes. Independent audit
passes1016 first requests/508 DEP-only pairs/48+47 source snapshots/trace/usage.
Functional gate passes; only1/5 quality gates passes (CWE125 both improves),four
fail. CWE125 Accuracy control.659341/.637363 vs candidate.714286/.648352;
CWE190 control.542857/.514286 vs candidate.400000/.371429; overall second
Accuracy declines and family intervals cross0. Keep foundation/default unchanged,
candidateOFF; no CWE routing, rerun, locked Devign or GitHub. Authorization consumed.
Read evaluation/GRAPH_EVIDENCE_CARDS_LLM_FINDINGS_20261009.md before future work.

On 2026-10-10 the user explicitly requests an isolated converged three-stage
architecture experiment, accepting consideration of small quality loss for
simplicity (not automatic promotion or a measured noninferiority claim).
Local branch codex/converged-architecture-20261010 contains the standalone
development/converged_graph_candidate_20261010 prototype. Read its README.
Preserve all prior source and results. This is an architecture-level change,
not a single-component causal ablation. Existing GAT/MIL checkpoints may be used
for engineering diagnostics only; failed bag calibration must remain disclosed.
The graph risk net is shadow-only without a new bound calibration receipt.
Full local254 offline mock preflight is allowed; no new live API calls, model
training on locked data, promotion or GitHub upload is authorized by this request.

The new prototype's full254 paired offline preflight is COMPLETE at
output/converged_architecture_preflight_v2_20261010: 508 actual first mock requests,
zero runtime errors/external attempts/paid calls; 254 local GAT forwards. Read-only
graph/source audit passes358 displayed paths and1871 source-line occurrences.
15 new synthetic tests,227 existing regressions,5 portable checks passed separately.
Engineering pass does NOT mean live-quality readiness:19 rows have no criterion
even in the original graph,43 have empty displayed paths (including those19),144
hit candidate enumeration cap; net remains shadow and old GAT calibration failed.
The first preflight attempt is retained and INVALID due to tool/source drift.
Do not promote, fabricate Accuracy/F1 from mocks, or spend API fees before resolving
input readiness, defining new calibration and obtaining full-batch authorization.
