# STATE semantic audit — 2026-10-07

## Outcome and scope

Diagnostic only. No prediction implementation changes, benchmark labels, real
model calls, or model-token usage. Fifteen deliberately chosen synthetic probes:
four normal controls agree with local operation reasoning; eleven counterexamples
disagree. This is NOT a representative error rate, whole-function ground truth,
or evidence of a measured F1/Accuracy improvement/decline.

Artifacts: `output/state_semantics_audit_20261007/report_with_controls.json`
contains exact source, probe, expectation/rationale, observed histories, actual
first user prompt, path-update probe, second user prompt and five production-file
hashes. Initial eleven-case `report.json` preserved. Audit tool:
`python -m evaluation.audit_state_semantics --output <new-report.json>`; refuses
overwrite. No client is constructed. Audit integrity tests do not lock incorrect
legacy behavior into desired regression expectations.

## Reproduced findings

| Local operation | Current helper result | Semantic problem |
| --- | --- | --- |
| `if(c) free(p); else p->x=1;` | UAF true | Mutually exclusive branches concatenated |
| `if(c) free(p); else free(p);` | double-free true | One executed free counted twice |
| free, new malloc, guarded use | UAF true | Allocation lifetimes not separated |
| free, new malloc, free | double-free true | Distinct objects merged |
| free, use, free | UAF false | Last release masks earlier UAF |
| use, then null check | null-deref risk false | Later check treated as protection |
| `if(p==NULL) p->x=1;` | null-deref risk false | Check polarity ignored |
| comment containing free/use | UAF true | Comment scanned as executable text |
| string containing free/use | UAF true | String scanned as executable text |
| `q=p; free(p); q->x=1;` | UAF(q) false | No alias propagation |
| `sscanf(src,fmt,buf); buf[0]=1;` | taint(buf) false | Format argument marked instead of destination |

Separate path-only probe: `_update_program_state` on node `p = malloc(n);`
records `n: allocated(step1)`, not p. `_extract_var` captures allocation-call first
argument, and raw graph code is lowercased. Thus this fallback cannot reliably
attribute assignment targets or preserve case-sensitive C variable identity.
Source scanner suppresses path events if ANY same-type step0 event exists for the
variable: this is coarse event-type deduplication, not node/location identity.
Neither observation order nor step number proves feasible execution order.

## Actual consumers and limits of causal claims

1. `build_hierarchical_context` independently scans FULL original function code,
   including when SRC is sliced, and injects STATE truncated to 150 characters.
   The first user-prompt builder ignores its separate state_dump argument; STATE
   arrives through hierarchical context. The recorded exclusive-UAF prompt
   actually contains `freed(step0) -> dereferenced(step0)` without branch scope.
2. `constrained_reasoning_loop` separately scans the same full function, updates
   that tracker using retrieved paths after each answer, and later injects up to
   350 characters under PROGRAM STATE UPDATE. Separate trackers can diverge.
3. `build_compact_context` has another lexical STATE renderer; its truncation
   condition (>300) takes 400 characters, not a uniform 300-character bound.
4. UAF/double-free/null/taint helper booleans are consumed by type-specific
   explanation generation. They do not directly assign final predictions in
   the audited reasoning loop. Misleading STATE text could affect LLM decisions,
   but these synthetic findings do not measure that effect.
5. Dump omits event source locations/branch conditions. Even source-ordered
   lexical events are not runtime facts; `step0` is a reasoning annotation, not a
   program clock. Arbitrary prefix truncation can hide later evidence or split an
   event. No assertion that every full history is actually visible to the model.

## Recommended implementation sequence (not implemented here)

First isolate a default-OFF candidate: non-executable-text masking, correct event
target and case preservation, location-based dedup, complete-event serialization
within the existing budget. Render observations as conditional/may-events unless
graph evidence proves their ordering/guard relationship. Do not use a null
comparison alone as a safety certificate. Separate allocation epochs and alias
evidence; fail open to uncertainty for unresolved scopes/paths rather than assert
safe/vulnerable. AST/CDG/DFG are preferable to increasingly complicated regexes;
plain reverse CFG reachability does not establish domination.

Then synthetic tests for controls/counterexamples and label-free prompt-budget
shadow audit. Only after freezing the candidate, reserve fresh development
groups and compare standard, STATE disabled, and corrected STATE on identical
inputs/model/budgets with prespecified repeats and full failure accounting.
Existing exposed development results must not be reused as independent evidence;
locked test stays untouched. No per-CWE exceptions or outcome-driven rules.
No guarantee that correctness repairs improve F1/Accuracy.

All 46 files in the prior action-order manifest still match their frozen hashes
after this audit; baseline prediction behavior unchanged.

Validation: `python -m unittest discover -s evaluation -p 'test*.py'` completed
with 138 tests passing. Printed LLM-labelled traces in regression output are
mocked responses, not real model calls.
