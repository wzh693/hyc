# Observed STATE candidate — 2026-10-07

## Status

Implemented first-stage conservative correction, default OFF:
`OBSERVED_STATE_CANDIDATE=0`. No `.env` changed, real model call made, prediction
threshold tuned, or benchmark label used. Failed GAT/graph-net/field-order/short
contract candidates remain inactive. No claim of F1/Accuracy improvement.

This is an observation renderer, **not** a repaired path-sensitive state solver.
Rather than return false safety proofs or merge incompatible lifetimes, it makes
execution-order/lifetime/guard/alias reasoning explicitly unknown. All four
type-specific predicate APIs return `None` (unknown) in the candidate, not benign.
Explanation generation recognizes the candidate before consulting these APIs.
Legacy callers continue to receive the unmodified legacy class when OFF.

## Implementation

`planning/observed_state.py` masks comments/literals while preserving offsets,
extracts simple allocation assignment targets (not allocation size), maintains
case-sensitive names, and reads balanced API arguments. Scanf destinations start
after format (`scanf`) or input/stream plus format (`sscanf`/`fscanf`); multiple
destination arguments are observed. Unsupported expressions are omitted rather
than guessed. Pointer declarations are not claimed to be runtime dereferences;
ambiguous unary uses are intentionally undercovered.

Events are `alloc-call`, `free-call`, `input-call`, `null-test`, `copy`, `assign`,
or `use`, each with source offset/location and unresolved scope. Allocation calls
do not establish success; null tests do not establish protection; copies do not
prove object alias propagation. `MAY;unordered:` serialization contains no
chronological arrows. Reallocation remains a lexical occurrence, not an inferred
new live allocation epoch. No new final-prediction flip rule is introduced.

Source occurrences deduplicate by offset/type/variable/detail. A unique exact
graph-code fragment reconciles to that offset; otherwise graph observations have
node-local identity and unknown source line (`G`). Repeated node observations
deduplicate; different unresolved node/source identities are not claimed to be
distinct runtime operations. METHOD/BLOCK nodes are excluded for `node_type`,
`label`, or `_label`. No fuzzy source mapping or graph line-offset assumption.

All source-scanning entrypoints share `create_program_state`; the reasoning loop
and initial context still maintain separate instances, now using the same
candidate extractor. Path updates select the conservative extractor only when
the candidate is instantiated. Initial context uses whole-event render(150),
incremental dump render(350), compact context render(400). Candidate source-based
renderers cap characters and UTF-8 bytes to the legacy serialized reference
length as well as the existing section limit; no partial event is emitted.
This may omit evidence, especially with small caps; it is not a completeness
guarantee. No promotion and no provider-token guarantee.

Standard development preparation/evaluation and SVEN launch settings explicitly
pin the candidate OFF to prevent an inherited environment from contaminating a
control run. No real evaluation arm for this candidate is launched yet.

## Offline evidence

`output/observed_state_shadow_20261007/report_final.json`: fifteen synthetic
paired actual first prompts; all fifteen OFF prompts exactly match the saved
pre-implementation audit. Only STATE changes on ON. Every pair respects the
legacy character/UTF-8-byte limits; combined first-prompt characters 3840 ->
3280. These totals are synthetic only, not provider tokens or a cost estimate.
Forty-seven prediction files are hashed in that artifact. Earlier shadow report
preserved. Shadow code never constructs an API client.

Local tests cover non-code masking/locations, target/case correctness, balanced
and multiple scanf arguments, exact-node reconciliation, repeated/distinct events,
container-node exclusion, all prior synthetic probes returning unknown instead
of unsafe lifecycle certificates, complete-unit budgets, factory defaults,
prompt isolation, uncertainty-aware explanations, and the reasoning entrypoint
with a mocked answer. Printed model-labelled regression traces are mocks.

Full local regression: `python -m unittest discover -s evaluation -p 'test*.py'`
completed with **150 tests passing**, including twelve new candidate tests.

Historical action-order frozen snapshot remains intact: all 46 manifest files
hash-match the preserved snapshot. Current production source intentionally differs
because this candidate has now been implemented; old audits must use their
appropriate archived code, not treat the current tree as unchanged.

## Remaining work before quality evaluation

1. Shadow on cached CPG/source without labels or API calls to inspect unmapped
   graph observations, event omission, repeated scopes/macros/unevaluated code,
   and serialized coverage. Character/byte caps alone do not enforce model tokens.
2. To recover definite lifecycle facts, add AST/CDG/DFG-backed scoped alias/object
   and allocation-epoch analysis with feasibility/guard evidence; do not patch
   bool patterns with benchmark-specific rules. Unsupported cases stay unknown.
3. Reserve new unexposed development groups before observing labels, freeze code
   and manifest, then preregister standard / STATE-disabled / candidate with
   identical evidence, model/budgets and two repeats. Account for all failures,
   provider variance, prompt/completion usage, always-positive baseline and paired
   uncertainty. Locked test stays untouched. Promote only if independent results
   support quality/cost claims; fixes alone do not prove improved metrics.
