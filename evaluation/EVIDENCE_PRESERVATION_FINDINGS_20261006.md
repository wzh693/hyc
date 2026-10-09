# Offline evidence preservation audit — 2026-10-06

254 existing SVEN pairs audited, zero API calls, zero prediction changes.
Defaults/checkpoints/thresholds/prompts unchanged. This is a post-hoc diagnostic,
not a new quality experiment or evidence that a proposed fix improves F1.

## Measurements

Categories are label-independent textual candidates (masked comments/strings):
if/for/while/switch, allocation/free, return/break/goto, array/member access.
They are NOT proven protective guards, exploit sites or relevant statements.
Use exact whole-line matching, leaving repeated baseline lines ambiguous; use
recorded source-line identities for nonfallback candidate slices. Each recorded
candidate slice is verified against the actual saved first model SRC. Replayed
graph compression sizes match the original full run for all254 pairs.

| Candidate category | Control SRC unambiguous lines | Candidate SRC identified lines | Lost relative to control | Gained |
| --- | ---: | ---: | ---: | ---: |
| Conditions/loops | 974 | 567 | 503 | 74 |
| Allocation/free | 73 | 69 | 4 | 0 |
| Exit statements | 103 | 53 | 50 | 0 |
| Array/member accesses | 1167 | 738 | 614 | 141 |

Counts are row-weighted line occurrences, not unique independent statements or
source families. Ambiguous baseline/candidate lines remain separately recorded;
the present-line deltas need not equal lost-minus-gained after ambiguity handling.
SRC loss does not establish absence from PATHS/STATE or establish a causal effect.

Node line-position proxy:182 condition/loop lines and273 exit lines have some
full-CPG node representation but none among compressed nodes. Allocation/free
line proxy loss is zero. This is optimistic line coverage, not semantic/edge
preservation: keeping one node on a line does not prove its important relations
survive. Conversely missing a node line position does not prove the original
statement was not represented in a multi-line node CODE field. No invented
parsing-failure claim from these counts.

## Outcome association, not causal attribution

Evidence measures are computed before labels/predictions are attached. All
directions retained, no selected favorable examples or per-CWE rules:

| Transition | Rows | Lost condition candidates | Budget omission present |
| --- | ---: | ---: | ---: |
| TP -> FN | 24 | 18 | 7 |
| FN -> TP | 12 | 9 | 2 |
| TN -> FP | 18 | 12 | 12 |
| FP -> TN | 18 | 14 | 7 |

Both TP->FN and FN->TP lose conditions in75% of rows. Therefore this association
does not identify guard loss as the cause of the quality regression. None of
the positive-label flips loses allocation/free lines by this measurement.
The net12 additional false negatives previously reported are24 losses minus12
recoveries, not only12 individual flipped examples.

40 first message pairs are identical;8 of those have different final predictions,
all8 are single-step on BOTH sides. Provider response variation remains a
competing explanation. Repeated sources/families are correlated; no significance
or independent generalization claim from these transition counts.

## Reproduction and instrumentation

Initial results:
output/sven_evidence_preservation_audit_20261006/{rows.json,report.json}.
Before changing diagnostic receipts, all prediction source files matching the
full-SVEN manifest were copied to
output/sven_full_pipeline_code_snapshot_20261006; hashes verified before copy.
No API secrets/environment file copied; this is a code snapshot, not a claim
of exact provider/environment recreation.

Verified frozen-code audit replay:
output/sven_evidence_preservation_snapshot_replay_20261006. Category totals and
all transition cohorts match exactly. Reproduce against this snapshot with:

    python -m evaluation.audit_evidence_preservation --run output/sven_full_pipeline_eval_20261006 --code-root output/sven_full_pipeline_code_snapshot_20261006 --output NEW_EMPTY_DIRECTORY

Historical path text truncates node content and does not save node IDs; exact
TopK criterion lineage cannot be recovered reliably from these receipts. Do not
invent a claim that a particular node was lost by TopK.

Added local-only trace receipts for FUTURE runs, gated by RECORD_REASONING_TRACE:
compressed node IDs, initial TopK node-ID sequences/path-graph origin, source
offset, criterion/visited node IDs, pre-budget selected lines and omitted lines.
Pipeline lineage is attached after inference; slicing lineage is never supplied
as prompt context. No scoring, path selection, budgets or prediction policy
changed.122 regressions pass, including traced/untraced identical slice text and
selection. Existing historical manifests/results were not rewritten.

## Next gate

First verify exact node/edge provenance with these receipts. Then test whether
atomic criterion+relevant-guard+termination evidence groups can fit the SAME
budget without discarding allocation/size/lifetime evidence or adding unrelated
guards. Treat this as a new default-off candidate, not an established solution.
Use label-independent offline invariants first, then a preregistered group-disjoint
development comparison; no post-hoc selection on these SVEN outcomes or locked
final test. No detection-quality gain claimed by this audit.
