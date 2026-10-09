# CWE-125 diagnosis and one-candidate full replay

Status: authorized1016-result batch COMPLETE at
output/sven_complete_src_eval_20261008. Both independent audits passed.
The complete-SRC candidate is REJECTED for the stated CWE-125/global objective;
it stays default OFF. No rerun, promotion, locked test or new GitHub upload.
Prior60-result smoke was only10 CWE-125 rows per repeat;30% is not the full91-row
CWE-125 accuracy. Repeat1 TP2/TN1/FP4/FN3;repeat2 TP3/TN0/FP5/FN2.

## Concrete observations, not causal quality claims

Saved idx187 input drops standalone closing braces around drive validation and
fdc validation. The answer infers validation before use, while the supplied
source puts set_dor outside those branches. Macro implementation is unavailable,
so restoring braces alone cannot prove an OOB read or the correct label.

Idx189 sparse input drops a closing error-branch brace. The answer places
hdr->frame_size inside parse failure, but the supplied slice has that read later,
inside a different branch. Original SVEN itself has missing branch bodies and
unbalanced scope; do not invent the absent original return/helper postcondition.

Idx224/232 false positives cite absence of an offset bounds guard in the slice.
Idx235 false negative assumes ReadProfileByte updates length and exhaustion
behavior without visible helper implementation. These illustrate incomplete
evidence/contract reasoning, not that all labels are correct or that SRC alone
explains30% accuracy. All10 smoke CWE-125 source-security-net receipts have
score0 and no flips: that net is not responsible for these observed predictions.

CWE-125 is a read beyond the intended buffer (including before its beginning),
not pointer arithmetic or a suspicious API alone. Primary definition and examples:
https://cwe.mitre.org/data/definitions/125.html.

## Chosen experiment

Single default-OFF COMPLETE_SOURCE_SLICE: preserve all supplied input verbatim
up to6000 characters, explicitly fall back on larger input. No label/CWE routing,
new prompts, output-budget changes, graph/ranking/parser/net changes or threshold
sweeps. All254 local supplied slices fit;254 candidate first inputs change only
SRC,0 fallbacks. DEP/STATE/system/caps remain identical. Extra input cost expected.
This is evidence completeness of an existing slice, not full-function recovery.

193 local regression tests pass, including a fresh-process suite of6 actual
isolated-source checks (scope/assignments/comments/order/cap/dependency-policy/
mocked actual pipeline). The6 child checks are nested in one of the193 cases;
do not sum them as199 top-level tests. Network/model creation blocked there.

Final preflight is output/sven_complete_src_preflight_v2_20261008: deterministic
input recipes, not a full254-row pipeline shadow. Actual first request equality
is verified before each first external invocation; all254 sources/CPGs hashed,
47 candidate sources and evaluator/protocol/auditor/test tool hashes frozen.
45 candidate files match foundation; only config.py and typed_paths.py differ.
Earlier preflight remains archived and is not used after final tooling freeze.

User explicitly authorized full254 control/candidate twice,1016 scheduled results,
DeepSeek public-source/path/context disclosure and API fees. No Devign locked
test, automatic rerun, promotion, final submission or new GitHub upload authorized.
Repeat1 primary/repeat2 sensitivity; retain duplicates/conflicting labels/errors.
Protocol SVEN_COMPLETE_SRC_PROTOCOL_20261008.md defines all decision gates.

## Completed matched full-set comparison

All1016 planned results explicit;1017 successful invocations (one extra second
step in control/r1),0 failed/unknown-usage calls,0 errors/abstentions. Requested
deepseek-chat, all returned deepseek-flash. Reported1032335 tokens,974 length
finishes. All1016 actual first requests verified;508 actual paired first inputs
change only SRC.47 candidate hashes unchanged,52 repaired root files and47
frozen/released foundation files preserved.193 local top-level tests passed.

| Scope | Repeat | Control F1 / Acc | Complete SRC F1 / Acc |
| --- | ---: | ---: | ---: |
| All254 | 1 | 60.50% / 56.30% | 56.62% / 53.54% |
| All254 | 2 | 58.52% / 55.91% | 58.39% / 55.12% |
| CWE-125,91 | 1 | 70.48% / 65.93% | 42.72% / 35.16% |
| CWE-125,91 | 2 | 65.31% / 62.64% | 46.00% / 40.66% |
| CWE-190,70 | 1 | 61.54% / 50.00% | 60.00% / 54.29% |
| CWE-190,70 | 2 | 61.36% / 51.43% | 60.76% / 55.71% |
| CWE-416,93 | 1 | 47.06% / 51.61% | 69.66% / 70.97% |
| CWE-416,93 | 2 | 47.62% / 52.69% | 69.47% / 68.82% |

CWE-125 control TP/TN/FP/FN37/23/18/13 and32/25/16/18; candidate22/10/31/28
and23/14/27/27. Candidate MCC -.31891/-.19854 vs control .30625/.24891.
Primary CWE-125 Accuracy delta -.307692, family95%CI[-.637681,-.09]; F1 delta
-.277577,[-.771710,-.028333]. Global primary Accuracy -.027559 CI
[-.175258,.107143]; F1 -.038806 CI[-.208952,.102296]. These are descriptive
intervals for exposed groups, not future-provider/independent-test guarantees.

Candidate all-call tokens +31.80%/+32.30%; paired first prompt tokens184028->
255752 each repeat (+38.97%). Candidate repeat disagreements24 vs control31,
but reduced variability does not compensate for worse CWE-125/global quality.
Always-positive F1 .673629 / Acc .507874; all global F1 scores below its F1.
Only constant-Accuracy/MCC gate passes; other preregistered gates fail.

The old30% was on10 selected CWE-125 rows, not the full91. The newly observed
control65.93%/62.64% is a different sample cohort and invocation time, NOT a
candidate improvement from30%. No favorable-repeat or after-the-fact CWE routing.

## Saved-answer post-hoc diagnosis and next hypothesis

failure_diagnosis.json records all changes. CWE-125 correct->wrong31/28 vs
wrong->correct3/8; CWE-416 gains24/25 vs losses6/10. Do not ignore the tradeoff.
Three primary CWE-125 families account for23 of28 net lost correct rows: NG
packet parsing10, adaptive thresholding7, LHA header6. These are correlated,
post-hoc descriptions, not independent confirmation or causal proof.

Idx214: control calls len unchanged after line+=3, but actual supplied source
contains len=ptr-line before memcpy. It hits the positive label using an invalid
specific reason. Candidate sees the length update and calls it safe, without
checking whether strchr's source scanning is bounded/NUL-terminated. Thus a
correct label does NOT certify control reasoning; neither simply hiding nor
adding statements repairs read-bound semantics.

Idx244 candidate flags size_t multiplication before the MagickRealType cast,
where the benchmark says benign. The arithmetic is present, but caller limits,
virtual-pixel API contracts and original omitted control regions are absent.
Do not automatically declare the label wrong or infer an exploitable OOB from
that local expression. Idx205 candidate relies on header/padding guards without
visible macro values/helper contracts. Those gaps need explicit provenance.

Next hypothesis: preserve the compressed graph/type-coverage foundation and
bind each real read (including string scans/copy-source/decode widths) to its
own buffer origin, remaining capacity, offset/width and same-path guards. Keep
destination capacity distinct from source readable size; a strchr-derived length
does not itself bound the preceding scan. Trace length/cursor updates, and mark
unknown helper/caller contracts rather than inventing safety/vulnerability facts.
First validate on label-free synthetic counterexamples; only then freeze ONE
new candidate for separately authorized unexposed confirmation. This report does
not implement or authorize another real-model batch or metadata-based CWE routing.

Data audit:74 exact sources,36 family-union groups,8 conflicting exact-source
groups covering51 rows. All retained. Source-only deterministic Accuracy bound
92.52% applies only to identical-SRC deterministic classifiers, not graph-aware
or stochastic systems. This does not explain away the observed CWE-125 decline.
Controls were run before candidates, not randomly interleaved; provider time
drift cannot be excluded merely because returned model strings match.

Artifacts: report.json, audit.json, audit_addendum.json, failure_diagnosis.json,
append-only results/API receipts and source/tooling snapshots. All audits and
diagnosis add0 real calls. Batch authorization is consumed. No paper-ready claim.
