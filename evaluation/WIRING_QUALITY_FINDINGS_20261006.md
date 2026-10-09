# Quality findings and evaluation configuration defect

**No quality candidate promoted. The corrected type-covered replay is now complete;
see WIRING_QUALITY_FIXED_FINDINGS_20261006.md.** All new switches remain default off;
failed GAT and graph security net remain disabled. Locked test was untouched.

## What actually ran

60 group-sampled development functions, all CPGs valid, 36 positive/24 negative;
8 first-repeat arms plus 3 predeclared second-repeat arms, 660 scheduled pairs,
688 observed API invocations, zero pipeline errors. Requests and answers were
preserved in `output/devign_wiring_quality60_eval_20261006/api_receipts.jsonl`.
Returned model: `deepseek-flash`; requested alias: `deepseek-chat`. This does not
identify an exact provider weight version or match another paper's model.

Post-run audit found an **experiment configuration mismatch**: `python -m
evaluation...` imported `evaluation/__init__.py`, which eagerly imported ablation,
reasoning and `config` *before* the runner installed its frozen environment.
In particular TYPE_COVERAGE_PROMPT and RECORD_REASONING_TRACE stayed false.
The actual system prompt contains the original six types, not the predeclared
expanded OOB-read/Integer-Overflow vocabulary. The envelope's requested settings
were not sufficient proof of their effective values. Raw API records still save
the exact system/user prompts and answers, even though inner traces omit text.

The batch is therefore archived as **legacy-type exploratory factorial evidence**,
not the intended type-covered control, not a replacement for historical SVEN
scores and not publishable as the predeclared method result. Code was frozen
through the run; the configuration defect was corrected only after completion.
Old receipts, scores and manifests have not been rewritten.

## Observed scores under the actual legacy-type configuration

Full-denominator Accuracy and conservative F1; uncertain/error responses count
as errors. Each row has the same 60 functions, not 60 new samples per arm.

| First-repeat arm | F1 | Accuracy | Mean actual tokens |
| --- | ---: | ---: | ---: |
| Control | .4727 | .5167 | 934.3 |
| Dependence slice only | .5385 | .6000 | 914.8 |
| Bounded verdict-first output only | .1000 | .4000 | 810.5 |
| Enhanced expansion only | .3922 | .4833 | 880.4 |
| Combined | .2326 | .4500 | 873.5 |
| Combined without slice | .1429 | .4000 | 892.9 |
| Combined without bounded output | .5385 | .6000 | 881.0 |
| Combined without expansion upgrade | .1905 | .4333 | 777.2 |

Second-repeat control: F1 .4615 / Acc .5333; bounded output: .0952 / .3667;
combined: .1905 / .4333. Repeat first system/user prompts were unchanged for
all 60 samples in each of these three profiles; prediction disagreements were
11, 3 and 2. Contract-only vs control first user prompts also matched 60/60.
Thus the large output-contract regression is not explained by changed user
evidence or lost unambiguous standard type names in the parser.

Contract-only final hypotheses: **52 Benign, 5 Uncertain, 3 concrete types**.
The parser recognized all unambiguous standard-vocabulary positive hypotheses.
No contract fields were incomplete. The model's semantic judgment shifted toward
Benign; merely eliminating output truncation was not a quality improvement.
This prompt also adds an uncertainty option/evidence policy and changes field
order, so it is a compound output-policy intervention, not pure formatting.
Do not attribute the regression uniquely to line order or token length.

Slice-only F1 delta +.0657, paired group CI95 [-.1545,+.2871]; Accuracy delta
+.0833, CI95 [-.0667,+.2333]. These intervals cross zero and are exploratory,
not multiple-comparison-adjusted. No robust gain established. Slice fallback
3/60; budget-omitted lines in 26/60; no node cap hits. Slicing executes real
REACHING_DEF/CDG traversal, but budget coverage remains incomplete.

Enhanced expansion-only executed **zero new-path events**, because legacy long
responses did not supply a complete explicit action+gap. Combined ran 6 valid
expansion events and 6 second calls. Its overall quality still declined.
Calling a module does not establish its benefit or even a nonzero trigger rate.

Outer source verifier fixed-answer removal: **zero flips in every arm/repeat**.
No contribution is observed on this batch. This is an exact no_safety_net replay
with saved main predictions and arbitration disabled, not a fresh model rerun.
Graph safety verification and learned scores remained off in every recorded arm.

Always-positive trivial baseline: Accuracy .60 / F1 .75; always-negative:
Accuracy .40 / F1 .00. No arm exceeded both requested >.60 metrics; none beat
the always-positive baseline on both. Do not treat cost savings alone as progress
toward the paper's detection-quality goal.

## Fix and verification

`evaluation/__init__.py` now lazily exports ablation/robustness APIs, preserving
public imports while avoiding premature config loading. The runner checks actual
config values against every requested prediction switch **before any API call**,
saves `effective_settings`, and includes package init in its code hashes.
`--preflight-only` verifies the real module entry, graph/source identities and
expanded vocabulary without creating an API client. Mismatch fails closed.

111 regression tests passed, including fresh-process package import and
configuration-mismatch rejection. Corrected zero-call preflight passed on all
60 inputs; TYPE_COVERAGE_PROMPT and trace are now true, all learned/graph-net
flags false. Manifest saved at
`output/devign_wiring_quality60_preflight_fixed_20261006/manifest.json`.

Verdict audit v1 incorrectly read absent inner answers; retain it as a failed
audit, not evidence of missing model hypotheses. v2 reads original API answers
and supersedes its hypothesis distribution. Neither changes predictions.

## Next gate

Completion update: the corrected replay finished 660 pairs / 687 API invocations.
Slice+expansion without bounded output reached point F1 .6774 / Accuracy .6667,
but unchanged-input variation prevents attribution and it lacks independent
confirmation. Preserve both batches; do not treat the old scores below as the
effective type-covered configuration. Detailed corrected findings are separate.

Rerun the intended configuration under effective-value assertions; label any
same-batch replay as development/configuration repair, not independent confirmation.
No threshold tuning or favorable rerun selection. Retain the rejected output
policy and expansion upgrade off. Any slice candidate requires a separately
group-disjoint confirmation and enough evidence coverage, before default promotion
or a paper claim. Legacy bounded-observation experiments already exist; inspect
their evidence before proposing another supposedly new prompt.
