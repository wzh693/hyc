# Authorized isolated-baseline smoke

User requested real LLM testing and GitHub upload if testing has no problems.
The user accepted the recommended small scope:30 fixed SVEN rows, two repeats,
60 planned results. Do not silently upgrade this to254 rows/508 results.

Seed20261009, five rows per binary label per CWE.26 exact sources and21 family
groups; SVEN is development-exposed and duplicate/conflicting examples are kept.
No matched fresh control or independent publication-test claim.

Editable source must match all47 frozen baseline hashes. Use its actual pipeline,
not repaired root modules or a direct single-pass replacement. Inputs use the
previously hash-verified source/CPG cache. First actual requests must exactly match
the10/06 control requests already reproduced254/254 by the complete offline audit.
Read credentials locally; never copy/log keys. Send only the approved public SVEN
source/path/reasoning payload to https://api.deepseek.com/v1, requested deepseek-chat;
record the actual returned model and every invocation, including failed attempts.

Fixed cap150, maxsteps2, wrapper max3 attempts per step, SDK retries0, timeout90s.
No sample replacements, favorable resume, threshold tuning or prediction-code edits.
Local preprocessing/identical-regex caches may accelerate repeated inputs; they
must not change requests or scoring. This is not a cold-cache timing measurement.

Freeze manifest/runner/code before real calls. Retain60 scheduled rows, errors and
abstentions in the primary denominator. Match API tokens and trace answers to rows.
Record truncation, uncertainty, repeated-call differences, all-positive reference
and actual model. Successful network execution alone is not sufficient quality.

Predeclared GitHub gate: all scheduled results explicit, no pipeline/API errors,
all usage known, verified input/code/receipt integrity, plus accuracy>.5 and MCC>0
in BOTH repeats. This is only an exploratory sanity gate, not significance or
proof of historical61.15% recovery. If gate fails, do not upload under the user's
conditional instruction; report the issue and request direction.

If eligible, publish a scoped experimental source package on a separate branch
of the configured https://github.com/wzh693/hyc.git repository. Preserve dirty
root changes and staging. No secrets, datasets, CPGs, weights, raw prompts/responses,
local absolute paths or unpublished research reports. Publish accurate aggregate
results and portable offline tests, not an unsupported paper-readiness claim.
