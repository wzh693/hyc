# Complete supplied SRC candidate, full local SVEN (2026-10-08)

Hypothesis: sparse source selection erases scope delimiters, length updates and
exits. Historical smoke answers demonstrate branch misinterpretation, not proof
that every error is caused by slicing. CWE-125 requires an actual read outside
its intended range, not merely a suspicious pointer or absent local guard:
https://cwe.mitre.org/data/definitions/125.html.

One default-OFF candidate COMPLETE_SOURCE_SLICE in the user-selected isolated
development source. Only config.py and linearization/typed_paths.py change.
Source <=6000 characters is preserved verbatim; larger inputs explicitly fall
back to legacy sparse source. No invented scopes/guards/helpers, no label/CWE
routing. Complete provided SVEN slice is NOT guaranteed complete function code.
Keep original src_budget for DEP path-count selection: all non-SRC user sections,
system prompt, graph, retrieval, parser, safety net, maxsteps2, graphbudget4096
and outputcap150 unchanged. Extra input tokens must be reported, not hidden.

All254 original local rows (91 CWE-125,70 CWE-190,93 CWE-416),74 exact sources,
36 source/family-union groups. Duplicate and conflicting-label rows retained.
Repeated calls are not independent data. This is an exposed development replay,
not held-out validation, not the entirety of upstream SVEN research resources.

Human explicitly approved the full payload/destination/API-fee scope in this
chat on2026-10-08: control and complete_src twice each,1016 planned results.
Authorization is limited to this one batch; no automatic reruns/extra variants.
Only https://api.deepseek.com/v1, requested deepseek-chat; actual model recorded.
Maximum2 steps and3 wrapper attempts per step, SDK retries0, timeout90 seconds,
no favorable resume/replacement/automatic rerun. Credentials never copied/logged.
Keep full result denominator, errors, abstentions and all invocation costs.

Freeze code, settings, data/CPG/source hashes and first requests before calls.
Control uses candidate code with flag OFF (45 unchanged files, config adds only
flag, typed_paths only guarded SRC replacement); all first requests must match
the verified10/06 frozen foundation. Candidate first requests must change only
SRC and contain provided input verbatim on every <=6000-character row. Synthetic
actual pipeline tests validate both modes; deterministic preflight input recipes
are checked against actual first requests before sending them. The recipes are
not falsely described as full254-row production shadow execution.

Repeat1 is primary, repeat2 sensitivity. Report per-CWE/global conservative F1,
accuracy, MCC, balanced accuracy, confusion counts, always-positive/negative,
coverage/errors, model/usage/truncation and same-input repeat disagreements.
Paired family bootstrap2000 draws seed20261012, global and CWE-125 intervals.
No multiplicity-adjusted significance claims or claims of future generalization.

Exploratory support gate: CWE-125 F1 and accuracy improve in BOTH repeats;
global F1/accuracy do not fall in either repeat; candidate exceeds constant-positive
accuracy and MCC>0 in both; primary CWE-125 accuracy CI lower bound>0. Failures
do not relax gates or permit tuning/retesting. Even a pass is not automatic
promotion, GitHub upload, final test or submission. Root repaired code, frozen
foundation and previously published experimental package remain unchanged.
