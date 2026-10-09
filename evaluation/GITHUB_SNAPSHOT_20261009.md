# Graph-guided research snapshot — 2026-10-09

This publication records the current workspace source and research reports. It
does not promote an experimental candidate or claim independent test success.

## Selected foundation

The selected prediction source is
`development/type_coverage_reconstructed_20261008/src/`, whose 47 Python files
match `baselines/type_coverage_reconstructed_20261008/baseline.json`.
Root entry points still execute the preserved repaired implementation; they do
not automatically select the isolated foundation. Read the development README
and `GRAPH_GUIDED_MAINLINE_20261009.md` before running or changing a pipeline.

The complete-source, graph-read-slice, display-reranking and whole-evidence-card
candidates are research comparisons, not selected defaults. Whole-evidence v2
improved CWE-125 in both repeats but failed four of five quality gates, with
substantial CWE-190 degradation. See `GRAPH_EVIDENCE_CARDS_LLM_FINDINGS_20261009.md`.
All previous paid-test authorizations are consumed. This upload makes no new
model calls and does not authorize subsequent calls or locked-test evaluation.

## Research interpretation

Stay within the original sequence: what to compress, what paths to retrieve,
and what missing evidence to query under constrained reasoning. Current trials
motivate studying preservation of decision-relevant relations, complete and
traceable graph-to-source projection, and queries targeting explicit evidence
gaps. These are hypotheses to validate, not established contributions.
Do not combine the highest per-CWE scores into a claimed unified result or route
prediction using dataset CWE labels. SVEN remains development-exposed.

## Publication scope and reproduction

Includes source, frozen foundation metadata, isolated candidates, protocols,
tests and findings. Excludes local datasets/split manifests, model weights,
raw API requests/responses, runtime output and credentials. Existing tracked
legacy weights are not updated in this snapshot. Some audit and dataset tests
require the excluded local artifacts; this is not a self-contained raw-data
reproduction bundle.

The existing `releases/type_coverage_reconstructed_20261008/run_tests.py` provides
portable synthetic/fixed-answer engineering checks. These checks are not fresh
LLM evaluation or evidence of detection quality. No candidate activation, main
branch merge, final independent test or submission is performed by this upload.

## Pre-publication checks

The full offline evaluation-tool regression suite passed all 227 tests. Its
initial sandboxed attempt encountered temporary-directory permission failures;
the permission-scoped offline rerun passed. The portable release passed all five
checks. Staged Python files under frozen/isolated source roots were checked for
byte identity with local files. Credential-pattern and excluded-path scans found
no matches in the staged publication. These checks do not replace live quality
evaluation or a comprehensive security audit.
