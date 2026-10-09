# Experimental type-coverage baseline

This is an isolated, reconstructed HGL-Vul development foundation, based on a
hash-verified 2026-10-06 snapshot and the historical type-coverage configuration.
It is **not** an exact restoration of the source that produced historical SVEN
F1 61.15%, and is not an independently validated vulnerability detector.

The original repository entry points are unchanged. Use this package explicitly;
do not mix its results with the root pipeline. Prediction source is in `src/`;
`profile.json` contains portable paths, settings and SHA-256 hashes of all47 files.
Learning and later candidate switches are off, graph budget4096, output cap150,
maxsteps2. No dataset, CPG, checkpoint, secret or raw model response is included.
Legacy optional training/evaluation modules are retained for source provenance;
they are not standalone entry points and require separately prepared data/tools.

## Offline checks after cloning

From this directory, with Python3.13 (the tested runtime):

```shell
python -m pip install -r requirements.txt
python -B run_tests.py
```

These checks use the isolated source, a synthetic graph and fixed mock answers.
Network, real model-client creation and Joern subprocesses are blocked. They do
not need ignored local experiment folders or API credentials and do not measure
real-model detection quality. Do not use a root-repository test count as a test
count for this package.

## Actual authorized LLM smoke, 2026-10-08

Thirty fixed, development-exposed SVEN rows (five per label per CWE), repeated
twice.26 exact sources and21 source-family groups. Sixty successful API calls,
no failures/unknown usage/abstentions; requested `deepseek-chat`, all returned
`deepseek-flash`. Full scheduled denominators retained; first requests and code
hashes verified. Aggregate receipts are in `smoke_summary.json`.

| Repeat | F1 | Accuracy | MCC | Reported tokens |
| --- | ---: | ---: | ---: | ---: |
| 1 | 58.06% | 56.67% | 0.1336 | 26046 |
| 2 | 58.82% | 53.33% | 0.0692 | 26072 |

Important limitations:

- Always-positive F1 is66.67%, greater than both observed F1 scores; its accuracy
  is50%. Passing the exploratory accuracy/MCC sanity gate is not strong quality.
- CWE-125 accuracy is30% in both repeats, with negative MCC. CWE-416 accuracy is
 50%. The aggregate should not hide these weak groups.
- 58/60 answers end at the output length limit; three predictions change between
  repeats despite fixed inputs. Successful invocation does not imply complete
  reasoning or stable detection.
- There is no fresh matched control, no independent final test, and no evidence
  of a causal improvement or paper-readiness. Repeated calls are the same30 rows,
  not60 independent samples. No new LLM score of61.15% is claimed.
- Legacy verdict/safety-net/compression semantics remain in this reference.
  Future semantic fixes must be separate candidates; do not trust this baseline
  for production security decisions without independent validation.
- Raw prompts, responses and private local paths remain local. This source-only
  experimental publication does not authorize further paid/external tests.

Modify a separate candidate copy, keep the reference hashes, document input
changes, then obtain authorization for a fresh real-model comparison. SVEN has
already been exposed for development and cannot be called a held-out test.
