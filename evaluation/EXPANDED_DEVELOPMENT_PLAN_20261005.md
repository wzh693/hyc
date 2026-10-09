# Expanded development experiment — frozen before training

Goal: test whether more diverse, valid CPGs improve grouped generalization;
this is not a guarantee of F1/Accuracy > .60. Do not reuse the development30
to tune thresholds or pick a favorable stochastic LLM repeat.

Inputs:

- Existing `output/train_cpg`:600 requested;49 fail real-body audit,551 valid.
  Source-to-cache provenance is legacy metadata,not fully hash-bound original
  build receipts. Keep that limitation separate from newer caches.
- New `output/devign_development300_20261005`:300 label-blind group-selected
  functions from development only; exclude previous development30 groups.
  Manifest SHA256 `ee4609eeefa3c665db0ca1859348e8f3613ea902a0f6a481141adeb0af3cc667`.
  Retain parser failures and their class/project distribution; never replace them.
- Do not consume validation944 or locked_test938 for training/calibration.

One candidate, no hyperparameter sweep:

- Same GATMIL architecture/features as prior candidate,128hidden/4heads/2layers.
- Seed42,Adam lr1e-3,beta entropy0,accum16,max20epochs,patience8.
- Reuse fixed clone/commit closure; train/epoch-selection/calibration groups
  disjoint. Selection uses AUC only; calibration never selects epochs.
- Calibration grid .50:.05:.95,minimum3selected,precision >=2/3. No eligible
  threshold means abstain/reject,not lower the gate after inspecting results.
- Save model/split/calibration to `learning/model/gat_expanded_beta0_20261005`,
  never overwrite existing checkpoints. Report class counts and unavailable rows.
- Internal AUC is not system F1/Acc. Even a passing calibration requires a
  separately frozen system comparison before mainline activation.

Command after complete preparation:

```powershell
python -u -m learning.train_gat 20 16 --beta-ent 0 --patience 8 --threads 4 --cache-dir output/train_cpg --cache-dir output/devign_development300_20261005 --output-dir learning/model/gat_expanded_beta0_20261005
python -m learning.calibrate_gat --model-dir learning/model/gat_expanded_beta0_20261005
```

No LLM calls are needed for preparation, training or calibration. Failed
experiments are preserved. A larger data experiment is not evidence that the
architecture or paper claim is already effective.

## Completed outcome

Preparation293/300valid;7failures retained. Merged844/900requested usable graphs.
Train689/epoch selection90/calibration65; stopped epoch10,best epoch2.
Selection AUC .5853; calibration AUC .48246. Standalone fixed.50 F1 .61538,
Acc .53846,below always-positive F1 .73786/Acc .58462 on the same65groups.
No threshold passes the frozen precision/coverage gate. Candidate rejected;
no mainline switch or HGL score claim. No LLM calls,validation/locked_test untouched.
