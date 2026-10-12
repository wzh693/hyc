"""Read-only identity, full denominator and fixed-selection checks for the WD run."""
import json
from pathlib import Path
from sklearn.metrics import roc_auc_score, balanced_accuracy_score
from development.converged_graph_v2_candidate_20261010.audit_training import audit
from development.converged_graph_v2_candidate_20261010.train_minimal_gat import ROOT, read, sha


def main():
    control = ROOT/'output/converged_minimal_gat_training_20261010'
    run = ROOT/'output/converged_gat_wd_training_20261010'
    identity = audit(run)
    baseline_split, split = read(control/'split.json'), read(run/'split.json')
    baseline, report = read(control/'report.json'), read(run/'report.json')
    for key in ('train', 'selection', 'calibration', 'group_membership', 'graph_identities', 'unavailable'):
        if split[key] != baseline_split[key]:
            raise ValueError('Changed data: '+key)
    policy = dict(report['policy'])
    if policy.pop('weight_decay') != .001 or policy != baseline['policy']:
        raise ValueError('More than one policy change')
    if split['baseline_model_sha256'] != sha(control/'gat_mil.pt') or split['baseline_report_sha256'] != sha(control/'report.json'):
        raise ValueError('Control receipt mismatch')
    if report['untrained_selection'] != baseline['untrained_selection']:
        raise ValueError('Initialization mismatch')
    best = max(report['history'], key=lambda row: row['selection_auc'])
    if report['best_epoch'] != best['epoch']:
        raise ValueError('Invalid epoch selection')
    for part in ('train', 'selection', 'calibration'):
        result = report[part]
        rows = result['scores']
        if result['n'] != len(split[part]) or len(rows) != len(split[part]) or {r['fid'] for r in rows} != set(split[part]):
            raise ValueError('Dropped/duplicated rows: '+part)
        y, p = [r['target'] for r in rows], [r['probability'] for r in rows]
        if roc_auc_score(y, p) != result['auc'] or balanced_accuracy_score(y, [v >= .5 for v in p]) != result['balanced_accuracy_fixed_05']:
            raise ValueError('Incorrect metrics')
    cal = report['calibration']
    if report['model_diagnostic_gate'] != (cal['auc'] > .5 and cal['balanced_accuracy_fixed_05'] > .5):
        raise ValueError('Changed diagnostic gate')
    if report['blocked_external_attempts'] or report['quality_test_authorized'] or report['graph_security_net_calibrated']:
        raise ValueError('Scope violation')
    print(json.dumps(dict(pass_audit=True, identity=identity, same_data=True, same_initialization=True,
        only_policy_change='weight_decay=0.001', best_epoch=report['best_epoch'],
        full_partition_predictions=293, unavailable_rows=7, model_diagnostic_gate=report['model_diagnostic_gate']), indent=2))


if __name__ == '__main__':
    main()
