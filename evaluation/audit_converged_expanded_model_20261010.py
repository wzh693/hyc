"""Full expanded-model receipt and prediction replay audit; no retraining or APIs."""
import contextlib
import io
import json
import math
from pathlib import Path
import socket
from unittest.mock import patch

import torch
from sklearn.metrics import roc_auc_score, balanced_accuracy_score
from graph.load_graph import load_graph
from learning.gat_model import GATMIL
from development.converged_graph_v2_candidate_20261010.minimal_features import graph_to_arrays
from development.converged_graph_v2_candidate_20261010.train_minimal_gat import tensors
from evaluation.prepare_converged_expansion_20261010 import ROOT, read, sha


def main():
    run = ROOT/'output/converged_expanded_gat_training_20261010'
    expansion = ROOT/'output/converged_expansion_cpg_20261010'
    original = ROOT/'output/converged_minimal_gat_training_20261010'
    original_cache = ROOT/'output/devign_development300_20261005'
    split, report = read(run/'split.json'), read(run/'report.json')
    baseline_split, baseline = read(original/'split.json'), read(original/'report.json')
    if report['policy'] != baseline['policy'] or report['untrained_selection'] != baseline['untrained_selection']:
        raise ValueError('Policy/initialization drift')
    for part in ('selection', 'calibration'):
        if split[part] != baseline_split[part]:
            raise ValueError('Changed held-out development groups')
    expanded_meta, original_meta = read(expansion/'meta.json'), read(original_cache/'meta.json')
    expected_train = set(baseline_split['train']) | {f for f, r in expanded_meta.items() if r['status'] == 'prepared'}
    if len(split['train']) != len(expected_train) or set(split['train']) != expected_train:
        raise ValueError('Changed training scope')
    keys = set().union(*(set(split[k]) for k in ('train', 'selection', 'calibration')))
    unavailable = {r['fid'] for r in split['unavailable']}
    if keys & unavailable or keys | unavailable != set(original_meta) | set(expanded_meta) or len(keys)+len(unavailable) != 2644:
        raise ValueError('Dropped full-scope rows')
    groups = [{split['group_membership'][f] for f in split[k]} for k in ('train', 'selection', 'calibration')]
    if any(groups[i] & groups[j] for i in range(3) for j in range(i)):
        raise ValueError('Group leakage')
    for name, expected in split['source_hashes'].items():
        if sha(ROOT/name) != expected:
            raise ValueError('Training source drift')
    if sha(expansion/'meta.json') != split['expansion_metadata_sha256'] or sha(run/'gat_mil.pt') != report['model_sha256']:
        raise ValueError('Data/model drift')
    checkpoint = torch.load(run/'gat_mil.pt', map_location='cpu', weights_only=True)
    if checkpoint['split_manifest_sha256'] != sha(run/'split.json'):
        raise ValueError('Checkpoint/split binding mismatch')
    torch.set_num_threads(2)
    model = GATMIL(**checkpoint['config']).eval()
    model.load_state_dict(checkpoint['state_dict'])
    maximum = entropy_maximum = 0.
    audited = 0
    def blocked(*a, **kw):
        raise RuntimeError('External connections forbidden')
    with patch.object(socket.socket, 'connect', blocked), patch.object(socket, 'create_connection', blocked), torch.no_grad():
        for part in ('train', 'selection', 'calibration'):
            result = report[part]
            rows = result['scores']
            if len(rows) != len(split[part]) or {r['fid'] for r in rows} != set(split[part]):
                raise ValueError('Incomplete predictions')
            y, p = [], []
            for row in rows:
                fid = row['fid']
                cache, meta = (expansion, expanded_meta) if fid in expanded_meta else (original_cache, original_meta)
                dot, source = cache/fid/'export/export.dot', cache/fid/'source.c'
                identity = split['graph_identities'][fid]
                if sha(dot) != identity['dot_sha256'] or sha(source) != identity['source_sha256'] or row['target'] != int(meta[fid]['target']):
                    raise ValueError('Graph/source/target drift')
                with contextlib.redirect_stdout(io.StringIO()):
                    graph = load_graph(str(dot))
                logit, attention = model(*tensors(graph_to_arrays(graph)))
                probability = float(torch.sigmoid(logit))
                entropy = float(-(attention*torch.log(attention.clamp_min(1e-9))).sum())/max(math.log(len(attention)), 1.)
                maximum = max(maximum, abs(probability-row['probability']))
                entropy_maximum = max(entropy_maximum, abs(entropy-row['normalized_attention_entropy']))
                y.append(row['target'])
                p.append(probability)
                audited += 1
            if abs(roc_auc_score(y, p)-result['auc']) > 1e-12 or balanced_accuracy_score(y, [v >= .5 for v in p]) != result['balanced_accuracy_fixed_05']:
                raise ValueError('Metrics mismatch')
            print(json.dumps(dict(audited_partition=part, rows=len(rows))), flush=True)
    if maximum > 1e-6 or entropy_maximum > 1e-6:
        raise ValueError('Prediction replay mismatch')
    best = max(report['history'], key=lambda r: r['selection_auc'])
    if report['best_epoch'] != best['epoch']:
        raise ValueError('Wrong epoch selection')
    cal = report['calibration']
    gate = cal['auc'] > .5 and cal['balanced_accuracy_fixed_05'] > .5
    if gate != report['model_diagnostic_gate']:
        raise ValueError('Changed acceptance gate')
    result = dict(pass_audit=True, requested=2644, audited_predictions=audited,
        unavailable=len(unavailable), probability_max_abs=maximum, entropy_max_abs=entropy_maximum,
        group_disjoint=True, model_diagnostic_gate=gate, source_sha256=sha(Path(__file__)),
        model_sha256=sha(run/'gat_mil.pt'), paid_api_calls=0,
        limitation='Repeated development diagnostics, not independent LLM/system evaluation')
    (run/'audit.json').write_text(json.dumps(result, indent=2), encoding='utf8')
    print(json.dumps(result, indent=2), flush=True)


if __name__ == '__main__':
    main()
