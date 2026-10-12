"""Full prepared-development diagnosis; read frozen weights, never train or call APIs."""
import argparse
import contextlib
import io
import json
import math
from pathlib import Path
import socket
from unittest.mock import patch

import numpy as np
import torch
from sklearn.metrics import roc_auc_score, balanced_accuracy_score, log_loss
from graph.load_graph import load_graph
from learning.gat_model import GATMIL, _TOK_RE
from development.converged_graph_v2_candidate_20261010.audit_training import audit
from development.converged_graph_v2_candidate_20261010.architecture import SharedGATScorer
from development.converged_graph_v2_candidate_20261010.minimal_features import graph_to_arrays
from development.converged_graph_v2_candidate_20261010.train_minimal_gat import ROOT, read, tensors, sha

PARTS = ('train', 'selection', 'calibration')
CONTAINERS = {'METHOD', 'BLOCK', 'FILE', 'NAMESPACE_BLOCK'}


def metrics(rows, field='probability'):
    y = [r['target'] for r in rows]
    p = [r[field] for r in rows]
    return dict(n=len(rows), positive=sum(y), negative=len(y)-sum(y),
                predicted_positive=sum(v >= .5 for v in p),
                auc=float(roc_auc_score(y, p)) if len(set(y)) == 2 else None,
                balanced_accuracy=float(balanced_accuracy_score(y, np.array(p) >= .5))
                    if len(set(y)) == 2 else None,
                bce=float(log_loss(y, p, labels=[0, 1])))


def summarize(rows):
    fields = ('nodes', 'edges', 'normalized_entropy', 'top15_mass',
              'container_node_fraction', 'container_attention_mass',
              'criterion_attention_mass', 'truncated_node_fraction')
    return {key: dict(mean=float(np.mean([r[key] for r in rows])),
                     median=float(np.median([r[key] for r in rows]))) for key in fields}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('Refuse overwrite')
    run = ROOT/'output/converged_minimal_gat_training_20261010'
    before = audit(run)
    split, previous = read(run/'split.json'), read(run/'report.json')
    cache = ROOT/'output/devign_development300_20261005'
    metadata = read(cache/'meta.json')
    torch.set_num_threads(2)
    checkpoint = torch.load(run/'gat_mil.pt', map_location='cpu', weights_only=True)
    # Exact original initialization, for reconstruction checks, NOT model selection.
    torch.manual_seed(42)
    initial = GATMIL(**checkpoint['config']).eval()
    trained = GATMIL(**checkpoint['config']).eval()
    trained.load_state_dict(checkpoint['state_dict'])
    scorer = SharedGATScorer(run/'gat_mil.pt', run/'split.json')
    saved = {r['fid']: r for part in ('selection', 'calibration')
             for r in previous[part]['scores']}
    saved_initial = {r['fid']: r for r in previous['untrained_selection']['scores']}
    rows, errors = [], []
    parity_max = saved_max = initial_max = 0.
    blocked_count = [0]
    def blocked(*a, **kw):
        blocked_count[0] += 1
        raise RuntimeError('External connections forbidden')
    with patch.object(socket.socket, 'connect', blocked), patch.object(socket, 'create_connection', blocked):
        for part in PARTS:
            for fid in split[part]:
                try:
                    with contextlib.redirect_stdout(io.StringIO()):
                        graph = load_graph(str(cache/fid/'export/export.dot'))
                    arrays = graph_to_arrays(graph)
                    with torch.no_grad():
                        logit, attention = trained(*tensors(arrays))
                        ilogit, _ = initial(*tensors(arrays))
                    a = attention.numpy()
                    probability = float(torch.sigmoid(logit))
                    ip = float(torch.sigmoid(ilogit))
                    scores = scorer(graph, (cache/fid/'source.c').read_text(encoding='utf-8-sig'))
                    parity_max = max(parity_max, max(abs(scores[n]-float(a[i])) for i, n in enumerate(graph)))
                    if fid in saved:
                        saved_max = max(saved_max, abs(probability-saved[fid]['probability']))
                    if fid in saved_initial:
                        initial_max = max(initial_max, abs(ip-saved_initial[fid]['probability']))
                    attrs = [graph.nodes[n] for n in graph]
                    container = np.array([v.get('node_type') in CONTAINERS for v in attrs])
                    criterion = np.array([v.get('node_type') in {'CALL', 'RETURN'} for v in attrs])
                    row = dict(fid=fid, partition=part, target=int(metadata[fid]['target']),
                        project=metadata[fid]['project'], probability=probability,
                        initial_probability=ip, nodes=len(graph), edges=graph.number_of_edges(),
                        normalized_entropy=float(-(a*np.log(np.maximum(a, 1e-9))).sum())/max(math.log(len(a)), 1.),
                        top15_mass=float(np.sort(a)[-15:].sum()),
                        container_node_fraction=float(container.mean()), container_attention_mass=float(a[container].sum()),
                        criterion_attention_mass=float(a[criterion].sum()),
                        top1_type=attrs[int(a.argmax())].get('node_type'),
                        truncated_node_fraction=sum(len(_TOK_RE.findall(v.get('code') or '')) > 48 for v in attrs)/len(attrs))
                    rows.append(row)
                except Exception as exc:
                    errors.append(dict(fid=fid, partition=part, error=repr(exc)))
            print(json.dumps(dict(partition=part, processed=len(rows), errors=len(errors))), flush=True)
    if errors or len(rows) != split['available_rows'] or max(parity_max, saved_max, initial_max) > 1e-6:
        passed = False
    else:
        passed = audit(run) == before
    results = {}
    for part in PARTS:
        subset = [r for r in rows if r['partition'] == part]
        results[part] = dict(trained=metrics(subset), initial_posthoc=metrics(subset, 'initial_probability'),
            graph_attention=summarize(subset),
            top1_container_rows=sum(r['top1_type'] in CONTAINERS for r in subset),
            projects={p: metrics([r for r in subset if r['project'] == p]) for p in sorted({r['project'] for r in subset})})
    groups = {}
    for fid in split['group_membership']:
        groups.setdefault(split['group_membership'][fid], []).append(fid)
    conflicts = [members for members in groups.values() if len({metadata[f]['target'] for f in members}) > 1]
    report = dict(pass_integrity=passed, audit=before, frozen_model_sha256=sha(run/'gat_mil.pt'),
        diagnostic_source_sha256=sha(Path(__file__)), parameter_count=sum(p.numel() for p in trained.parameters()),
        requested_rows=300, scored_rows=len(rows), unavailable=split['unavailable'], errors=errors,
        parity_max_abs=parity_max, saved_probability_max_abs=saved_max,
        reconstructed_initial_selection_max_abs=initial_max, partitions=results,
        conflicting_label_groups_in_available=conflicts, epoch_history=previous['history'], rows=rows,
        blocked_external_attempts=blocked_count[0], paid_api_calls=0, training_updates=0,
        limitations='Posthoc diagnosis of all available prepared-development graphs, not independent evaluation. '
        'Metadata targets are reused, not independently reannotated. Initial model is diagnostic only; '
        'no model/threshold selection, retraining, LLM accuracy or causal attention attribution.')
    args.output.mkdir(parents=True)
    (args.output/'report.json').write_text(json.dumps(report, indent=2), encoding='utf8')
    print(json.dumps({k: report[k] for k in ('pass_integrity', 'scored_rows', 'parameter_count', 'partitions')}, indent=2))


if __name__ == '__main__':
    main()
