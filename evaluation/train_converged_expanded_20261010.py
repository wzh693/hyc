"""Single data-expansion experiment; original optimizer and held-out development groups."""
import argparse
import contextlib
import hashlib
import io
import json
import math
from pathlib import Path
import random
import socket
from unittest.mock import patch

import numpy as np
import torch
from sklearn.metrics import roc_auc_score, balanced_accuracy_score
from graph.load_graph import load_graph
from learning.gat_model import GATMIL
from development.converged_graph_v2_candidate_20261010.minimal_features import FEATURE_NAMES, graph_to_arrays
from development.converged_graph_v2_candidate_20261010.audit_training import audit

ROOT = Path(__file__).resolve().parents[1]
POLICY = dict(seed=42, epochs=10, lr=.001, beta_entropy=.01, accumulation=16,
              hidden=128, heads=4, selection='maximum full selection-split bag AUC; earliest tie',
              inputs='six node-type indicators + log code length + hashed code-token embedding',
              calibration='reserved full grouped calibration; not used for epoch selection',
              safety_net='not calibrated from bag predictions; shadow only')


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def partition(group):
    value = int(hashlib.sha256(f'42:{group}'.encode()).hexdigest()[:16], 16) / 2**64
    if value >= .2:
        return 'train'
    return 'selection' if hashlib.sha256(f'calibration:42:{group}'.encode()).digest()[0] < 128 else 'calibration'


def tensors(arrays):
    return [torch.from_numpy(arrays[k]) for k in ('x', 'tok_flat', 'tok_offsets', 'edge_index', 'edge_type')]


def evaluate(model, samples, keys):
    model.eval()
    scored = []
    with torch.no_grad():
        for fid in keys:
            arrays, target = samples[fid]
            logit, attention = model(*tensors(arrays))
            entropy = float(-(attention * torch.log(attention.clamp_min(1e-9))).sum()) / max(math.log(len(attention)), 1.)
            scored.append(dict(fid=fid, target=target, probability=float(torch.sigmoid(logit)),
                               normalized_attention_entropy=entropy))
    y = [s['target'] for s in scored]
    p = [s['probability'] for s in scored]
    return dict(n=len(keys), auc=float(roc_auc_score(y, p)),
        balanced_accuracy_fixed_05=float(balanced_accuracy_score(y, [int(v >= .5) for v in p])),
        scores=scored)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('Refuse overwrite or automatic resume')
    baseline_run = ROOT/'output/converged_minimal_gat_training_20261010'
    baseline_audit = audit(baseline_run)
    baseline_split = read(baseline_run/'split.json')
    baseline_report = read(baseline_run/'report.json')
    expansion = ROOT/'output/converged_expansion_cpg_20261010'
    preparation = read(expansion/'report.json')
    expansion_meta = read(expansion/'meta.json')
    prep_protocol = read(expansion/'protocol.json')
    admitted = read(expansion/'manifest.json')
    if len(expansion_meta) != 2344 or {m['idx'] for m in expansion_meta.values()} != {m['idx'] for m in admitted}:
        raise ValueError('Expansion metadata does not cover frozen scope')
    if preparation['completed'] != 2344 or preparation['prepared']/2344 < .9:
        raise ValueError('Full preparation and >=90% coverage required; no favorable subset training')
    if sha(expansion/'meta.json') != preparation['metadata_sha256'] or sha(expansion/'protocol.json') != preparation['protocol_sha256']:
        raise ValueError('Preparation receipt drift')
    for name, expected in prep_protocol['source_hashes'].items():
        if sha(ROOT/name) != expected:
            raise ValueError('Preparation source drift')
    torch.set_num_threads(2)
    torch.manual_seed(42)
    np.random.seed(42)
    rng = random.Random(42)
    protocol_path = ROOT/'evaluation/protocol_clone_v2_20261005/development.json'
    allowed = {r['idx']: r for r in read(protocol_path)}
    cache = ROOT/'output/devign_development300_20261005'
    metadata = read(cache/'meta.json')
    if len(metadata) != 300:
        raise ValueError('Expected entire prepared development300 scope')
    groups, data, unavailable, identities = {}, {}, [], {}
    blocked_count = [0]
    def blocked(*args, **kwargs):
        blocked_count[0] += 1
        raise RuntimeError('Local training forbids external access')
    with patch.object(socket.socket, 'connect', blocked), patch.object(socket, 'create_connection', blocked):
        for fid, info in sorted(metadata.items()):
            entry = allowed.get(info['idx'])
            if entry is None or any(entry.get(k) != info.get(k) for k in
                                    ('source_sha256', 'project', 'commit_id', 'group_id')):
                raise ValueError('Sample not in exact clean development allowlist: '+fid)
            if info.get('error'):
                unavailable.append(dict(fid=fid, reason=info['error']))
                continue
            dot = cache/fid/'export/export.dot'
            if not dot.exists():
                unavailable.append(dict(fid=fid, reason='missing graph'))
                continue
            with contextlib.redirect_stdout(io.StringIO()):
                graph = load_graph(str(dot))
            arrays = graph_to_arrays(graph)
            if arrays is None:
                unavailable.append(dict(fid=fid, reason='empty graph'))
                continue
            data[fid] = (arrays, int(info['target']))
            groups[fid] = info['group_id']
            identities[fid] = dict(dot_sha256=sha(dot), source_sha256=sha(cache/fid/'source.c'))
    if set(data) != set(baseline_split['group_membership']):
        raise ValueError('Original available scope changed')
    held_groups = set(groups.values())
    expansion_available = []
    with patch.object(socket.socket, 'connect', blocked), patch.object(socket, 'create_connection', blocked):
        for fid, info in sorted(expansion_meta.items()):
            entry = allowed.get(info['idx'])
            if entry is None or any(entry.get(k) != info.get(k) for k in
                    ('source_sha256', 'project', 'commit_id', 'group_id')) or info['group_id'] in held_groups:
                raise ValueError('Expansion admission/group mismatch')
            if info['status'] != 'prepared':
                unavailable.append(dict(fid=fid, reason=info['error']))
                continue
            dot = expansion/fid/'export/export.dot'
            if sha(dot) != info['dot_sha256'] or sha(expansion/fid/'source.c') != info['source_raw_sha256']:
                raise ValueError('Expanded graph/source drift')
            with contextlib.redirect_stdout(io.StringIO()):
                graph = load_graph(str(dot))
            arrays = graph_to_arrays(graph)
            if arrays is None:
                raise ValueError('Prepared graph became empty')
            data[fid] = (arrays, int(info['target']))
            groups[fid] = info['group_id']
            identities[fid] = dict(dot_sha256=sha(dot), source_sha256=sha(expansion/fid/'source.c'))
            expansion_available.append(fid)
    splits = dict(train=sorted(baseline_split['train']+expansion_available),
                  selection=baseline_split['selection'], calibration=baseline_split['calibration'])
    if any(len({data[f][1] for f in keys}) != 2 for keys in splits.values()):
        raise ValueError('Each full grouped partition needs both classes')
    feature_path = ROOT/'development/converged_graph_v2_candidate_20261010/minimal_features.py'
    source_paths = [Path(__file__), feature_path,
                    ROOT/'learning/gat_model.py', ROOT/'graph/load_graph.py']
    source_hashes = {str(p.relative_to(ROOT)): sha(p) for p in source_paths}
    manifest = dict(policy=POLICY, clean_development_manifest_sha256=sha(protocol_path),
        cache_metadata_sha256=sha(cache/'meta.json'), requested_rows=2644,
        expansion_metadata_sha256=sha(expansion/'meta.json'),
        expansion_protocol_sha256=sha(expansion/'protocol.json'),
        baseline_split_sha256=sha(baseline_run/'split.json'),
        changed_factor='training scope only: original train plus all available admitted expansion graphs',
        available_rows=len(data), unavailable=unavailable, group_membership=groups,
        **splits, source_hashes=source_hashes, graph_identities=identities,
        paid_api_calls=0, locked_samples_accessed=0)
    args.output.mkdir(parents=True)
    split_path = args.output/'split.json'
    split = dict(manifest, holdout=splits['selection'])
    split_path.write_text(json.dumps(split, indent=2), encoding='utf8')
    model_cfg = dict(d_feat=7, d_tok=32, hidden=128, heads=4, n_edge_types=5,
                     edge_dim=16, d_attn=64, dropout=.1)
    model = GATMIL(**model_cfg)
    optimizer = torch.optim.Adam(model.parameters(), lr=.001)
    untrained = evaluate(model, data, splits['selection'])
    if untrained != baseline_report['untrained_selection']:
        raise ValueError('Initialization/control selection differs')
    best_auc, best_state, best_epoch, history = -1., None, None, []
    keys = list(splits['train'])
    for epoch in range(1, 11):
        model.train()
        rng.shuffle(keys)
        optimizer.zero_grad()
        loss_sum = 0.
        for i, fid in enumerate(keys):
            arrays, target = data[fid]
            logit, attention = model(*tensors(arrays))
            bce = torch.nn.functional.binary_cross_entropy_with_logits(logit, torch.tensor(float(target)))
            entropy = -(attention * torch.log(attention.clamp_min(1e-9))).sum() / max(math.log(len(attention)), 1.)
            loss = bce + .01 * entropy
            group_size = min(16, len(keys) - (i // 16) * 16)
            (loss / group_size).backward()
            loss_sum += float(loss.detach())
            if (i+1) % 16 == 0 or i+1 == len(keys):
                optimizer.step()
                optimizer.zero_grad()
        selection = evaluate(model, data, splits['selection'])
        history.append(dict(epoch=epoch, loss=loss_sum/len(keys), selection_auc=selection['auc']))
        if selection['auc'] > best_auc:
            best_auc, best_epoch = selection['auc'], epoch
            best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
        print(json.dumps(history[-1]), flush=True)
    model.load_state_dict(best_state)
    checkpoint_path = args.output/'gat_mil.pt'
    torch.save(dict(state_dict=model.state_dict(), config=model_cfg,
        feature_names=FEATURE_NAMES, split_manifest_sha256=sha(split_path),
        policy=POLICY, feature_module_sha256=sha(feature_path)), checkpoint_path)
    calibration = evaluate(model, data, splits['calibration'])
    report = dict(policy=POLICY, best_epoch=best_epoch, history=history,
        untrained_selection=untrained, selection=evaluate(model, data, splits['selection']),
        calibration=calibration, train=evaluate(model, data, splits['train']),
        changed_factor=manifest['changed_factor'], model_sha256=sha(checkpoint_path),
        requested_rows=2644, available_rows=len(data), partition_counts={k: len(v) for k,v in splits.items()},
        unavailable=unavailable, blocked_external_attempts=blocked_count[0],
        model_diagnostic_gate=calibration['auc'] > .5 and calibration['balanced_accuracy_fixed_05'] > .5,
        quality_test_authorized=False, graph_security_net_calibrated=False,
        limitations='Internal grouped model diagnostics only. No LLM performance, causal node attribution, '
                    'or graph-net threshold/flip calibration. No automatic retraining if gate fails.')
    for name, expected in source_hashes.items():
        if sha(ROOT/name) != expected:
            raise ValueError('Training source drift; keep attempt')
    if sha(protocol_path) != manifest['clean_development_manifest_sha256'] or sha(cache/'meta.json') != manifest['cache_metadata_sha256']:
        raise ValueError('Training metadata drift')
    if audit(baseline_run) != baseline_audit or sha(expansion/'meta.json') != manifest['expansion_metadata_sha256']:
        raise ValueError('Control or expansion source changed during training')
    (args.output/'report.json').write_text(json.dumps(report, indent=2), encoding='utf8')
    print(json.dumps({k: report[k] for k in ('available_rows','partition_counts','best_epoch','model_diagnostic_gate')}, indent=2), flush=True)


if __name__ == '__main__':
    main()
