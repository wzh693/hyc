"""Full exposed SVEN evidence diagnostics, frozen architecture, no training/API."""
import argparse
import contextlib
from dataclasses import asdict
import io
import json
from pathlib import Path
import socket
from unittest.mock import patch

import torch
from development.converged_graph_v2_candidate_20261010 import architecture as a
from development.converged_graph_v2_candidate_20261010.audit_offline import audit
from development.converged_graph_v2_candidate_20261010.run_offline import ROOT, read, sha
from development.converged_graph_v2_candidate_20261010.minimal_features import graph_to_arrays
from development.converged_graph_v2_candidate_20261010.train_minimal_gat import tensors
from graph.load_graph import load_graph
from learning.gat_model import GATMIL
from linearization.source_mapping import source_line_offset


def diagnostics(result, graph):
    evidence = result['trace'][0]['evidence']
    visible = {n for p in evidence['displayed_paths'] for n in p}
    selected = {n for p in result['topk'] for n in p}
    nodes = {str(n): attrs for n, attrs in graph.nodes(data=True)}
    return dict(empty_src=not evidence['source_lines'],
        empty_paths=not evidence['displayed_paths'], cap_hit=result['candidate_cap_hit'],
        kept_nodes=result['compression']['kept_nodes'],
        displayed_paths=len(evidence['displayed_paths']), displayed_nodes=len(visible),
        selected_nodes=len(selected), undisplayed_selected_nodes=len(selected-visible),
        displayed_criteria=len(set(result['selected_criteria']) & visible),
        source_lines=len(evidence['source_lines']), source_chars=evidence['source_chars'],
        path_chars=evidence['path_chars'], omitted_source_lines=evidence['omitted_lines'],
        slice_cap_hit=evidence['node_cap_hit'],
        displayed_deref_nodes=sum(nodes[n].get('name') in a.DEREFS or
            nodes[n].get('method_full_name') in a.DEREFS for n in visible),
        source_criteria_not_displayed=len(set(evidence['criteria_node_ids'])-visible))


def jaccard(left, right):
    left, right = set(left), set(right)
    return len(left & right)/len(left | right) if left | right else 1.0


def compare(left, right):
    le, re = (r['trace'][0]['evidence'] for r in (left, right))
    return dict(request_changed=left['trace'][0]['request'] != right['trace'][0]['request'],
        kept_jaccard=jaccard(left['compression']['kept_node_ids'], right['compression']['kept_node_ids']),
        criterion_jaccard=jaccard(left['selected_criteria'], right['selected_criteria']),
        source_line_jaccard=jaccard(le['source_lines'], re['source_lines']),
        visible_node_jaccard=jaccard([n for p in le['displayed_paths'] for n in p],
                                   [n for p in re['displayed_paths'] for n in p]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('Fresh output required; never overwrite failed runs')
    from evaluation.test_graph_guided_foundation import verify_foundation
    verify_foundation()
    torch.set_num_threads(2)
    reference_path = ROOT/'output/sven_complete_src_eval_20261008/manifest.json'
    reference = read(reference_path)
    dataset = read(reference['dataset'])
    samples = sorted(reference['samples'], key=lambda r: r['idx'])
    if len(dataset) != 254 or len(samples) != 254 or {r['idx'] for r in samples} != set(range(254)):
        raise ValueError('Full exposed SVEN required')
    if sha(reference['dataset']) != reference['dataset_sha256']:
        raise ValueError('Dataset drift')
    directories = {k: ROOT/'output'/v for k, v in {
        'original': 'converged_minimal_gat_training_20261010',
        'expanded': 'converged_expanded_gat_training_20261010'}.items()}
    scorers = {k: a.SharedGATScorer(p/'gat_mil.pt', p/'split.json') for k, p in directories.items()}
    checkpoint = torch.load(directories['original']/'gat_mil.pt', map_location='cpu', weights_only=True)
    torch.manual_seed(42)
    initial = GATMIL(**checkpoint['config']).eval()
    def untrained(graph, source):
        with torch.no_grad():
            _, attention = initial(*tensors(graph_to_arrays(graph)))
        scores = dict(zip(graph, map(float, attention.tolist())))
        a.validate_scores(graph, scores)
        return scores
    scorers['untrained_diagnostic'] = untrained
    paths = [Path(__file__), Path(a.__file__),
        ROOT/'development/converged_graph_v2_candidate_20261010/audit_offline.py',
        ROOT/'development/converged_graph_v2_candidate_20261010/minimal_features.py',
        ROOT/'learning/gat_model.py', ROOT/'graph/load_graph.py',
        ROOT/'planning/observed_state.py', ROOT/'planning/state_memory.py',
        ROOT/'linearization/source_mapping.py', ROOT/'config.py']
    bindings = {str(p.relative_to(ROOT)): sha(p) for p in paths}
    model_bindings = {k: {f: sha(p/f) for f in ('gat_mil.pt', 'split.json', 'report.json')}
                      for k, p in directories.items()}
    expanded_audit = read(directories['expanded']/'audit.json')
    if not expanded_audit['pass_audit'] or expanded_audit['model_sha256'] != model_bindings['expanded']['gat_mil.pt']:
        raise ValueError('Missing/broken expanded model audit')
    cfg = a.Settings()
    args.output.mkdir(parents=True)
    manifest = dict(settings=asdict(cfg), dataset_sha256=reference['dataset_sha256'],
        reference_manifest_sha256=sha(reference_path), source_tool_hashes=bindings,
        model_bindings=model_bindings, rows=254, arms=list(scorers),
        planned_mock_requests=762, paid_api_calls=0, quality_evaluation=False,
        purpose='Evidence ranking diagnostics only; untrained is not an eligible replacement',
        safety_net_mode='shadow; uncalibrated')
    (args.output/'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf8')
    rows = {k: [] for k in scorers}
    blocked_calls = [0]
    def blocked(*arg, **kw):
        blocked_calls[0] += 1
        raise RuntimeError('External connections prohibited')
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(socket.socket, 'connect', blocked))
        stack.enter_context(patch.object(socket, 'create_connection', blocked))
        handles = {}
        for arm in scorers:
            folder = args.output/arm
            folder.mkdir()
            (folder/'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf8')
            handles[arm] = stack.enter_context((folder/'candidate_rows.jsonl').open('x', encoding='utf8'))
        for index, sample in enumerate(samples):
            code = dataset[sample['idx']]['input']
            graph_error = None
            try:
                dot = Path(sample['cache_path'])/'export/export.dot'
                if sha(dot) != sample['cpg_sha256'] or sha(sample['source_path']) != sample['wrapped_source_sha256']:
                    raise ValueError('Graph/source identity drift')
                import hashlib
                if hashlib.sha256(code.encode()).hexdigest() != sample['source_sha256']:
                    raise ValueError('Code drift')
                with contextlib.redirect_stdout(io.StringIO()):
                    graph = load_graph(str(dot))
                offset = source_line_offset(code, Path(sample['source_path']).read_text(encoding='utf8'))
            except Exception as exc:
                graph_error = repr(exc)
            for arm, scorer in scorers.items():
                row = dict(idx=sample['idx'], source_sha256=sample['source_sha256'], group_id=sample['group_id'])
                calls = []
                try:
                    if graph_error:
                        raise ValueError(graph_error)
                    def invoke(**request):
                        calls.append(request)
                        return dict(text='{"verdict":"Uncertain","reason":"offline fixture","action":"Stop"}',
                            finish_reason='stop', model='offline-mock', usage=None)
                    result = a.run(graph, code, offset, scorer, invoke, cfg)
                    if len(calls) != 1 or result['security_net']['mode'] != 'shadow':
                        raise ValueError('Unexpected mock invocation or net activation')
                    row.update(error=None, result=result, diagnostics=diagnostics(result, graph))
                except Exception as exc:
                    row.update(error=repr(exc))
                row['actual_mock_requests'] = len(calls)
                rows[arm].append(row)
                handles[arm].write(json.dumps(row, ensure_ascii=False)+'\n')
                handles[arm].flush()
            if (index+1) % 25 == 0 or index == 253:
                print(f'all three arms {index+1}/254', flush=True)
    report = dict(rows_per_arm=254, requested_arm_rows=762, blocked_external_attempts=blocked_calls[0],
        actual_mock_requests=sum(r['actual_mock_requests'] for rr in rows.values() for r in rr),
        paid_api_calls=0, quality_metrics=None, arms={}, pairs={}, independent_audits={})
    for arm, rr in rows.items():
        good = [r for r in rr if not r['error']]
        report['arms'][arm] = dict(rows=len(rr), errors=len(rr)-len(good),
            totals={k: sum(r['diagnostics'][k] for r in good) for k in good[0]['diagnostics']} if good else {})
        # Format adapter uses actual original-arm mock requests; no extra baseline
        # calls are invented. Each paired audit shares the same 254 control rows.
        folder = args.output/arm
        (folder/'control').mkdir()
        (folder/'control/rows.jsonl').write_text(''.join(json.dumps(dict(idx=r['idx'],
            error=r['error'], request=r.get('result', {}).get('trace', [{}])[0].get('request')))+'\n'
            for r in rows['original']), encoding='utf8')
        passed = len(good) == 254 and not any(r['error'] for r in rows['original']) and not blocked_calls[0]
        (folder/'report.json').write_text(json.dumps({'pass': passed}), encoding='utf8')
        if passed:
            report['independent_audits'][arm] = audit(folder)
        if arm != 'original':
            pairs = [dict(idx=l['idx'], **compare(l['result'], r['result']))
                     for l, r in zip(rows['original'], rr) if not l['error'] and not r['error']]
            report['pairs'][arm] = dict(paired_rows=len(pairs),
                changed_requests=sum(p['request_changed'] for p in pairs),
                mean_jaccard={k: sum(p[k] for p in pairs)/len(pairs) for k in
                    ('kept_jaccard', 'criterion_jaccard', 'source_line_jaccard', 'visible_node_jaccard')})
            (folder/'pairs.json').write_text(json.dumps(pairs, indent=2), encoding='utf8')
    if any(sha(ROOT/name) != value for name, value in bindings.items()):
        raise ValueError('Source drift')
    for arm, directory in directories.items():
        if any(sha(directory/f) != value for f, value in model_bindings[arm].items()):
            raise ValueError('Model receipt drift')
    verify_foundation()
    report['pass'] = (not blocked_calls[0] and report['actual_mock_requests'] == 762 and
        all(not v['errors'] for v in report['arms'].values()) and len(report['independent_audits']) == 3)
    (args.output/'report.json').write_text(json.dumps(report, indent=2), encoding='utf8')
    print(json.dumps(report, indent=2), flush=True)
    if not report['pass']:
        raise SystemExit('Failed evidence audit; preserve entire scope')


if __name__ == '__main__':
    main()
