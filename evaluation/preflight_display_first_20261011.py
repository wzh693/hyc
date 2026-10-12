"""Full254 paired SRC-only display-first mock preflight; no external client."""
import argparse
import contextlib
from dataclasses import asdict
import hashlib
import io
import json
from pathlib import Path
import socket
from unittest.mock import patch
import torch
from development.converged_graph_v2_candidate_20261010 import architecture as base
from development.converged_display_first_candidate_20261011 import architecture as candidate
from development.converged_graph_v2_candidate_20261010.audit_offline import audit
from development.converged_graph_v2_candidate_20261010.run_offline import ROOT, read, sha
from evaluation.compare_converged_evidence_20261011 import diagnostics
from evaluation.test_graph_guided_foundation import verify_foundation
from graph.load_graph import load_graph
from linearization.source_mapping import source_line_offset


def validate_pair(control, changed):
    for key in ('compression', 'topk', 'selected_criteria', 'shared_scores_sha256',
                'candidate_cap_hit', 'shared_scorer_invocations', 'main_pred', 'final_pred'):
        if control[key] != changed[key]:
            raise ValueError('Non-SRC result drift: '+key)
    for result in (control, changed):
        if len(result['trace']) != 1 or result['security_net']['mode'] != 'shadow':
            raise ValueError('Unexpected inference/net behavior')
    left, right = (result['trace'][0] for result in (control, changed))
    for key in ('displayed_paths', 'path_chars', 'state_chars'):
        if left['evidence'][key] != right['evidence'][key]:
            raise ValueError('Non-SRC evidence drift: '+key)
    lreq, rreq = left['request'], right['request']
    if lreq['max_tokens'] != rreq['max_tokens'] or lreq['messages'][0] != rreq['messages'][0]:
        raise ValueError('Prompt/settings drift')
    if lreq['messages'][1]['content'].split('\n\nPATHS:\n', 1)[1] != rreq['messages'][1]['content'].split('\n\nPATHS:\n', 1)[1]:
        raise ValueError('PATHS/STATE drift')
    evidence = right['evidence']
    endpoints = {p[-1] for p in evidence['displayed_paths']}
    if set(evidence['criteria_node_ids']) != endpoints:
        raise ValueError('SRC criteria differ from displayed endpoints')
    return lreq['messages'][1]['content'] != rreq['messages'][1]['content']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    output = parser.parse_args().output
    if output.exists():
        raise ValueError('Fresh output required; preserve prior failures')
    verify_foundation()
    torch.set_num_threads(2)
    ref_path = ROOT/'output/sven_complete_src_eval_20261008/manifest.json'
    ref = read(ref_path)
    dataset = read(ref['dataset'])
    samples = sorted(ref['samples'], key=lambda r: r['idx'])
    if len(dataset) != 254 or len(samples) != 254 or {r['idx'] for r in samples} != set(range(254)):
        raise ValueError('Full254 required')
    if sha(ref['dataset']) != ref['dataset_sha256']:
        raise ValueError('Dataset drift')
    model_dir = ROOT/'output/converged_expanded_gat_training_20261010'
    scorer = base.SharedGATScorer(model_dir/'gat_mil.pt', model_dir/'split.json')
    model_audit = read(model_dir/'audit.json')
    if not model_audit['pass_audit'] or model_audit['model_sha256'] != scorer.model_sha256:
        raise ValueError('Expanded model audit mismatch')
    previous = read(ROOT/'output/converged_evidence_comparison_20261011/manifest.json')
    bindings = dict(previous['source_tool_hashes'])
    for name, expected in bindings.items():
        if sha(ROOT/name) != expected:
            raise ValueError('Frozen dependency drift')
    for path in (Path(__file__), Path(candidate.__file__),
                 ROOT/'evaluation/test_display_first_20261011.py',
                 ROOT/'development/converged_display_first_candidate_20261011/README.md'):
        bindings[str(path.relative_to(ROOT))] = sha(path)
    for filename in ('gat_mil.pt', 'split.json', 'report.json', 'audit.json'):
        path = model_dir/filename
        bindings[str(path.relative_to(ROOT))] = sha(path)
    cfg = base.Settings()
    manifest = dict(settings=asdict(cfg), dataset_sha256=ref['dataset_sha256'],
        source_tool_hashes=bindings, reference_manifest_sha256=sha(ref_path),
        model_sha256=scorer.model_sha256, rows=254, planned_first_requests=508,
        paid_api_calls=0, quality_evaluation=False, safety_net_mode='shadow',
        comparison='expanded frozen v2 vs display-first SRC only')
    output.mkdir(parents=True)
    (output/'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf8')
    rows, blocked_count = {'control': [], 'candidate': []}, [0]
    def blocked(*args, **kwargs):
        blocked_count[0] += 1
        raise RuntimeError('External connections prohibited')
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(socket.socket, 'connect', blocked))
        stack.enter_context(patch.object(socket, 'create_connection', blocked))
        handles = {arm: stack.enter_context((output/(arm+'_rows.jsonl')).open('x', encoding='utf8')) for arm in rows}
        for index, sample in enumerate(samples):
            code = dataset[sample['idx']]['input']
            error = None
            try:
                dot = Path(sample['cache_path'])/'export/export.dot'
                if (sha(dot) != sample['cpg_sha256'] or sha(sample['source_path']) != sample['wrapped_source_sha256'] or
                        hashlib.sha256(code.encode()).hexdigest() != sample['source_sha256']):
                    raise ValueError('Source/graph drift')
                with contextlib.redirect_stdout(io.StringIO()):
                    graph = load_graph(str(dot))
                offset = source_line_offset(code, Path(sample['source_path']).read_text(encoding='utf8'))
                scores = scorer(graph, code)
            except Exception as exc:
                error = repr(exc)
            for arm, run in (('control', base.run), ('candidate', candidate.run)):
                row = dict(idx=sample['idx'], source_sha256=sample['source_sha256'], group_id=sample['group_id'])
                calls = []
                try:
                    if error:
                        raise ValueError(error)
                    def invoke(**request):
                        calls.append(request)
                        return dict(text='{"verdict":"Uncertain","action":"Stop"}',
                            finish_reason='stop', model='offline-mock', usage=None)
                    result = run(graph, code, offset, lambda g, s: scores, invoke, cfg)
                    if len(calls) != 1:
                        raise ValueError('Unexpected mock count')
                    row.update(result=result, diagnostics=diagnostics(result, graph), error=None)
                except Exception as exc:
                    row['error'] = repr(exc)
                row['actual_mock_requests'] = len(calls)
                rows[arm].append(row)
                handles[arm].write(json.dumps(row, ensure_ascii=False)+'\n')
                handles[arm].flush()
            if (index+1) % 25 == 0 or index == 253:
                print(f'paired {index+1}/254', flush=True)
    report = dict(rows=254, planned_first_requests=508,
        actual_mock_requests=sum(r['actual_mock_requests'] for rr in rows.values() for r in rr),
        blocked_external_attempts=blocked_count[0], paid_api_calls=0, arms={}, audits={}, changed_src=0)
    errors = sum(bool(r['error']) for rr in rows.values() for r in rr)
    report['errors'] = errors
    for arm, rr in rows.items():
        good = [r for r in rr if not r['error']]
        report['arms'][arm] = {key: sum(r['diagnostics'][key] for r in good) for key in good[0]['diagnostics']} if good else {}
        folder = output/arm
        folder.mkdir()
        (folder/'control').mkdir()
        (folder/'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf8')
        (folder/'candidate_rows.jsonl').write_text(''.join(json.dumps(r, ensure_ascii=False)+'\n' for r in rr), encoding='utf8')
        (folder/'control/rows.jsonl').write_text(''.join(json.dumps(r, ensure_ascii=False)+'\n' for r in rows['control']), encoding='utf8')
        (folder/'report.json').write_text(json.dumps({'pass': not errors and not blocked_count[0]}), encoding='utf8')
        if not errors and not blocked_count[0]:
            report['audits'][arm] = audit(folder)
    if not errors:
        report['changed_src'] = sum(validate_pair(l['result'], r['result']) for l, r in zip(rows['control'], rows['candidate']))
    report['pass'] = (not errors and not blocked_count[0] and report['actual_mock_requests'] == 508 and
        len(report['audits']) == 2 and report['arms']['candidate']['empty_src'] <= report['arms']['control']['empty_src'])
    if any(sha(ROOT/name) != expected for name, expected in bindings.items()):
        raise ValueError('Frozen source/model drift')
    verify_foundation()
    (output/'report.json').write_text(json.dumps(report, indent=2), encoding='utf8')
    print(json.dumps(report, indent=2), flush=True)
    if not report['pass']:
        raise SystemExit('Engineering gate failed; preserve all rows')


if __name__ == '__main__':
    main()
