"""Full254 paired actual mock preflight. No real client or quality metrics."""
import argparse
import contextlib
from dataclasses import asdict
import hashlib
import json
import io
from pathlib import Path
import socket
import subprocess
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--internal-control', action='store_true')
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('Fresh output required; old failures retained')
    if args.internal_control:
        from evaluation.preflight_graph_display import worker
        return worker(args.output, 'control', list(range(254)))
    from . import architecture as a
    import torch
    torch.set_num_threads(2)
    from graph.load_graph import load_graph
    from linearization.source_mapping import source_line_offset
    from evaluation.test_graph_guided_foundation import verify_foundation
    verify_foundation()
    old_path = ROOT/'output/sven_complete_src_eval_20261008/manifest.json'
    old = read(old_path)
    dataset = read(old['dataset'])
    samples = old['samples']
    if len(dataset) != 254 or len(samples) != 254 or {s['idx'] for s in samples} != set(range(254)):
        raise ValueError('Entire local254 required')
    if sha(old['dataset']) != old['dataset_sha256']:
        raise ValueError('Dataset drift')
    model_dir = ROOT/'learning/model/gat_expanded_beta0_20261005'
    # Fixed by provenance (largest existing grouped development model), not SVEN score.
    scorer = a.SharedGATScorer(model_dir/'gat_mil.pt', model_dir/'split.json')
    cfg = a.Settings()
    tools = [Path(__file__), Path(a.__file__), Path(a.__file__).with_name('test_architecture.py'),
             Path(a.__file__).with_name('audit_offline.py'),
             ROOT/'learning/gat_model.py', ROOT/'learning/features.py', ROOT/'graph/load_graph.py',
             ROOT/'linearization/backward_slice.py', ROOT/'linearization/source_mapping.py',
             ROOT/'planning/observed_state.py', ROOT/'planning/state_memory.py', ROOT/'config.py']
    hashes = {str(p.relative_to(ROOT)): sha(p) for p in tools}
    manifest = dict(settings=asdict(cfg), model_sha256=scorer.model_sha256,
        split_sha256=sha(model_dir/'split.json'), dataset_sha256=old['dataset_sha256'],
        reference_manifest_sha256=sha(old_path), source_tool_hashes=hashes,
        rows=254, planned_first_requests=508, paid_api_calls=0,
        safety_net_mode='shadow; uncalibrated', quality_evaluation=False,
        model_limitations='43 manual features; entropy beta0; failed previous bag calibration')
    args.output.mkdir(parents=True)
    (args.output/'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf8')
    blocked_calls = [0]
    def blocked(*args, **kwargs):
        blocked_calls[0] += 1
        raise RuntimeError('Offline external access prohibited')
    rows, cache = [], {}
    with patch.object(socket.socket, 'connect', blocked), patch.object(socket, 'create_connection', blocked):
        with (args.output/'candidate_rows.jsonl').open('x', encoding='utf8') as handle:
            for i, sample in enumerate(sorted(samples, key=lambda s: s['idx'])):
                row = dict(idx=sample['idx'], source_sha256=sample['source_sha256'],
                           group_id=sample['group_id'])
                try:
                    code = dataset[sample['idx']]['input']
                    dot = Path(sample['cache_path'])/'export/export.dot'
                    if (sha(dot) != sample['cpg_sha256'] or
                            sha(sample['source_path']) != sample['wrapped_source_sha256'] or
                            hashlib.sha256(code.encode()).hexdigest() != sample['source_sha256']):
                        raise ValueError('Source/graph drift')
                    key = (sample['source_sha256'], sample['cpg_sha256'])
                    if key not in cache:
                        with contextlib.redirect_stdout(io.StringIO()):
                            cache[key] = (load_graph(str(dot)), None)
                    graph, scores = cache[key]
                    if scores is None:
                        scores = scorer(graph, code)
                        cache[key] = (graph, scores)
                    calls = []
                    def invoke(**request):
                        calls.append(request)
                        return dict(text='{"verdict":"Uncertain","reason":"offline fixture","action":"Stop"}',
                                    finish_reason='stop', model='offline-mock', usage=None)
                    offset = source_line_offset(code, Path(sample['source_path']).read_text(encoding='utf8'))
                    result = a.run(graph, code, offset, lambda g, s: scores, invoke, cfg)
                    if len(calls) != 1 or result['security_net']['mode'] != 'shadow':
                        raise ValueError('Unexpected preflight call/override')
                    row.update(result=result, actual_mock_requests=len(calls), error=None)
                except Exception as exc:
                    row.update(error=f'{type(exc).__name__}: {exc}', actual_mock_requests=0)
                rows.append(row)
                handle.write(json.dumps(row, ensure_ascii=False)+'\n')
                handle.flush()
                if (i+1) % 25 == 0 or i == 253:
                    print(f'candidate {i+1}/254, errors={sum(bool(r["error"]) for r in rows)}', flush=True)
    # Separate process avoids mixing baseline and candidate module imports.
    baseline = subprocess.run([sys.executable, '-B', '-m',
        'development.converged_graph_candidate_20261010.run_offline', '--output',
        str((args.output/'control').resolve()), '--internal-control'], cwd=ROOT,
        capture_output=True, text=True, encoding='utf8', errors='replace')
    (args.output/'control.log').write_text(baseline.stdout+'\n'+baseline.stderr, encoding='utf8')
    control_file = args.output/'control/rows.jsonl'
    controls = [json.loads(line) for line in control_file.read_text(encoding='utf8').splitlines()] if control_file.exists() else []
    complete = (len(controls) == 254 and {r['idx'] for r in controls} == set(range(254)))
    report = dict(candidate_rows=len(rows), control_rows=len(controls), full_scope=complete,
        candidate_errors=sum(bool(r['error']) for r in rows),
        control_errors=sum(bool(r.get('error')) for r in controls), control_exit=baseline.returncode,
        actual_candidate_mock_requests=sum(r['actual_mock_requests'] for r in rows),
        unique_graph_model_forwards=scorer.calls, blocked_external_attempts=blocked_calls[0],
        paid_api_calls=0, quality_metrics=None, calibrated_security_net=False,
        empty_src=sum(not r['result']['trace'][0]['evidence']['source_lines'] for r in rows if not r['error']),
        empty_paths=sum(not r['result']['trace'][0]['evidence']['displayed_paths'] for r in rows if not r['error']))
    if complete:
        by_idx = {r['idx']: r for r in controls}
        report['changed_first_messages'] = sum(r['result']['trace'][0]['request']['messages'] !=
            by_idx[r['idx']]['request']['messages'] for r in rows if not r['error'] and not by_idx[r['idx']].get('error'))
    report['pass'] = complete and not any(report[k] for k in
        ('candidate_errors', 'control_errors', 'control_exit', 'blocked_external_attempts'))
    if any(sha(ROOT/name) != expected for name, expected in hashes.items()):
        raise ValueError('Tool/source drift; preserve run')
    verify_foundation()
    (args.output/'report.json').write_text(json.dumps(report, indent=2), encoding='utf8')
    print(json.dumps(report, indent=2), flush=True)
    if not report['pass']:
        raise SystemExit('Engineering preflight failed; all rows retained')


if __name__ == '__main__':
    main()
