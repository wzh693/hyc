"""Full254 foundation/candidate offline requests; no checkpoint or live client."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import contextlib
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCES = dict(control=ROOT/'development/type_coverage_reconstructed_20261008/src',
               candidate=ROOT/'development/graph_aligned_compact_candidate_20261011/src')


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def worker(output, arm, indices):
    from evaluation.test_graph_guided_foundation import verify_foundation
    base = verify_foundation()
    os.environ.update(base['settings'])
    os.environ.update(OPENAI_API_KEY='offline-not-a-key', RECORD_REASONING_TRACE='1')
    sys.path.insert(0, str(SOURCES[arm]))
    pipeline = importlib.import_module('graph.pipeline')
    api = importlib.import_module('reasoning.llm_api')
    if not Path(pipeline.__file__).resolve().is_relative_to(SOURCES[arm]):
        raise ValueError('Wrong source root')
    ref = read(ROOT/'output/sven_complete_src_eval_20261008/manifest.json')
    data = read(ref['dataset'])
    if len(data) != 254 or sha(ref['dataset']) != ref['dataset_sha256']:
        raise ValueError('Dataset drift/scope')
    samples = {s['idx']:s for s in ref['samples']}
    from evaluation.audit_type_coverage_baseline import memoized_search
    rows, external = [], [0]
    def blocked(*a, **k):
        external[0] += 1
        raise RuntimeError('Offline external operation prohibited')
    output.mkdir(parents=True)
    re._MAXCACHE = 32768
    with patch.object(re, 'search', memoized_search(re.search)), \
            patch.object(socket.socket, 'connect', blocked), patch.object(socket, 'create_connection', blocked), \
            patch.object(api, 'create_client', blocked), patch('subprocess.Popen', blocked):
        for idx in indices:
            sample, code = samples[idx], data[idx]['input']
            row = dict(idx=idx, arm=arm, error=None, actual_mock_requests=0)
            requests, captured = [], {}
            try:
                dot = Path(sample['cache_path'])/'export/export.dot'
                if (sha(dot) != sample['cpg_sha256'] or sha(sample['source_path']) != sample['wrapped_source_sha256'] or
                        hashlib.sha256(code.encode()).hexdigest() != sample['source_sha256']):
                    raise ValueError('Source/graph drift')
                original_load, original_loop = pipeline.load_graph, pipeline.reasoning_loop
                def load(*a, **k):
                    graph = original_load(*a, **k)
                    captured['original'] = graph
                    return graph
                def loop(graph, paths, *a, **k):
                    captured.update(graph=graph, topk=paths, offset=k['source_line_offset'])
                    return original_loop(graph, paths, *a, **k)
                def mock(**request):
                    requests.append(request)
                    return SimpleNamespace(model='offline-mock', usage=SimpleNamespace(total_tokens=0, prompt_tokens=0, completion_tokens=0),
                        choices=[SimpleNamespace(finish_reason='stop', message=SimpleNamespace(content=
                            'HYPOTHESIS: Uncertain\nACTION: {"action":"Stop","reason":"missing bounds"}\nREASONING: Missing bounds'))])
                client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=mock)))
                with patch.object(pipeline, 'build_cpg', return_value=str(dot.parent)), \
                        patch.object(pipeline, 'load_graph', load), patch.object(pipeline, 'reasoning_loop', loop), \
                        contextlib.redirect_stdout(io.StringIO()):
                    result = pipeline.run_hgl_pipeline(sample['source_path'], code, sample['sample_id'],
                        sample['cache_path'], client, 4096, return_details=True)
                if len(requests) != 1 or requests[0]['max_tokens'] != 150:
                    raise ValueError('Unexpected request count/cap')
                graph = captured['graph']
                row.update(request=requests[0], topk=captured['topk'], module_audit=result['module_audit'],
                    prediction=result['prediction'], graph_sha256=digest(dict(
                        nodes=sorted([(str(n), a) for n,a in graph.nodes(data=True)]),
                        edges=sorted([(str(a),str(b),str(k),d) for a,b,k,d in graph.edges(keys=True,data=True)], key=lambda e:e[:3]))))
                if arm == 'candidate':
                    if any(n == 'learning' or n.startswith('learning.') or n == 'torch' for n in sys.modules):
                        raise ValueError('Training/model module imported')
                    audit = row['module_audit']['backward_slice']
                    align = row['module_audit']['alignment']
                    nodes = {n for p in align['displayed_paths'] for n in p}
                    if set(audit['criteria_node_ids']) != nodes:
                        raise ValueError('Display/SRC mismatch')
                    text = requests[0]['messages'][1]['content']
                    src = text.split('SRC:\n',1)[1].split('\n\nDEP PATHS:',1)[0]
                    if src != '\n'.join(code.splitlines()[i-1] for i in audit['source_lines']):
                        raise ValueError('Source line mismatch')
                    dep = text.split('DEP PATHS:\n',1)[1].split('\n\nSTATE:',1)[0]
                    paths = [] if dep.startswith('  (') else [json.loads(line) for line in dep.splitlines()]
                    if [[n['id'] for n in p] for p in paths] != align['displayed_paths']:
                        raise ValueError('Displayed path mismatch')
                    for p in paths:
                        for i,n in enumerate(p):
                            attrs = graph.nodes[n['id']]
                            if n['c'] != (attrs.get('code') or '') or n['l'] != attrs.get('line_number'):
                                raise ValueError('Clipped/invented node')
                            expected = sorted({d.get('edge_type','OTHER') for d in graph.get_edge_data(p[i-1]['id'],n['id']).values()}) if i else []
                            if n['e'] != expected:
                                raise ValueError('Invented edge')
                    if len(src) > audit['char_budget'] or len(dep) > 1000:
                        raise ValueError('Budget exceeded')
                    original = captured['original']
                    seen, queue = set(nodes), list(nodes)
                    while queue and not audit['node_cap_hit']:
                        node = queue.pop(0)
                        for pred,_,attrs in original.in_edges(node, data=True):
                            if attrs.get('edge_type') in {'DFG','REACHING_DEF','CDG','CONTROL_DEPENDENCE'} and pred not in seen:
                                seen.add(pred); queue.append(pred)
                    if not audit['node_cap_hit'] and seen != set(audit['visited_node_ids']):
                        raise ValueError('Dependence closure mismatch')
                    for a,b,kind in audit['dependence_witnesses']:
                        if not any(d.get('edge_type') == kind for d in original.get_edge_data(a,b,default={}).values()):
                            raise ValueError('Invented dependence witness')
            except Exception as exc:
                row['error'] = repr(exc)
            row['actual_mock_requests'] = len(requests)
            rows.append(row)
            with (output/'rows.jsonl').open('a', encoding='utf8') as handle:
                handle.write(json.dumps(row, ensure_ascii=False)+'\n')
    (output/'status.json').write_text(json.dumps(dict(errors=sum(bool(r['error']) for r in rows),
        external_attempts=external[0], rows=len(rows))), encoding='utf8')
    if external[0] or any(r['error'] for r in rows):
        raise SystemExit('Offline shard failed; all rows retained')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--arm', choices=SOURCES)
    parser.add_argument('--indices')
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('Fresh output required')
    if os.environ.get('PYTHONHASHSEED') != '0':
        raise ValueError('Start with PYTHONHASHSEED=0')
    if args.arm:
        return worker(args.output, args.arm, list(map(int, args.indices.split(','))))
    if args.indices:
        raise ValueError('Full254 scope required')
    from evaluation.test_graph_guided_foundation import verify_foundation
    verify_foundation()
    bindings = {str(p.relative_to(ROOT)):sha(p) for root in SOURCES.values() for p in root.rglob('*.py')}
    bindings[str(Path(__file__).relative_to(ROOT))] = sha(__file__)
    args.output.mkdir(parents=True)
    manifest = dict(rows=254, planned_requests=508, source_tool_hashes=bindings,
        reference_commit='6da6852f0e670e846266a31dc0ee618dbbdb3f72', PYTHONHASHSEED='0',
        candidate='non-GAT aligned evidence + compact native output', paid_calls=0, quality_evaluation=False)
    (args.output/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf8')
    jobs = [(arm, shard, list(range(254))[shard::6]) for arm in SOURCES for shard in range(6)]
    def launch(job):
        arm, shard, indices = job
        result = subprocess.run([sys.executable,'-B','-m','evaluation.preflight_graph_aligned_compact_20261011',
            '--output',str(args.output/f'{arm}_{shard}'),'--arm',arm,'--indices',','.join(map(str,indices))],
            cwd=ROOT, capture_output=True, text=True, encoding='utf8', errors='replace')
        (args.output/f'{arm}_{shard}.log').write_text(result.stdout+'\n'+result.stderr,encoding='utf8')
        print(f'{arm}/{shard} exit={result.returncode}', flush=True)
        return result.returncode
    with ThreadPoolExecutor(max_workers=6) as pool:
        statuses = list(pool.map(launch,jobs))
    rows = [json.loads(line) for arm,shard,_ in jobs
            for line in (args.output/f'{arm}_{shard}/rows.jsonl').read_text(encoding='utf8').splitlines()]
    indexed = {(r['idx'],r['arm']):r for r in rows}
    errors = [dict(idx=r['idx'],arm=r['arm'],error=r['error']) for r in rows if r['error']]
    selection_drift = [i for i in range(254) if not any(indexed[i,a]['error'] for a in SOURCES) and
        any(indexed[i,'control'][key] != indexed[i,'candidate'][key] for key in ('topk','graph_sha256'))]
    candidate = [r for r in rows if r['arm']=='candidate' and not r['error']]
    report = dict(rows=254, retained_results=len(rows), actual_mock_requests=sum(r['actual_mock_requests'] for r in rows),
        errors=errors, selection_drift=selection_drift, shard_exit_codes=statuses, paid_calls=0, quality_evaluation=False,
        displayed_paths=sum(len(r['module_audit']['alignment']['displayed_paths']) for r in candidate),
        source_line_occurrences=sum(len(r['module_audit']['backward_slice']['source_lines']) for r in candidate),
        empty_display_rows=sum(not r['module_audit']['alignment']['displayed_paths'] for r in candidate),
        empty_source_rows=sum(not r['module_audit']['backward_slice']['source_lines'] for r in candidate),
        omitted_path_occurrences=sum(len(r['module_audit']['alignment']['omitted_paths']) for r in candidate),
        omitted_source_lines=sum(r['module_audit']['backward_slice']['omitted_lines'] for r in candidate),
        node_cap_rows=sum(r['module_audit']['backward_slice']['node_cap_hit'] for r in candidate))
    report['pass'] = (not any(statuses) and not errors and not selection_drift and len(rows)==508 and
        len(indexed)==508 and report['actual_mock_requests']==508 and all(sha(ROOT/n)==h for n,h in bindings.items()))
    (args.output/'report.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    verify_foundation()
    print(json.dumps(report,indent=2),flush=True)
    if not report['pass']:
        raise SystemExit('Full offline gate failed')


if __name__ == '__main__':
    main()
