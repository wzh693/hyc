"""Entire local SVEN, actual mock requests, no API; new files only."""
import argparse
from collections import Counter
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
BASE = ROOT/'baselines/type_coverage_reconstructed_20261008/baseline.json'
REFERENCE = ROOT/'output/sven_complete_src_eval_20261008'
SOURCES = {'control': ROOT/'development/type_coverage_reconstructed_20261008/src',
           'display': ROOT/'development/graph_display_candidate_20261009/src'}


def read(path): return json.loads(Path(path).read_text(encoding='utf-8-sig'))
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def digest(value): return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def prepare():
    base, old = read(BASE), read(REFERENCE/'manifest.json')
    if sha(old['dataset']) != old['dataset_sha256']: raise ValueError('Dataset changed')
    data = read(old['dataset'])
    if len(data) != 254 or {s['idx'] for s in old['samples']} != set(range(254)): raise ValueError('Full254 scope required')
    if len(old['samples']) != 254: raise ValueError('Repeated ID')
    roots = [(SOURCES['control'], base['code_hashes']), (Path(base['frozen_source']), base['code_hashes']),
             (ROOT, base['preserved_repaired_code_hashes']),
             (ROOT/'releases/type_coverage_reconstructed_20261008/src', base['code_hashes'])]
    for root, hashes in roots:
        for name, expected in hashes.items():
            if sha(root/name) != expected: raise ValueError('Preserved source changed: '+str(root/name))
    candidate = {name: sha(SOURCES['display']/name) for name in base['code_hashes']}
    changes = {n.replace('\\', '/') for n, h in candidate.items() if h != base['code_hashes'][n]}
    if changes != {'retrieval/retrieve_topk.py'}: raise ValueError('Candidate must change one module')
    inventory = {p.relative_to(SOURCES['display']).as_posix() for p in SOURCES['display'].rglob('*.py')}
    if inventory != {n.replace('\\', '/') for n in candidate}: raise ValueError('Unexpected candidate files')
    for sample in old['samples']:
        if sha(sample['source_path']) != sample['wrapped_source_sha256'] or sha(Path(sample['cache_path'])/'export/export.dot') != sample['cpg_sha256']:
            raise ValueError('Input source/CPG changed')
        if hashlib.sha256(data[sample['idx']]['input'].encode()).hexdigest() != sample['source_sha256']:
            raise ValueError('Dataset source changed')
    tools = ['evaluation/preflight_graph_display.py', 'evaluation/verify_graph_display.py',
             'evaluation/test_graph_display_candidate.py', 'evaluation/GRAPH_DISPLAY_PROTOCOL_20261009.md',
             'evaluation/audit_graph_read_evidence.py', 'evaluation/audit_type_coverage_baseline.py']
    return dict(dataset=old['dataset'], dataset_sha256=old['dataset_sha256'], samples=old['samples'],
                source_hashes={'control': base['code_hashes'], 'display': candidate}, settings=base['settings'],
                tooling_hashes={n: sha(ROOT/n) for n in tools}, source_roots={k: str(v) for k,v in SOURCES.items()},
                reference_manifest_sha256=sha(REFERENCE/'manifest.json'), planned_rows=254, planned_requests=508,
                new_api_calls=0, independent_quality_test=False), data


def graph_hash(graph):
    return digest(dict(nodes=sorted(((str(n), attrs) for n, attrs in graph.nodes(data=True)), key=lambda x:x[0]),
                       edges=sorted(((str(a), str(b), str(k), attrs) for a,b,k,attrs in graph.edges(keys=True,data=True)),
                                    key=lambda x:x[:3])))


def worker(output, profile, indices):
    manifest, data = prepare()
    os.environ.update(manifest['settings']); os.environ['OPENAI_API_KEY'] = 'offline-not-a-key'
    sys.dont_write_bytecode = True; sys.path.insert(0, str(SOURCES[profile]))
    pipeline = importlib.import_module('graph.pipeline')
    typed = importlib.import_module('linearization.typed_paths')
    api = importlib.import_module('reasoning.llm_api')
    retrieval = importlib.import_module('retrieval.retrieve_topk')
    for module in (pipeline, typed, api, retrieval):
        if not Path(module.__file__).resolve().is_relative_to(SOURCES[profile]): raise ValueError('Wrong import root')
    from evaluation.audit_graph_read_evidence import extract_facts, related_facts, survival, sections
    from evaluation.audit_type_coverage_baseline import memoized_search
    samples = {s['idx']:s for s in manifest['samples']}
    old_first = {}
    for line in (REFERENCE/'api_receipts.jsonl').read_text(encoding='utf8').splitlines():
        call = json.loads(line)
        if call['profile'] == 'control': old_first.setdefault((call['idx'],call['repeat']), call['request'])
    output.mkdir(parents=True)
    external = [0]
    def blocked(*a, **k): external[0] += 1; raise RuntimeError('Offline external access forbidden')
    cache, rows = {}, []
    re._MAXCACHE = 32768
    if hasattr(re, '_MAXCACHE2'): re._MAXCACHE2 = 16384
    with patch.object(re, 'search', memoized_search(re.search)), patch.object(api, 'create_client', blocked), \
            patch.object(socket.socket, 'connect', blocked), patch.object(socket, 'create_connection', blocked), patch('subprocess.Popen', blocked):
        for number, idx in enumerate(indices):
            sample, code = samples[idx], data[idx]['input']
            row = {k:sample[k] for k in ('idx','cwe','source_sha256','group_id')}; row['profile'] = profile
            try:
                key = (sample['source_sha256'], sample['cpg_sha256'])
                if key not in cache:
                    captured, requests = {}, []
                    original_load, original_summary = pipeline.load_graph, pipeline.summarize_graph
                    original_extract, original_loop = pipeline.extract_all_candidate_paths, pipeline.reasoning_loop
                    def capture_load(*a, **k):
                        graph = original_load(*a, **k); captured['original'] = graph; return graph
                    def capture_summary(*a, **k):
                        graph = original_summary(*a, **k); captured['compressed'] = graph; return graph
                    def capture_extract(graph, *a, **k):
                        paths = original_extract(graph, *a, **k)
                        captured.setdefault('extractions', []).append((graph, paths)); return paths
                    def capture_loop(graph, paths, function_code, fs, blocks, **kwargs):
                        captured.update(path_graph=graph, topk=paths, offset=kwargs['source_line_offset'])
                        return original_loop(graph, paths, function_code, fs, blocks, **kwargs)
                    def mock(**request):
                        requests.append(request)
                        return SimpleNamespace(model='offline-mock', usage=SimpleNamespace(total_tokens=0,prompt_tokens=0,completion_tokens=0),
                            choices=[SimpleNamespace(finish_reason='stop', message=SimpleNamespace(content='HYPOTHESIS: no vulnerability detected\nACTION: {"action":"Stop"}'))])
                    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=mock)))
                    with patch.object(pipeline,'build_cpg', return_value=str(Path(sample['cache_path'])/'export')), \
                            patch.object(pipeline,'load_graph',capture_load), patch.object(pipeline,'summarize_graph',capture_summary), \
                            patch.object(pipeline,'extract_all_candidate_paths',capture_extract), patch.object(pipeline,'reasoning_loop',capture_loop), \
                            contextlib.redirect_stdout(io.StringIO()):
                        pipeline.run_hgl_pipeline(sample['source_path'], code, sample['sample_id'], sample['cache_path'], client, 4096, return_details=True)
                    if len(requests) != 1: raise ValueError('Expected one actual mock first request')
                    graph, compressed, pg, topk = [captured[k] for k in ('original','compressed','path_graph','topk')]
                    candidates = next(p for g,p in reversed(captured['extractions']) if g is pg)
                    src, dep = sections(requests[0]['messages'][1]['content'])
                    ndep, depmax = (4,300) if min(1100,max(600,len(code)//8)) > 600 else (2,260)
                    displayed = topk[:ndep]
                    facts, updates, guards = extract_facts(code)
                    selected_updates, selected_guards = [], []
                    for fact in facts:
                        us, gs = related_facts(fact,updates,guards)
                        for u in us:
                            if u not in selected_updates: selected_updates.append(u)
                        for g in gs:
                            if g not in selected_guards: selected_guards.append(g)
                    def observed(values):
                        return [survival(v, graph, compressed, pg, candidates, topk, displayed, captured['offset'], src, dep) for v in values]
                    cache[key] = dict(request=requests[0], src=src, dep=dep, reads=observed(facts), updates=observed(selected_updates), guards=observed(selected_guards),
                                      graph_hash=graph_hash(graph), compressed_hash=graph_hash(compressed), path_graph_hash=graph_hash(pg),
                                      candidate_paths_sha256=digest(candidates), candidate_count=len(candidates), topk=topk,
                                      display_paths=displayed, display_chars=depmax, display_slots=ndep,
                                      serialized=[typed._labeled_compact_path(pg,p,max_len=depmax) for p in displayed],
                                      selection_receipt=pg.graph.get('display_selection_receipt'),
                                      all_selected_from_candidates=all(p in candidates for p in topk))
                row.update(cache[key])
                if profile == 'control' and not all(row['request'] == old_first[idx, rep] for rep in (1,2)):
                    raise ValueError('Actual control request differs from verified historical foundation')
            except Exception as exc: row['error'] = type(exc).__name__+': '+str(exc)
            rows.append(row)
            with (output/'rows.jsonl').open('a',encoding='utf8') as f: f.write(json.dumps(row,ensure_ascii=False)+'\n')
            if (number+1)%10 == 0 or number+1 == len(indices): print(f'OFFLINE {profile} {number+1}/{len(indices)} errors={sum(bool(r.get("error")) for r in rows)}',flush=True)
    after, _ = prepare()
    if after != manifest: raise ValueError('Source/tool/input drift during preflight')
    (output/'status.json').write_text(json.dumps(dict(rows=len(rows), errors=sum(bool(r.get('error')) for r in rows),
                                                   blocked_external_attempts=external[0], api_calls=0)),encoding='utf8')
    if external[0] or any(r.get('error') for r in rows): raise SystemExit('Keep failed rows; preflight incomplete')


def aggregate(rows):
    from evaluation.audit_graph_read_evidence import summarize
    by_profile = {p:[r for r in rows if r['profile']==p] for p in SOURCES}
    indexed = {(r['idx'],r['profile']):r for r in rows}
    errors, changed, selected_changed = [], 0, 0
    for idx in range(254):
        a,b = indexed[idx,'control'],indexed[idx,'display']
        if a.get('error') or b.get('error'): errors.append(dict(idx=idx,error='Pipeline failure retained')); continue
        for name in ('graph_hash','compressed_hash','path_graph_hash','candidate_paths_sha256','candidate_count','src','display_slots','display_chars'):
            if a[name]!=b[name]: errors.append(dict(idx=idx,error='Non-selection change: '+name))
        requests = [json.loads(json.dumps(r['request'])) for r in (a,b)]
        for request in requests:
            text = request['messages'][1]['content']
            prefix, rest = text.split('\n\nDEP PATHS:\n',1)
            _, suffix = rest.split('\n\nSTATE:',1)
            request['messages'][1]['content'] = prefix+'\n\nDEP PATHS:\n<dep>\n\nSTATE:'+suffix
        if requests[0]!=requests[1]: errors.append(dict(idx=idx,error='Changed non-DEP actual request'))
        changed += a['request']!=b['request']; selected_changed += a['topk']!=b['topk']
        for r in (a,b):
            if not r['all_selected_from_candidates'] or len(r['topk'])!=len(a['topk']): errors.append(dict(idx=idx,error='Candidate/TopK count mismatch'))
            if any(len(s)>r['display_chars'] for s in r['serialized']): errors.append(dict(idx=idx,error='Display budget exceeded'))
            # Verify serialized body is ACTUALLY present in the mock request.
            if any(s and s not in r['dep'] for s in r['serialized']): errors.append(dict(idx=idx,error='Selected display body not sent'))
    return dict(rows=254, mock_requests=len(rows), new_api_calls=0, independent_quality_test=False,
                actual_request_changes=changed, selected_path_changes=selected_changed, engineering_errors=errors,
                summaries={p:summarize(batch) for p,batch in by_profile.items()},
                limitations=['Lexical coverage only; not new model quality or causal evidence.',
                             'Unchanged35-character node truncation and graph decoding can hide read/update facts.',
                             'Complete lexical presence is not readable capacity, execution order or guard dominance.',
                             'Read-first preference may displace lifecycle evidence; no automatic activation.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path); parser.add_argument('--workers',type=int,default=6)
    parser.add_argument('--internal-profile',choices=list(SOURCES)); parser.add_argument('--internal-indices')
    args = parser.parse_args()
    if args.output.exists(): raise ValueError('Fresh output directory required')
    if args.internal_profile:
        if not args.internal_indices: raise ValueError('Internal shard missing IDs')
        return worker(args.output,args.internal_profile,[int(i) for i in args.internal_indices.split(',')])
    if args.internal_indices or not 1<=args.workers<=6: raise ValueError('Full scope only/workers1..6')
    manifest,_ = prepare(); args.output.mkdir(parents=True)
    (args.output/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf8')
    partitions = [list(range(254))[i::args.workers] for i in range(args.workers)]
    jobs = [(p,i,indices) for p in SOURCES for i,indices in enumerate(partitions)]
    def launch(job):
        p,i,indices=job; dest=args.output/f'{p}_{i:02d}'
        result=subprocess.run([sys.executable,'-B','-m','evaluation.preflight_graph_display','--output',str(dest.resolve()),
                               '--internal-profile',p,'--internal-indices',','.join(map(str,indices))],
                              cwd=ROOT,capture_output=True,text=True,encoding='utf8',errors='replace')
        (args.output/f'{p}_{i:02d}.log').write_text(result.stdout+'\n'+result.stderr,encoding='utf8')
        print(f'OFFLINE shard {p}/{i} completed exit={result.returncode}',flush=True)
        return result.returncode
    with ThreadPoolExecutor(max_workers=args.workers) as pool: statuses=list(pool.map(launch,jobs))
    rows=[]
    for p,i,_ in jobs:
        path=args.output/f'{p}_{i:02d}'/'rows.jsonl'
        if path.exists(): rows.extend(json.loads(line) for line in path.read_text(encoding='utf8').splitlines())
    if len(rows)!=508 or {(r['idx'],r['profile']) for r in rows}!={(i,p) for i in range(254) for p in SOURCES}:
        raise ValueError('Incomplete full dataset; shard logs preserved')
    rows.sort(key=lambda r:(r['idx'],r['profile']))
    (args.output/'rows.jsonl').write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in rows),encoding='utf8')
    report=aggregate(rows); report.update(shard_exit_codes=statuses,rows_sha256=sha(args.output/'rows.jsonl'),
        blocked_external_attempts=sum(read(args.output/f'{p}_{i:02d}'/'status.json')['blocked_external_attempts'] for p,i,_ in jobs))
    (args.output/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf8')
    after,_=prepare()
    if after!=manifest: raise ValueError('Source drift during parent preflight')
    print(json.dumps({k:report[k] for k in ('rows','mock_requests','actual_request_changes','selected_path_changes','engineering_errors','new_api_calls')},indent=2),flush=True)
    if any(statuses) or report['engineering_errors'] or report['blocked_external_attempts']: raise SystemExit('Preflight failed; preserve all artifacts')


if __name__=='__main__': main()
