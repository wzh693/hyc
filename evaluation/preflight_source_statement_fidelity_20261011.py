"""Full254 paired actual mocks: only SRC filtering may differ. Zero API."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys

from evaluation import preflight_graph_display as shared
from evaluation.test_graph_guided_foundation import verify_foundation

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {'control':ROOT/'development/type_coverage_reconstructed_20261008/src',
           'display':ROOT/'development/source_statement_fidelity_candidate_20261011/src'}
REFERENCE = ROOT/'output/graph_window_llm1016_20261011/control'
shared.SOURCES = SOURCES
shared.REFERENCE = REFERENCE


def prepare():
    base = verify_foundation()
    ref = shared.read(ROOT/'output/sven_complete_src_eval_20261008/manifest.json')
    data = shared.read(ref['dataset'])
    if len(data)!=254 or shared.sha(ref['dataset'])!=ref['dataset_sha256']:
        raise ValueError('Dataset drift/scope')
    hashes = {p.relative_to(SOURCES['display']).as_posix():shared.sha(p) for p in SOURCES['display'].rglob('*.py')}
    expected = {n.replace('\\','/'):h for n,h in base['code_hashes'].items()}
    if set(hashes)!=set(expected) or {n for n in hashes if hashes[n]!=expected[n]} != {'linearization/typed_paths.py'}:
        raise ValueError('Only one prediction file may change')
    for sample in ref['samples']:
        if shared.sha(sample['source_path'])!=sample['wrapped_source_sha256'] or shared.sha(Path(sample['cache_path'])/'export/export.dot')!=sample['cpg_sha256']:
            raise ValueError('Frozen input changed')
    if {s['idx'] for s in ref['samples']}!=set(range(254)) or len(ref['samples'])!=254:
        raise ValueError('Full254 denominator required')
    tools = [Path(__file__), ROOT/'evaluation/preflight_graph_display.py',
             ROOT/'evaluation/test_source_statement_fidelity_20261011.py',
             ROOT/'evaluation/audit_graph_read_evidence.py', ROOT/'evaluation/audit_type_coverage_baseline.py',
             ROOT/'development/source_statement_fidelity_candidate_20261011/README.md']
    return dict(samples=ref['samples'],settings=base['settings'],source_hashes={'control':expected,'display':hashes},
        tooling_hashes={p.relative_to(ROOT).as_posix():shared.sha(p) for p in tools},
        source_roots={p:str(s) for p,s in SOURCES.items()}, dataset=ref['dataset'],dataset_sha256=ref['dataset_sha256'],
        reference_receipts_sha256=shared.sha(REFERENCE/'api_receipts.jsonl'),
        rows=254,planned_mock_requests=508,paid_calls=0,quality_evaluation=False,
        candidate='SRC ordinary assignment/inc-dec/leading-dereference filter repair',PYTHONHASHSEED='0'), data


shared.prepare = prepare


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--arm',choices=SOURCES)
    parser.add_argument('--indices')
    args = parser.parse_args()
    if os.environ.get('PYTHONHASHSEED')!='0':
        raise ValueError('Startup PYTHONHASHSEED=0 required')
    if args.output.exists():
        raise ValueError('Fresh output only; preserve failed attempts')
    if args.arm:
        if not args.indices: raise ValueError('Internal IDs missing')
        return shared.worker(args.output,args.arm,list(map(int,args.indices.split(','))))
    if args.indices: raise ValueError('Full dataset only')
    manifest,_ = prepare()
    args.output.mkdir(parents=True)
    (args.output/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf8')
    jobs = [(p,i,list(range(254))[i::6]) for p in SOURCES for i in range(6)]
    def launch(job):
        arm,i,ids = job
        result = subprocess.run([sys.executable,'-B','-m','evaluation.preflight_source_statement_fidelity_20261011',
            '--output',str((args.output/f'{arm}_{i:02d}').resolve()),'--arm',arm,'--indices',','.join(map(str,ids))],
            cwd=ROOT,capture_output=True,text=True,encoding='utf8',errors='replace')
        (args.output/f'{arm}_{i:02d}.log').write_text(result.stdout+'\n'+result.stderr,encoding='utf8')
        print(f'OFFLINE {arm}/{i} exit={result.returncode}',flush=True)
        return result.returncode
    with ThreadPoolExecutor(max_workers=6) as pool:
        statuses = list(pool.map(launch,jobs))
    rows = []
    for arm,i,_ in jobs:
        path = args.output/f'{arm}_{i:02d}'/'rows.jsonl'
        if path.exists(): rows.extend(json.loads(s) for s in path.read_text(encoding='utf8').splitlines())
    errors = []
    if len(rows)!=508 or {(r['idx'],r['profile']) for r in rows}!={(i,p) for i in range(254) for p in SOURCES}:
        errors.append('Incomplete full scope')
    indexed = {(r['idx'],r['profile']):r for r in rows}
    differences = dict(changed_rows=0,read_added=0,read_lost=0,update_added=0,update_lost=0,guard_added=0,guard_lost=0)
    for idx in range(254):
        if any((idx,p) not in indexed for p in SOURCES): continue
        a,b = (indexed[idx,p] for p in SOURCES)
        if a.get('error') or b.get('error'):
            errors.append(dict(idx=idx,control=a.get('error'),candidate=b.get('error')))
            continue
        for field in ('graph_hash','compressed_hash','path_graph_hash','candidate_paths_sha256',
                      'candidate_count','topk','dep','display_paths','display_chars','display_slots'):
            if a[field]!=b[field]: errors.append(dict(idx=idx,unexpected_change=field))
        requests = [json.loads(json.dumps(r['request'])) for r in (a,b)]
        for request in requests:
            text=request['messages'][1]['content']
            if not text.startswith('SRC:\n'): raise ValueError('Unexpected input format')
            request['messages'][1]['content']='SRC:\n<masked>\n\nDEP PATHS:\n'+text.split('\n\nDEP PATHS:\n',1)[1]
        if requests[0]!=requests[1]: errors.append(dict(idx=idx,unexpected_change='non-SRC request'))
        differences['changed_rows'] += a['src']!=b['src']
        for category,name in [('reads','read'),('updates','update'),('guards','guard')]:
            def facts(row):
                return {shared.digest({k:v for k,v in fact.items() if k not in ('survival','original_node_ids','api_line_name_node_ids')}):fact['survival']['src_exact'] for fact in row[category]}
            left,right = facts(a),facts(b)
            if left.keys()!=right.keys(): errors.append(dict(idx=idx,fact_inventory=category)); continue
            differences[name+'_added'] += sum(not left[k] and right[k] for k in left)
            differences[name+'_lost'] += sum(left[k] and not right[k] for k in left)
    from evaluation.audit_graph_read_evidence import summarize
    report = dict(rows=254,actual_mock_requests=len(rows),shard_exit_codes=statuses,errors=errors,
        differences=differences,new_api_calls=0,quality_evaluation=False,
        summaries={p:summarize([r for r in rows if r['profile']==p]) for p in SOURCES},
        blocked_external_attempts=sum(shared.read(args.output/f'{p}_{i:02d}'/'status.json')['blocked_external_attempts']
            for p,i,_ in jobs if (args.output/f'{p}_{i:02d}'/'status.json').exists()))
    rows.sort(key=lambda r:(r['idx'],r['profile']))
    (args.output/'rows.jsonl').write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in rows),encoding='utf8')
    report['rows_sha256']=shared.sha(args.output/'rows.jsonl')
    report['pass']=not any(statuses) and not errors and report['blocked_external_attempts']==0
    if prepare()[0]!=manifest: raise ValueError('Freeze drift')
    (args.output/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf8')
    print(json.dumps({k:v for k,v in report.items() if k!='summaries'},ensure_ascii=False,indent=2),flush=True)
    if not report['pass']: raise SystemExit('Preflight failed; preserve all rows')


if __name__=='__main__': main()
