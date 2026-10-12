"""Full paired graph-integrity request recipes. Original bad graph is retained."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
from evaluation import preflight_graph_display as shared
from evaluation.test_graph_guided_foundation import verify_foundation

ROOT=Path(__file__).resolve().parents[1]
SOURCES=dict(control=ROOT/'development/type_coverage_reconstructed_20261008/src',display=ROOT/'development/graph_integrity_candidate_20261011/src')
shared.SOURCES=SOURCES
shared.REFERENCE=ROOT/'output/graph_window_llm1016_20261011/control'


def prepare():
    base=verify_foundation()
    audit=shared.read(ROOT/'output/graph_integrity_preflight_20261011/report.json')
    if not audit['pass_invariants'] or not audit['paid_input_gate']: raise ValueError('Graph integrity input gate failed; no LLM')
    ref=shared.read(ROOT/'output/sven_complete_src_eval_20261008/manifest.json')
    data=shared.read(ref['dataset'])
    hashes={p.relative_to(SOURCES['display']).as_posix():shared.sha(p) for p in SOURCES['display'].rglob('*.py')}
    frozen=shared.read(ROOT/'output/graph_integrity_preflight_20261011/manifest.json')
    if hashes!=frozen['source_hashes'] or len(data)!=254 or shared.sha(ref['dataset'])!=ref['dataset_sha256']:
        raise ValueError('Source/dataset drift')
    tools=['evaluation/preflight_graph_integrity_20261011.py','evaluation/preflight_graph_display.py',
           'evaluation/audit_type_coverage_baseline.py','evaluation/audit_graph_read_evidence.py']
    return dict(samples=ref['samples'],settings=base['settings'],source_hashes={'control':base['code_hashes'],'display':hashes},
        tooling_hashes={n:shared.sha(ROOT/n) for n in tools},source_roots={k:str(v) for k,v in SOURCES.items()},
        dataset=ref['dataset'],dataset_sha256=ref['dataset_sha256'],planned_rows=254,
        expected_preinference_abstentions=[146],new_api_calls=0),data


shared.prepare=prepare


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--arm',choices=SOURCES)
    parser.add_argument('--indices')
    args=parser.parse_args()
    if args.output.exists() or os.environ.get('PYTHONHASHSEED')!='0': raise ValueError('Fresh output and startup seed0 required')
    if args.arm: return shared.worker(args.output,args.arm,list(map(int,args.indices.split(','))))
    if args.indices: raise ValueError('Full scope required')
    manifest,_=prepare();args.output.mkdir(parents=True)
    (args.output/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf8')
    jobs=[(arm,i,list(range(254))[i::6]) for arm in SOURCES for i in range(6)]
    def launch(job):
        arm,i,ids=job
        result=subprocess.run([sys.executable,'-B','-m','evaluation.preflight_graph_integrity_20261011',
            '--output',str((args.output/f'{arm}_{i:02d}').resolve()),'--arm',arm,'--indices',','.join(map(str,ids))],cwd=ROOT,capture_output=True,text=True,encoding='utf8',errors='replace')
        (args.output/f'{arm}_{i:02d}.log').write_text(result.stdout+'\n'+result.stderr,encoding='utf8')
        print(f'OFFLINE {arm}/{i} exit={result.returncode}',flush=True)
        return result.returncode
    with ThreadPoolExecutor(max_workers=6) as pool:statuses=list(pool.map(launch,jobs))
    rows=[]
    for arm,i,_ in jobs:
        path=args.output/f'{arm}_{i:02d}'/'rows.jsonl'
        if path.exists(): rows.extend(json.loads(s) for s in path.read_text(encoding='utf8').splitlines())
    if len(rows)!=508 or len({(r['idx'],r['profile']) for r in rows})!=508: raise ValueError('Incomplete scope; preserve failures')
    errors=[r for r in rows if r.get('error')]
    expected={(146,'display')}
    unexpected=[dict(idx=r['idx'],profile=r['profile'],error=r['error']) for r in errors
                if (r['idx'],r['profile']) not in expected or 'unusable_source_mapped_function_body' not in r['error']]
    if {(r['idx'],r['profile']) for r in errors}!=expected: unexpected.append('Unexpected missing/extra graph rejection')
    for (arm,i,ids),status in zip(jobs,statuses):
        if bool(status)!=(arm=='display' and 146 in ids): unexpected.append('Unexpected shard exit')
    indexed={(r['idx'],r['profile']):r for r in rows}
    for idx in range(254):
        if idx==146:continue
        a,b=indexed[idx,'control'],indexed[idx,'display']
        if a.get('error') or b.get('error'):continue
        for r in (a,b):
            if not r['all_selected_from_candidates']:unexpected.append('TopK not from candidates')
        if a['request']['messages'][0]!=b['request']['messages'][0] or any(a['request'][k]!=b['request'][k] for k in ('model','max_tokens','temperature')):
            unexpected.append('Unexpected output contract change')
    from evaluation.audit_graph_read_evidence import summarize
    result=dict(pass_engineering=not unexpected,rows=254,paired_recipes=508,
        expected_bad_graph_abstentions=[146],unexpected_errors=unexpected,
        actual_request_changes=sum(indexed[i,'control'].get('request')!=indexed[i,'display'].get('request') for i in range(254)),
        summaries={arm:summarize([r for r in rows if r['profile']==arm]) for arm in SOURCES},new_api_calls=0,
        limitation='Recipe cache reuse; full1016 per-result runtime mocks required before paid batch.')
    rows.sort(key=lambda r:(r['idx'],r['profile']))
    (args.output/'rows.jsonl').write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in rows),encoding='utf8')
    result['rows_sha256']=shared.sha(args.output/'rows.jsonl')
    (args.output/'report.json').write_text(json.dumps(result,indent=2),encoding='utf8')
    if prepare()[0]!=manifest:raise ValueError('Freeze drift')
    print(json.dumps({k:v for k,v in result.items() if k!='summaries'},indent=2))
    if unexpected:raise SystemExit('Input preflight failed; no paid calls')


if __name__=='__main__':main()
