"""Independent120-row receipt and frozen code audit, zero external calls."""
import argparse
import json
from pathlib import Path
from evaluation.evaluate_graph_read_slice import ROOT, SOURCE, prepare, source_only_pair, summary
from evaluation.evaluate_reconstructed_llm import digest, read_json


def audit(run):
    manifest=read_json(run/'manifest.json'); fresh,data=prepare()
    if any(fresh[k]!=manifest[k] for k in fresh): raise ValueError('Current candidate/tooling/foundation freeze changed')
    for group, hashes, root in [('code_snapshot',manifest['code_hashes'],SOURCE),('tooling_snapshot',manifest['tooling_hashes'],ROOT)]:
        for name,expected in hashes.items():
            if digest(run/group/name)!=expected or digest(root/name)!=expected: raise ValueError('Snapshot mismatch')
    rows=[json.loads(s) for s in (run/'results.jsonl').read_text(encoding='utf8').splitlines()]
    calls=[json.loads(s) for s in (run/'api_receipts.jsonl').read_text(encoding='utf8').splitlines()]
    if len(rows)!=120: raise ValueError('Wrong planned denominator')
    result=summary(rows,calls,manifest)
    if result!=read_json(run/'report.json'): raise ValueError('Receipt recomputation differs')
    first={}
    for call in calls:
        first.setdefault((call['idx'],call['profile'],call['repeat']),call['request'])
        if call.get('usage_known'):
            if call['prompt_tokens']+call['completion_tokens']!=call['total_tokens']: raise ValueError('Known usage arithmetic wrong')
    pairs=0
    for s in manifest['samples']:
        for r in (1,2):
            a=first.get((s['idx'],'control',r)); b=first.get((s['idx'],'read_slice',r))
            if a and b: source_only_pair(a,b,data[s['idx']]['input']); pairs+=1
    for scope,key in [('global',None)]+[(c,c) for c in ('CWE-125','CWE-190','CWE-416')]:
        for p in manifest['profiles']:
            for r in (1,2):
                batch=[x for x in rows if x['profile']==p and x['repeat']==r and (key is None or x['cwe']==key)]
                tp=sum(x['target']==1 and x['prediction']==1 for x in batch)
                tn=sum(x['target']==0 and x['prediction']==0 for x in batch)
                fn=sum(x['target']==1 and x['prediction']!=1 for x in batch)
                fp=sum(x['target']==0 and x['prediction']!=0 for x in batch)
                m=result['metrics'][f'{p}/r{r}'] if key is None else result['by_cwe'][f'{p}/r{r}'][key]
                if [m[k] for k in ('tp','tn','fp','fn')]!=[tp,tn,fp,fn]: raise ValueError('Independent confusion arithmetic wrong')
                if m['accuracy']!=(tp+tn)/len(batch) or m['f1']!=(2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0): raise ValueError('Independent score arithmetic wrong')
    base=read_json(ROOT/'baselines/type_coverage_reconstructed_20261008/baseline.json')
    for name,expected in base['preserved_repaired_code_hashes'].items():
        if digest(ROOT/name)!=expected: raise ValueError('Root repaired source changed')
    return dict(passed=True,scheduled_results=120,actual_invocations=len(calls),first_requests_verified=len(first),
                source_only_pairs_verified=pairs,source_files_verified=47,new_api_calls=0,
                functional_gate=result['functional_gate'],exploratory_support=result['exploratory_support'],
                artifact_sha256={n:digest(run/n) for n in ('manifest.json','results.jsonl','api_receipts.jsonl','report.json')})


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--run',type=Path,required=True); args=parser.parse_args()
    result=audit(args.run); dest=args.run/'audit.json'
    if dest.exists(): raise ValueError('Do not overwrite audit')
    dest.write_text(json.dumps(result,indent=2),encoding='utf8'); print(json.dumps(result,indent=2))
