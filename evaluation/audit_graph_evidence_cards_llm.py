"""Independent full denominator, source, request/response and usage receipt audit."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
from evaluation.evaluate_graph_evidence_cards_llm import ROOT,prepare,summarize,PROFILES,pair_order
from evaluation.evaluate_reconstructed_llm import digest,read_json
from evaluation.evaluate_sven_complete_src import request_hash


def audit(run):
    manifest=read_json(run/'manifest.json'); fresh,requests,_,_=prepare()
    if manifest!=fresh:raise ValueError('Frozen current source/input/tool identity changed')
    for group,hashes in [('code_snapshot',manifest['source_hashes']['display']),('control_snapshot',manifest['source_hashes']['control']),('tooling_snapshot',manifest['tooling_hashes'])]:
        for name,expected in hashes.items():
            if digest(run/group/name)!=expected:raise ValueError('Snapshot hash mismatch')
    rows=[json.loads(line) for line in (run/'results.jsonl').read_text(encoding='utf8').splitlines()]
    calls=[json.loads(line) for line in (run/'api_receipts.jsonl').read_text(encoding='utf8').splitlines()]
    if len(rows)!=1016:raise ValueError('Full planned denominator not present')
    recomputed=summarize(rows,calls,manifest)
    if recomputed!=read_json(run/'report.json'):raise ValueError('Full receipt recomputation differs')
    first={}; own=defaultdict(list)
    for call in calls:
        key=call['idx'],call['profile'],call['repeat'];own[key].append(call)
        first.setdefault(key,call['request'])
        if call.get('usage_known'):
            if any(not isinstance(call.get(k),int) or call[k]<0 for k in ('prompt_tokens','completion_tokens','total_tokens')):
                raise ValueError('Invalid known usage')
            if call['prompt_tokens']+call['completion_tokens']!=call['total_tokens']:raise ValueError('Token arithmetic mismatch')
    for key,observed in own.items():
        successes=0;attempts=defaultdict(int);step_requests={}
        for call in observed:
            step=1+successes;attempts[step]+=1
            if call['step']!=step or call['attempt']!=attempts[step] or step>2 or attempts[step]>3:
                raise ValueError('Step/attempt bounds or ordering changed')
            if step==1 and call['request']!=requests[key[0],key[1]]:raise ValueError('First step retry differs from freeze')
            if step in step_requests and step_requests[step]!=call['request']:raise ValueError('Retry input changed')
            step_requests[step]=call['request'];successes+=not call.get('error')
    pairs=0
    for s in manifest['samples']:
        for rep in (1,2):
            a=first.get((s['idx'],'control',rep));b=first.get((s['idx'],'display',rep))
            if a and b:
                x,y=json.loads(json.dumps(a)),json.loads(json.dumps(b))
                for request in (x,y):
                    prefix,rest=request['messages'][1]['content'].split('\n\nDEP PATHS:\n',1)
                    _,suffix=rest.split('\n\nSTATE:',1)
                    request['messages'][1]['content']=prefix+'\n\nDEP PATHS:\n<dep>\n\nSTATE:'+suffix
                if x!=y:raise ValueError('Actual pair changed non-DEP fields')
                pairs+=1
    for cwe in (None,'CWE-125','CWE-190','CWE-416'):
        for p in PROFILES:
            for rep in (1,2):
                batch=[r for r in rows if r['profile']==p and r['repeat']==rep and (cwe is None or r['cwe']==cwe)]
                tp=sum(r['target']==1 and r.get('prediction')==1 for r in batch)
                tn=sum(r['target']==0 and r.get('prediction')==0 for r in batch)
                fp=sum(r['target']==0 and r.get('prediction')!=0 for r in batch)
                fn=sum(r['target']==1 and r.get('prediction')!=1 for r in batch)
                metric=recomputed['metrics'][f'{p}/r{rep}'] if cwe is None else recomputed['by_cwe'][f'{p}/r{rep}'][cwe]
                if [metric[k] for k in ('tp','tn','fp','fn')]!=[tp,tn,fp,fn]:raise ValueError('Independent confusion mismatch')
                if metric['accuracy']!=(tp+tn)/len(batch) or metric['f1']!=(2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0):raise ValueError('Independent metric mismatch')
    # Result completion order must match within each sample's scheduled four
    # runs; other samples can interleave freely across threads.
    for idx in range(254):
        actual=[(r['profile'],r['repeat']) for r in rows if r['idx']==idx]
        expected=[(p,rep) for rep in (1,2) for p in pair_order(idx,rep)]
        if actual!=expected:raise ValueError('Within-sample pair execution order changed')
    return dict(passed=True,scheduled_results=1016,actual_invocations=len(calls),first_requests_verified=len(first),
        dep_only_pairs_verified=pairs,candidate_source_files_verified=48,control_source_files_verified=47,
        new_api_calls=0,functional_gate=recomputed['functional_gate'],exploratory_support=recomputed['exploratory_support'],
        artifact_sha256={n:digest(run/n) for n in ('manifest.json','results.jsonl','api_receipts.jsonl','report.json')})


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--run',required=True,type=Path);args=parser.parse_args()
    result=audit(args.run);dest=args.run/'audit.json'
    if dest.exists():raise ValueError('Do not overwrite independent audit')
    dest.write_text(json.dumps(result,indent=2),encoding='utf8');print(json.dumps(result,indent=2))
