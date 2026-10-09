"""Offline field-order and action availability audit; no labels or API calls."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
from evaluation.audit_grouped_completeness import response_facts


def verify_pair(control,candidate):
    a,b=control['messages'],candidate['messages']
    if len(a)!=2 or len(b)!=2 or [m['role'] for m in a]!=['system','user'] or [m['role'] for m in b]!=['system','user']:
        raise ValueError('Expected one system and one user message')
    if a[1]!=b[1]:raise ValueError('User evidence changed')
    if {k:v for k,v in control.items() if k!='messages'}!={k:v for k,v in candidate.items() if k!='messages'}:
        raise ValueError('Request parameters changed')
    before,after=a[0]['content'],b[0]['content']
    if Counter(before.splitlines())!=Counter(after.splitlines()):raise ValueError('Prompt lines changed')
    if not before.index('\nREASONING:')<before.index('\nACTION:'):raise ValueError('Control order changed')
    if not after.index('\nHYPOTHESIS:')<after.index('\nACTION:')<after.index('\nREASONING:'):
        raise ValueError('Candidate order missing')
    return True


def audit(run):
    manifest=json.loads((run/'manifest.json').read_text(encoding='utf-8'))
    root=Path(__file__).resolve().parents[1]
    for name,digest in manifest['code_hashes'].items():
        if hashlib.sha256((root/name).read_bytes()).hexdigest()!=digest:raise ValueError('Frozen code changed')
    os.environ.update(manifest['settings'])
    from planning.planner import RetrievalPlanner
    planner=RetrievalPlanner()
    rows=[json.loads(line) for line in (run/'results.jsonl').read_text(encoding='utf-8').splitlines()]
    calls=[json.loads(line) for line in (run/'api_receipts.jsonl').read_text(encoding='utf-8').splitlines()]
    indexed={(r['sample_id'],r['profile'],r['repeat']):r for r in rows}
    expected={(s['sample_id'],p,rep) for s in manifest['samples'] for p in ('control','action_first') for rep in (1,2)}
    if len(indexed)!=len(rows) or set(indexed)!=expected:raise ValueError('Incomplete/duplicate results')
    successful=defaultdict(list)
    summaries={}
    for c in calls:
        if not c.get('error'):successful[c['sample_id'],c['profile'],c['repeat']].append(c)
    for key,row in indexed.items():
        trace=row.get('arbitrate',{}).get('reasoning_trace',[])
        if len(trace)!=len(successful[key]) or any(t['answer']!=c['answer'] for t,c in zip(trace,successful[key])):
            raise ValueError('Trace/call mismatch')
    for rep in (1,2):
        for profile in ('control','action_first'):
            batch=[c for key,cs in successful.items() if key[1:]==(profile,rep) for c in cs]
            first=[cs[0] for key,cs in successful.items() if key[1:]==(profile,rep) and cs]
            def facts(cs):
                measured=[response_facts(c.get('answer') or '') for c in cs]
                parsed=[planner.parse_json_action(c.get('answer') or '')[0] is not None for c in cs]
                return {'calls':len(cs),'length_calls':sum(c.get('finish_reason')=='length' for c in cs),
                    'nonempty_hypothesis':sum(m['hypothesis_present'] for m in measured),
                    'complete_action_json':sum(m['action_json_complete'] for m in measured),
                    'planner_explicit_action_available':sum(parsed),
                    'complete_action_but_planner_missed':sum(m['action_json_complete'] and not p for m,p in zip(measured,parsed))}
            summaries[f'{profile}/r{rep}']={'all_returned_calls':facts(batch),'first_returned_calls':facts(first),
                'two_step_samples':sum(r.get('reasoning_steps',0)>1 for key,r in indexed.items() if key[1:]==(profile,rep))}
    paired={}
    for rep in (1,2):
        count=0
        for s in manifest['samples']:
            a,b=successful[s['sample_id'],'control',rep],successful[s['sample_id'],'action_first',rep]
            if a and b:verify_pair(a[0]['request'],b[0]['request']);count+=1
        paired[f'r{rep}']={'verified_field_order_only_pairs':count,'scheduled_samples':len(manifest['samples'])}
    return {'profiles':summaries,'paired_input_checks':paired,'api_calls':0,'prediction_changes':0,
        'input_hashes':{name:hashlib.sha256((run/name).read_bytes()).hexdigest()
            for name in ('manifest.json','results.jsonl','api_receipts.jsonl')},
        'scope':'Action availability is not proof of classification improvement; repeats are not new samples.'}


def main():
    p=argparse.ArgumentParser();p.add_argument('run',type=Path);args=p.parse_args()
    dest=args.run/'format_audit.json'
    if dest.exists():raise ValueError('Refusing to overwrite audit')
    result=audit(args.run);dest.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
