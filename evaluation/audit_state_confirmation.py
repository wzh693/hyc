"""Offline verification of completed STATE comparison; never calls a model."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
from evaluation.check_observed_state_cache import compare_prompts
from evaluation.audit_grouped_completeness import response_facts
from evaluation.evaluate_wiring_quality import score


def verify_requests(control, disabled, candidate):
    for request in (control, disabled, candidate):
        if [m['role'] for m in request['messages']] != ['system','user']:
            raise ValueError('Unexpected message structure')
    params=lambda request:{k:v for k,v in request.items() if k!='messages'}
    if not params(control)==params(disabled)==params(candidate):
        raise ValueError('Non-message parameters changed')
    if not control['messages'][0]==disabled['messages'][0]==candidate['messages'][0]:
        raise ValueError('System requirements changed')
    return compare_prompts(*(request['messages'][1]['content'] for request in (control,disabled,candidate)))


def audit(run):
    root=Path(__file__).resolve().parents[1]
    manifest=json.loads((run/'manifest.json').read_text(encoding='utf-8'))
    for name,digest in manifest['code_hashes'].items():
        if hashlib.sha256((root/name).read_bytes()).hexdigest()!=digest:
            raise ValueError('Frozen prediction code changed: '+name)
    rows=[json.loads(line) for line in (run/'results.jsonl').read_text(encoding='utf-8').splitlines()]
    calls=[json.loads(line) for line in (run/'api_receipts.jsonl').read_text(encoding='utf-8').splitlines()]
    report=json.loads((run/'report.json').read_text(encoding='utf-8'))
    profiles=('control','state_disabled','observed_state')
    indexed={(r['sample_id'],r['profile'],r['repeat']):r for r in rows}
    expected={(s['sample_id'],p,rep) for s in manifest['samples'] for p in profiles for rep in (1,2)}
    if len(indexed)!=len(rows) or set(indexed)!=expected:
        raise ValueError('Incomplete/duplicate/unexpected scheduled rows')
    successful=defaultdict(list)
    for call in calls:
        key=call['sample_id'],call['profile'],call['repeat']
        if key not in expected:raise ValueError('Unexpected API receipt')
        if not call.get('error'):successful[key].append(call)
    for key,row in indexed.items():
        trace=row.get('arbitrate',{}).get('reasoning_trace',[])
        if len(trace)!=len(successful[key]) or any(t['answer']!=c['answer'] for t,c in zip(trace,successful[key])):
            raise ValueError('Trace differs from successful API receipts')
    summaries={}
    for rep in (1,2):
        for p in profiles:
            batch=[r for key,r in indexed.items() if key[1:]==(p,rep)]
            if score(batch)!=report['metrics'][f'{p}/r{rep}']:
                raise ValueError('Saved metric differs from full-denominator recomputation')
            cs=[c for key,records in successful.items() if key[1:]==(p,rep) for c in records]
            first=[records[0] for key,records in successful.items() if key[1:]==(p,rep) and records]
            facts=[response_facts(c.get('answer') or '') for c in cs]
            summaries[f'{p}/r{rep}']={
                'successful_calls':len(cs),'first_calls':len(first),
                'length_calls':sum(c.get('finish_reason')=='length' for c in cs),
                'nonempty_hypothesis':sum(f['hypothesis_present'] for f in facts),
                'complete_action_json':sum(f['action_json_complete'] for f in facts),
                'two_step_samples':sum(r.get('reasoning_steps',0)>1 for r in batch)}
    paired={}
    for rep in (1,2):
        valid=[]
        for sample in manifest['samples']:
            sid=sample['sample_id']
            first=[successful[sid,p,rep] for p in profiles]
            if not all(first):continue
            verified=verify_requests(*(records[0]['request'] for records in first))
            usages=[records[0].get('prompt_tokens') for records in first]
            valid.append(dict(sample_id=sid,**verified,prompt_tokens=dict(zip(profiles,usages))))
        usage_rows=[r for r in valid if all(v is not None for v in r['prompt_tokens'].values())]
        paired[f'r{rep}']={
            'verified_only_STATE_triplets':len(valid),'available_usage_triplets':len(usage_rows),
            'candidate_first_prompt_token_increases_vs_control':sum(
                r['prompt_tokens']['observed_state']>r['prompt_tokens']['control'] for r in usage_rows),
            'candidate_first_prompt_token_delta_vs_control':sum(
                r['prompt_tokens']['observed_state']-r['prompt_tokens']['control'] for r in usage_rows),
            'disabled_first_prompt_token_delta_vs_control':sum(
                r['prompt_tokens']['state_disabled']-r['prompt_tokens']['control'] for r in usage_rows),
            'rows':valid}
    return {'scheduled_rows':len(rows),'actual_invocations':len(calls),
        'failed_invocations':sum(bool(c.get('error')) for c in calls),
        'profiles':summaries,'actual_input_checks':paired,'api_calls_by_audit':0,'prediction_changes':0,
        'input_hashes':{name:hashlib.sha256((run/name).read_bytes()).hexdigest()
                        for name in ('manifest.json','results.jsonl','api_receipts.jsonl','report.json')},
        'limitations':['Complete ACTION and STATE provenance do not prove classification correctness.',
            'Character/byte budget compliance does not imply provider-token compliance.',
            'Failed attempts may have unknown billable usage; audit does not estimate prices.']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run',type=Path)
    args=parser.parse_args()
    result=audit(args.run)
    with (args.run/'state_audit.json').open('x',encoding='utf-8') as stream:
        json.dump(result,stream,ensure_ascii=False,indent=2)
    compact={k:v for k,v in result.items() if k!='actual_input_checks'}
    compact['actual_input_checks']={key:{k:v for k,v in data.items() if k!='rows'}
                                    for key,data in result['actual_input_checks'].items()}
    print(json.dumps(compact,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
