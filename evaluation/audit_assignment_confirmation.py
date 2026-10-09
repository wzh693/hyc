"""Offline complete-result audit and predeclared gate; never calls a model."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
from evaluation.check_assignment_evidence import compare_prompts
from evaluation.evaluate_wiring_quality import score


def audit(run,shadow):
    manifest=json.loads((run/'manifest.json').read_text(encoding='utf8'))
    report=json.loads((run/'report.json').read_text(encoding='utf8'))
    sh=json.loads((shadow/'report.json').read_text(encoding='utf8'))
    root=Path(__file__).resolve().parents[1]
    for name,digest in manifest['code_hashes'].items():
        if hashlib.sha256((root/name).read_bytes()).hexdigest()!=digest:raise ValueError('Code changed: '+name)
    if sh['code_hashes']!=manifest['code_hashes'] or sh['selection_sha256']!=manifest['selection_manifest_sha256']:
        raise ValueError('Shadow not from frozen code/selection')
    rows=[json.loads(x) for x in (run/'results.jsonl').read_text(encoding='utf8').splitlines()]
    calls=[json.loads(x) for x in (run/'api_receipts.jsonl').read_text(encoding='utf8').splitlines()]
    profiles=('control','assignment_evidence')
    expected={(s['sample_id'],p,r) for s in manifest['samples'] for p in profiles for r in (1,2)}
    indexed={(x['sample_id'],x['profile'],x['repeat']):x for x in rows}
    if len(rows)!=len(indexed) or set(indexed)!=expected:raise ValueError('Scheduled row mismatch')
    successful=defaultdict(list)
    for call in calls:
        if not call.get('error'):successful[call['sample_id'],call['profile'],call['repeat']].append(call)
    for key,row in indexed.items():
        trace=row.get('arbitrate',{}).get('reasoning_trace',[])
        if [x['answer'] for x in trace]!=[x['answer'] for x in successful[key]]:
            raise ValueError('Trace/receipt mismatch')
    input_checks={}
    for repeat in (1,2):
        checks=[]
        for sample in manifest['samples']:
            sid=sample['sample_id'];pair=[successful[sid,p,repeat] for p in profiles]
            if not all(pair):continue
            requests=[p[0]['request'] for p in pair]
            if requests[0]['messages'][0]!=requests[1]['messages'][0]:raise ValueError('System prompt differs')
            if {k:v for k,v in requests[0].items() if k!='messages'}!={k:v for k,v in requests[1].items() if k!='messages'}:
                raise ValueError('Request parameters differ')
            checks.append(dict(sample_id=sid,**compare_prompts(*(r['messages'][1]['content'] for r in requests))))
        input_checks[f'r{repeat}']={'compared':len(checks),'changed':sum(c['changed'] for c in checks),
            'prediction_disagreements_on_unchanged_input':sum(
                not c['changed'] and indexed[c['sample_id'],'control',repeat].get('prediction')!=
                indexed[c['sample_id'],'assignment_evidence',repeat].get('prediction') for c in checks)}
    metrics={}
    for p in profiles:
        for r in (1,2):
            batch=[indexed[s['sample_id'],p,r] for s in manifest['samples']]
            m=score(batch)
            if m!=report['metrics'][f'{p}/r{r}']:raise ValueError('Metric mismatch')
            tp,tn,fp,fn=(m[k] for k in ('tp','tn','fp_including_abstentions','fn_including_abstentions'))
            denom=((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))**.5
            metrics[f'{p}/r{r}']={**m,'mcc':(tp*tn-fp*fn)/denom if denom else 0,
                'balanced_accuracy':.5*(tp/(tp+fn)+tn/(tn+fp)) if tp+fn and tn+fp else 0,
                'tokens_per_scheduled':m['total_tokens']/m['n'] if m['n'] else 0}
    positives=sum(s['target']==1 for s in manifest['samples']);n=len(manifest['samples'])
    positive_acc=positives/n;positive_f1=2*positives/(n+positives)
    cand=[metrics[f'assignment_evidence/r{r}'] for r in (1,2)]
    ctrl=[metrics[f'control/r{r}'] for r in (1,2)]
    ci=report['paired_group_intervals']['assignment_evidence-vs-control']
    gates={'quality_above_60_both_repeats':all(m['f1']>.6 and m['accuracy']>.6 for m in cand),
        'beats_constant_accuracy_and_positive_mcc':all(m['accuracy']>positive_acc and m['mcc']>0 for m in cand),
        'no_negative_point_quality_delta':all(a['f1']>=b['f1'] and a['accuracy']>=b['accuracy'] for a,b in zip(cand,ctrl)),
        'primary_intervals':min(ci['group_delta_f1_ci95'][0],ci['group_delta_accuracy_ci95'][0])>=0 and
                            max(ci['group_delta_f1_ci95'][0],ci['group_delta_accuracy_ci95'][0])>0,
        'no_aggregate_returned_token_increase':all(a['total_tokens']<=b['total_tokens'] for a,b in zip(cand,ctrl)),
        'documented_input_change':all(x['changed']>0 for x in input_checks.values())}
    return {'metrics':metrics,'always_positive':{'f1':positive_f1,'accuracy':positive_acc},
            'always_negative':{'f1':0,'accuracy':1-positive_acc},'input_checks':input_checks,
            'gates':gates,'eligible_for_separate_validation':all(gates.values()),
            'actual_invocations':len(calls),'failed_invocations':sum(bool(c.get('error')) for c in calls),
            'unknown_usage_invocations':sum(not c.get('usage_known',False) for c in calls),
            'api_calls_by_audit':0,'prediction_changes':0,'auto_promoted':False}


def main():
    p=argparse.ArgumentParser();p.add_argument('run',type=Path);p.add_argument('shadow',type=Path)
    args=p.parse_args();result=audit(args.run,args.shadow)
    with (args.run/'assignment_audit.json').open('x',encoding='utf8') as f:json.dump(result,f,indent=2)
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
