"""Offline SVEN receipts audit/diagnosis. Never calls a model or edits predictions."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def dataset_facts(data):
    from evaluation.evaluate_sven_full_pipeline import source_groups
    exact=defaultdict(list)
    for idx,row in enumerate(data):exact[row['input']].append((idx,row['output']))
    conflicting=[];max_correct=0
    for group in exact.values():
        labels=Counter(label for _,label in group);max_correct+=max(labels.values())
        if len(labels)>1:
            conflicting.append({'indices':[i for i,_ in group],'labels':dict(labels)})
    return {'rows':len(data),'labels':dict(Counter(row['output'] for row in data)),
        'by_cwe':dict(Counter(row['cwe'] for row in data)),
        'exact_sources':len(exact),'family_union_groups':len(set(source_groups(data))),
        'conflicting_exact_sources':len(conflicting),
        'conflicting_rows':sum(len(c['indices']) for c in conflicting),
        'source_only_deterministic_accuracy_ceiling':max_correct/len(data),
        'ceiling_scope':'Same complete source -> same deterministic prediction; not an upper bound for filename/leaky metadata or stochastic predictions.',
        'conflicts':conflicting}


def historical_diagnosis(output):
    from evaluation.audit_grouped_completeness import response_facts
    dataset=ROOT/'sven_eval/data/sven_test.json'
    run=ROOT/'output/sven_full_pipeline_eval_20261006'
    manifest=json.loads((run/'manifest.json').read_text(encoding='utf8'))
    if digest(dataset)!=manifest['dataset_sha256']:raise ValueError('Historical dataset changed')
    calls=[json.loads(line) for line in (run/'api_receipts.jsonl').read_text(encoding='utf8').splitlines()]
    rows=[json.loads(line) for line in (run/'results.jsonl').read_text(encoding='utf8').splitlines()]
    facts={}
    for profile in manifest['profiles']:
        observed=[c for c in calls if c['profile']==profile]
        good=[c for c in observed if not c.get('error')]
        parsed=[response_facts(c.get('answer') or '') for c in good]
        facts[profile]={'successful_calls':len(good),'failed_calls':len(observed)-len(good),
            'length_calls':sum(c.get('finish_reason')=='length' for c in good),
            'complete_action_json':sum(p['action_json_complete'] for p in parsed),
            'nonempty_hypothesis':sum(p['hypothesis_present'] for p in parsed),
            'two_step_samples':sum((r.get('reasoning_steps') or 0)>1 for r in rows if r['profile']==profile)}
    report={'dataset':dataset_facts(json.loads(dataset.read_text(encoding='utf8'))),
        'historical_mechanism':facts,'input_sha256':{str(p.relative_to(ROOT)):digest(p)
            for p in (dataset,run/'manifest.json',run/'results.jsonl',run/'api_receipts.jsonl')},
        'api_calls':0,'prediction_changes':0,
        'interpretation':['Historical150-token outputs often truncated;512 is a hypothesis, not proven sufficient.',
            'Current semantic repairs make historical quality scores non-transferable.',
            'SVEN already development-exposed; preserve all rows and source-group clustering.',
            'If response completeness improves without tool events, early-stop/routing may be the next bottleneck.',
            'Do not enable multiple candidates or infer safety from lexical guard/API co-occurrence.']}
    output.write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf8')
    print(json.dumps({k:v for k,v in report.items() if k!='input_sha256'},indent=2))


def audit(run,output):
    manifest=json.loads((run/'manifest.json').read_text(encoding='utf8'))
    os.environ.update(manifest['settings'])
    for name,expected in manifest['code_hashes'].items():
        if digest(ROOT/name)!=expected or digest(run/'code_snapshot'/name)!=expected:
            raise ValueError('Code snapshot/current freeze mismatch: '+name)
    if digest(manifest['dataset'])!=manifest['dataset_sha256']:
        raise ValueError('Dataset changed')
    data=json.loads(Path(manifest['dataset']).read_text(encoding='utf8'))
    if len(data)!=len(manifest['samples']):raise ValueError('Dataset/schedule mismatch')
    preflight=ROOT/'output/sven_budget_preflight_20261008'
    if digest(preflight/'manifest.json')!=manifest['preflight_sha256'] or digest(preflight/'shadow.json')!=manifest['shadow_sha256']:
        raise ValueError('Preflight/shadow changed')
    shadow={s['idx']:s for s in json.loads((preflight/'shadow.json').read_text(encoding='utf8'))}
    for s in manifest['samples']:
        raw=data[s['idx']]
        if s['target']!=int(raw['output']=='VULNERABLE') or s['source_sha256']!=hashlib.sha256(raw['input'].encode()).hexdigest():
            raise ValueError('Label/source mismatch')
        if digest(s['source_path'])!=s['wrapped_sha256'] or digest(Path(s['cache_path'])/'export/export.dot')!=s['cpg_sha256']:
            raise ValueError('Prepared graph/source changed')
    rows=[json.loads(line) for line in (run/'results.jsonl').read_text(encoding='utf8').splitlines()]
    calls=[json.loads(line) for line in (run/'api_receipts.jsonl').read_text(encoding='utf8').splitlines()]
    first={};successful=defaultdict(list);all_calls=defaultdict(list)
    for c in calls:
        key=c['idx'],c['profile'],c['repeat']
        all_calls[key].append(c)
        if c['request']['max_tokens']!=manifest['profiles'][c['profile']]:raise ValueError('Wrong output ceiling')
        if c['request']['model']!=manifest['requested_model']:raise ValueError('Wrong requested model')
        if key not in first:
            s=shadow[c['idx']]
            messages=[{'role':'system','content':s['system_prompt']},{'role':'user','content':s['user_prompt']}]
            if c['request']['messages']!=messages:raise ValueError('Actual first request differs from shadow')
            first[key]=c
        if not c.get('error'):successful[key].append(c)
    sample_by_idx={s['idx']:s for s in manifest['samples']}
    for row in rows:
        key=row['idx'],row['profile'],row['repeat']
        sample=sample_by_idx[row['idx']]
        if any(row[k]!=sample[k] for k in ('target','sample_id','group_id','cwe','source_sha256')):
            raise ValueError('Result sample identity/label mismatch')
        if len(all_calls[key])>6:raise ValueError('Excess bounded attempts')
        if len(successful[key])>2:raise ValueError('Excess reasoning steps')
        module=row.get('module_audit',{})
        if module.get('learned_scoring') or module.get('graph_security_net') or module.get('backward_slice',{}).get('enabled') or module.get('output_contract') or module.get('expansion',{}).get('enabled'):
            raise ValueError('Unexpected candidate/module activation')
    from evaluation.evaluate_sven_budget import summarize
    computed=summarize(rows,calls,manifest)
    saved=json.loads((run/'report.json').read_text(encoding='utf8'));saved.pop('frozen_code_matches',None)
    if computed!=saved:raise ValueError('Recomputed report mismatch')
    facts=dataset_facts(data)
    from planning.planner import RetrievalPlanner
    planner=RetrievalPlanner();routing={}
    tool_actions={'ExpandDFG','ExpandCFG','ExpandCALL','RetrieveAlias','CheckReachability'}
    for profile in manifest['profiles']:
        for repeat in manifest['repeats']:
            batch=[r for r in rows if r['profile']==profile and r['repeat']==repeat]
            requests=0;blocked_confirm=0;blocked_selective=0;executed=0
            for row in batch:
                key=row['idx'],profile,repeat
                good=successful[key]
                action=planner.parse_json_action(good[0].get('answer') or '')[0] if good else None
                requests+=action in tool_actions
                events=row.get('tool_execution_receipts',[])
                executed+=bool(events)
                blocked_confirm+=(action in tool_actions and not events and
                    row.get('module_audit',{}).get('stop_reason')=='confirmed_first_step')
                blocked_selective+=(action in tool_actions and not events and
                    row.get('module_audit',{}).get('stop_reason')=='no_requested_gap')
            routing[f'{profile}/r{repeat}']={'first_explicit_tool_requests':requests,
                'samples_executing_tools':executed,
                'explicit_tool_requests_suppressed_by_confirm_stop':blocked_confirm,
                'explicit_tool_requests_suppressed_by_selective_stop':blocked_selective,
                'scope':'Observational routing counts, not a counterfactual quality gain.'}
    output.write_text(json.dumps({'audit_pass':True,'metrics':computed['metrics'],'gates':computed['gates'],
        'quality_support':computed['quality_support'],'dataset':facts,'routing_diagnosis':routing,'api_calls_by_audit':0,
        'prediction_changes':0,'actual_first_requests_matching_shadow':len(first),
        'actual_invocations':len(calls),'unknown_usage_invocations':sum(not c.get('usage_known') for c in calls),
        'input_sha256':{name:digest(run/name) for name in ('manifest.json','results.jsonl','api_receipts.jsonl','report.json')},
        'auto_promoted':False},indent=2,ensure_ascii=False),encoding='utf8')
    print(json.dumps({'audit_pass':True,'gates':computed['gates'],'quality_support':computed['quality_support'],
                      'actual_invocations':len(calls),'api_calls_by_audit':0},indent=2))


def main():
    p=argparse.ArgumentParser();p.add_argument('--run',type=Path);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    if args.output.exists():raise ValueError('Never overwrite an audit')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    if args.run:audit(args.run,args.output)
    else:historical_diagnosis(args.output)


if __name__=='__main__':main()
