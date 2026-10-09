"""Read completed frozen factorial results; never alter prediction settings."""
import argparse
import hashlib
import json
from pathlib import Path
from evaluation.evaluate_wiring_quality import score


def analyze(directory):
    manifest=json.loads((directory/'manifest.json').read_text(encoding='utf-8'))
    report=json.loads((directory/'report.json').read_text(encoding='utf-8'))
    samples=manifest['samples']
    trivial={name:score([{'target':s['target'],'prediction':prediction} for s in samples])
             for name,prediction in (('always_positive',1),('always_negative',0))}
    control=report['metrics']['control/r1']
    completed=[json.loads(line) for line in (directory/'results.jsonl').read_text(encoding='utf-8').splitlines()]
    safety={}
    for name in report['metrics']:
        profile,repeat_text=name.split('/r');repeat=int(repeat_text)
        batch=[r for r in completed if r['profile']==profile and r['repeat']==repeat]
        net_off=[dict(r,prediction=r.get('arbitrate',{}).get('main_pred')) for r in batch]
        metric=score(net_off)
        safety[name]={'fixed_llm_net_off_metrics':metric,
            'flips':sum(r.get('prediction')!=r.get('arbitrate',{}).get('main_pred') for r in batch),
            'delta_f1_with_net':report['metrics'][name]['f1']-metric['f1'],
            'delta_accuracy_with_net':report['metrics'][name]['accuracy']-metric['accuracy'],
            'scope':'Fixed-answer replay of outer source verifier only, matching no_safety_net ablation; not an independent model rerun.'}
    first_requests={}
    first_payloads={}
    first_answers={}
    first_usage={}
    for line in (directory/'api_receipts.jsonl').read_text(encoding='utf-8').splitlines():
        receipt=json.loads(line)
        key=(receipt['sample_id'],receipt['profile'],receipt['repeat'])
        first_requests.setdefault(key,receipt['request']['messages'])
        first_payloads.setdefault(key,receipt['request'])
        if not receipt.get('error'):
            first_answers.setdefault(key,receipt.get('answer'))
            first_usage.setdefault(key,receipt.get('prompt_tokens'))
    def request_hash(key,user_only=False):
        messages=first_requests.get(key)
        if messages is None:return None
        if user_only:messages=[m for m in messages if m['role']=='user']
        return hashlib.sha256(json.dumps(messages,sort_keys=True).encode()).hexdigest()
    prompt_audit={'repeat_first_request_changes':{
        profile:sum(request_hash((s['sample_id'],profile,1)) !=
                    request_hash((s['sample_id'],profile,2)) for s in samples)
        for profile in manifest['repeat_profiles']},
        'contract_vs_control_first_user_prompt_changes':sum(
            request_hash((s['sample_id'],'control',1),True) !=
            request_hash((s['sample_id'],'contract_only',1),True) for s in samples)
            if 'contract_only' in manifest['profiles'] else None}
    if 'grouped_slice' in manifest['profiles']:
        prompt_audit['grouped_vs_plain_first_request_changes'] = {
            f'r{repeat}':sum(request_hash((s['sample_id'],'slice_only',repeat)) !=
                            request_hash((s['sample_id'],'grouped_slice',repeat)) for s in samples)
            for repeat in (1,2)}
        prompt_audit['available_first_requests'] = {
            name:sum((s['sample_id'],profile,int(repeat)) in first_requests for s in samples)
            for name in report['metrics'] for profile,repeat in [name.split('/r')]}
    grouped_mechanism = {}
    for name in report['metrics']:
        profile,repeat_text=name.split('/r')
        if profile!='grouped_slice':continue
        batch=[r for r in completed if r['profile']==profile and r['repeat']==int(repeat_text)]
        audits=[r.get('arbitrate',{}).get('module_audit',{}).get('backward_slice',{}) for r in batch]
        # Pipeline keeps reasoning module receipts under arbitrate; inspect without
        # silently treating absent receipts as a verified mechanism execution.
        groups=[g for a in audits for g in a.get('atomic_groups',{}).get('groups',[])]
        grouped_mechanism[name]={'rows_with_group_audit':sum(a.get('atomic_groups',{}).get('enabled',False) for a in audits),
            'groups':len(groups),'admitted_groups':sum(g['admitted'] for g in groups),
            'admitted_with_control_and_exit':sum(g['admitted'] and bool(g['control_node_ids']) and bool(g['exit_node_ids']) for g in groups)}
    paired_prompt_diagnostics = {}
    indexed={(r['sample_id'],r['profile'],r['repeat']):r for r in completed}
    def compare_prompts(left,right):
        pairs=[(a,b) for s in samples
               for a,b in [((s['sample_id'],*left),(s['sample_id'],*right))]
               if a in first_requests and b in first_requests]
        identical=[(a,b) for a,b in pairs if request_hash(a)==request_hash(b)]
        differing=[(a,b) for a,b in identical
                   if indexed[a].get('prediction')!=indexed[b].get('prediction')]
        usage_pairs=[(a,b) for a,b in pairs
                     if first_usage.get(a) is not None and first_usage.get(b) is not None]
        return {'evaluable_first_request_pairs':len(pairs),
            'identical_first_messages':len(identical),
            'identical_complete_first_requests':sum(first_payloads[a]==first_payloads[b] for a,b in pairs),
            'changed_first_messages':len(pairs)-len(identical),
            'identical_messages_prediction_disagreements':len(differing),
            'identical_messages_first_answer_disagreements':sum(
                first_answers[a]!=first_answers[b] for a,b in identical
                if a in first_answers and b in first_answers),
            'identical_messages_prediction_disagreements_both_single_step':sum(
                len(indexed[a].get('arbitrate',{}).get('reasoning_trace',[]))==1 and
                len(indexed[b].get('arbitrate',{}).get('reasoning_trace',[]))==1 for a,b in differing),
            'available_first_prompt_usage_pairs':len(usage_pairs),
            'first_prompt_tokens_increased':sum(first_usage[b]>first_usage[a] for a,b in usage_pairs),
            'first_prompt_tokens_delta_total':sum(first_usage[b]-first_usage[a] for a,b in usage_pairs),
            'scope':'Descriptive fixed-input/provider sensitivity; not evidence of causal mechanism gain.'}
    for profile in manifest['repeat_profiles']:
        paired_prompt_diagnostics[f'{profile}-r2-vs-r1']=compare_prompts((profile,1),(profile,2))
    if 'grouped_slice' in manifest['profiles']:
        for repeat in (1,2):
            paired_prompt_diagnostics[f'grouped-vs-plain/r{repeat}']=compare_prompts(
                ('slice_only',repeat),('grouped_slice',repeat))
    if 'action_first' in manifest['profiles']:
        prompt_audit['action_vs_control_first_user_changes']={f'r{repeat}':sum(
            request_hash((s['sample_id'],'control',repeat),True)!=
            request_hash((s['sample_id'],'action_first',repeat),True) for s in samples) for repeat in (1,2)}
        for repeat in (1,2):
            paired_prompt_diagnostics[f'action-first-vs-control/r{repeat}']=compare_prompts(
                ('control',repeat),('action_first',repeat))
    if 'observed_state' in manifest['profiles']:
        for repeat in (1,2):
            for candidate,baseline in (('observed_state','control'),('observed_state','state_disabled'),
                                       ('state_disabled','control')):
                paired_prompt_diagnostics[f'{candidate}-vs-{baseline}/r{repeat}']=compare_prompts(
                    (baseline,repeat),(candidate,repeat))
    rows=[]
    for name,metric in report['metrics'].items():
        accounting=report['api_accounting'][name]
        mean_tokens=accounting['total_tokens']/len(samples)
        base_mean=report['api_accounting']['control/r1']['total_tokens']/len(samples)
        rows.append({'configuration':name,**metric,'mean_actual_tokens':mean_tokens,
            'token_ratio_vs_control_r1':mean_tokens/base_mean if base_mean else None,
            'truncated_calls':accounting['truncated_calls'],
            'actual_invocations':accounting['invocations'],
            'exceeds_60_both':metric['accuracy']>.6 and metric['f1']>.6,
            'beats_always_positive_both':metric['accuracy']>trivial['always_positive']['accuracy']
                                       and metric['f1']>trivial['always_positive']['f1'],
            'point_improves_control_both':metric['accuracy']>control['accuracy']
                                         and metric['f1']>control['f1']})
    return {'trivial_baselines':trivial,'configurations':rows,
            'first_prompt_integrity':prompt_audit,
            'grouped_mechanism':grouped_mechanism,
            'paired_prompt_diagnostics':paired_prompt_diagnostics,
            'source_verifier_fixed_answer_removal':safety,
            'paired_group_intervals':report['paired_group_intervals'],
            'repeat_sensitivity':report['repeat_sensitivity'],
            'auto_promoted':False,'limitations':report['limitations'],
            'note':'Point scores and token savings do not establish a robust quality gain or paper benchmark claim.'}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('directory',type=Path)
    args=parser.parse_args()
    result=analyze(args.directory)
    destination=args.directory/'analysis.json'
    if destination.exists():
        raise ValueError('Refusing to overwrite completed analysis')
    destination.write_text(json.dumps(result,indent=2),encoding='utf-8')
    for row in result['configurations']:
        print(f"{row['configuration']}: F1={row['f1']:.4f} Acc={row['accuracy']:.4f} tokens={row['mean_actual_tokens']:.1f} coverage={row['coverage']:.3f}")
    print('Trivial baselines:',json.dumps(result['trivial_baselines']))
    print('No candidate automatically promoted.')


if __name__=='__main__':main()
