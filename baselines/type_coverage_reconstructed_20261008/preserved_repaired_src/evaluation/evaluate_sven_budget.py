"""Frozen full-SVEN replay: request budget only, no production default edits."""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import contextlib
import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import random
import shutil
import sys
import threading
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PROFILES = {'control': 150, 'output512': 512}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def code_hashes():
    from evaluation.evaluate_wiring_quality import prediction_code_hashes
    result = prediction_code_hashes()
    for name in ('evaluation/evaluate_sven_budget.py',
                 'evaluation/evaluate_sven_full_pipeline.py',
                 'evaluation/audit_grouped_completeness.py',
                 'sven_eval/data/wrap_slice.py'):
        result[name] = digest(ROOT/name)
    return result


def budget_request(request, ceiling):
    if request.get('max_tokens') != 150 or ceiling not in (150, 512):
        raise ValueError('Unexpected base request/experimental ceiling')
    return dict(request, max_tokens=ceiling)


def compare_requests(control, candidate):
    if control.get('max_tokens') != 150 or candidate.get('max_tokens') != 512:
        raise ValueError('Budget contrast missing')
    if {k:v for k,v in control.items() if k!='max_tokens'} != {
            k:v for k,v in candidate.items() if k!='max_tokens'}:
        raise ValueError('Non-budget first request changed')


def extended_score(rows):
    from evaluation.evaluate_wiring_quality import score
    result = score(rows)
    tp, tn, fp, fn = [result[k] for k in (
        'tp', 'tn', 'fp_including_abstentions', 'fn_including_abstentions')]
    denom = (tp+fp)*(tp+fn)*(tn+fp)*(tn+fn)
    result.update(mcc=(tp*tn-fp*fn)/math.sqrt(denom) if denom else 0,
                  balanced_accuracy=((tp/(tp+fn) if tp+fn else 0)+
                                     (tn/(tn+fp) if tn+fp else 0))/2,
                  tokens_per_scheduled=result['total_tokens']/len(rows) if rows else 0)
    return result


def summarize(rows, calls, manifest, bootstrap=2000):
    from evaluation.audit_grouped_completeness import response_facts
    profiles = manifest['profiles']
    repeats = manifest['repeats']
    samples = manifest['samples']
    indexed = {(r['idx'], r['profile'], r['repeat']):r for r in rows}
    expected = {(s['idx'],p,rep) for s in samples for p in profiles for rep in repeats}
    if len(indexed)!=len(rows) or set(indexed)!=expected:
        raise ValueError('Missing/duplicate/unexpected scheduled rows')
    batches = {f'{p}/r{rep}':[indexed[s['idx'],p,rep] for s in samples]
               for p in profiles for rep in repeats}
    metrics = {key:extended_score(batch) for key,batch in batches.items()}
    by_cwe = {key:{c:extended_score([r for r in batch if r['cwe']==c])
                  for c in sorted({s['cwe'] for s in samples})} for key,batch in batches.items()}
    successful = defaultdict(list)
    all_calls = defaultdict(list)
    for call in calls:
        key = call['idx'],call['profile'],call['repeat']
        if key not in expected:
            raise ValueError('Unexpected API receipt')
        all_calls[key].append(call)
        if not call.get('error'):
            successful[key].append(call)
    for key,row in indexed.items():
        spent = sum(c.get('total_tokens') or 0 for c in all_calls[key])
        if row.get('tokens_used',0)!=spent:
            raise ValueError('Result/API token mismatch')
        if not row.get('error'):
            trace = row.get('arbitrate',{}).get('reasoning_trace',[])
            if len(trace)!=len(successful[key]) or any(
                    t['answer']!=c['answer'] for t,c in zip(trace,successful[key])):
                raise ValueError('Trace/API mismatch')
    accounting, mechanism = {}, {}
    from planning.planner import RetrievalPlanner
    planner = RetrievalPlanner()
    for p in profiles:
        for rep in repeats:
            name = f'{p}/r{rep}'
            batch = batches[name]
            observed = [c for c in calls if c['profile']==p and c['repeat']==rep]
            good = [c for c in observed if not c.get('error')]
            accounting[name] = {
                'invocations':len(observed),'successful_invocations':len(good),
                'failed_invocations':len(observed)-len(good),
                'unknown_usage_invocations':sum(not c.get('usage_known',False) for c in observed),
                'actual_models':dict(Counter(c.get('model','unavailable') for c in observed)),
                **{k:sum(c.get(k) or 0 for c in observed)
                   for k in ('prompt_tokens','completion_tokens','total_tokens')}}
            facts = [response_facts(c.get('answer') or '') for c in good]
            audits = [r.get('module_audit',{}) for r in batch]
            mechanism[name] = {
                'successful_calls':len(good),
                'length_calls':sum(c.get('finish_reason')=='length' for c in good),
                'length_rate':sum(c.get('finish_reason')=='length' for c in good)/len(good) if good else 0,
                'complete_action_json':sum(f['action_json_complete'] for f in facts),
                'complete_action_rate':sum(f['action_json_complete'] for f in facts)/len(good) if good else 0,
                'planner_explicit_actions':sum(planner.parse_json_action(c.get('answer') or '')[0] is not None for c in good),
                'two_step_samples':sum((r.get('reasoning_steps') or 0)>1 for r in batch),
                'actual_tool_events':sum(len(r.get('tool_execution_receipts',[])) for r in batch),
                'tool_events_returning_paths':sum(bool(e['returned_paths']) for r in batch for e in r.get('tool_execution_receipts',[])),
                'enhanced_expansion_events':sum(len(a.get('expansion',{}).get('events',[])) for a in audits),
                'stop_reasons':dict(Counter(a.get('stop_reason','unavailable') for a in audits))}
    input_checks, intervals, repeats_report = {}, {}, {}
    if 'output512' in profiles:
        for rep in repeats:
            compared = 0
            for s in samples:
                a,b = successful[s['idx'],'control',rep],successful[s['idx'],'output512',rep]
                if a and b:
                    compare_requests(a[0]['request'],b[0]['request']); compared+=1
            input_checks[f'r{rep}'] = {'budget_only_first_pairs':compared,'scheduled':len(samples)}
        groups = defaultdict(list)
        for s in samples:
            groups[s['group_id']].append(s['idx'])
        rng = random.Random(20261008)
        deltas = {'f1':[],'accuracy':[]}
        from evaluation.evaluate_wiring_quality import score
        for _ in range(bootstrap):
            ids = [i for group in rng.choices(list(groups.values()),k=len(groups)) for i in group]
            a = score([indexed[i,'control',1] for i in ids])
            b = score([indexed[i,'output512',1] for i in ids])
            for k in deltas:
                deltas[k].append(b[k]-a[k])
        for k,values in deltas.items():
            values.sort()
            intervals[k] = {'delta':metrics['output512/r1'][k]-metrics['control/r1'][k],
                'ci95':[values[int(bootstrap*.025)],values[min(bootstrap-1,int(bootstrap*.975))]]}
    if len(repeats)==2:
        for p in profiles:
            compared = 0
            for s in samples:
                a,b = successful[s['idx'],p,1],successful[s['idx'],p,2]
                if a and b:
                    if a[0]['request']!=b[0]['request']:
                        raise ValueError('Repeat first input changed')
                    compared+=1
            repeats_report[p] = {'identical_first_requests':compared,
                'prediction_disagreements':sum(indexed[s['idx'],p,1].get('prediction')!=
                    indexed[s['idx'],p,2].get('prediction') for s in samples)}
    constant = {name:extended_score([dict(s,prediction=value) for s in samples])
                for name,value in (('always_positive',1),('always_negative',0))}
    gates = {}
    if 'output512' in profiles:
        gates = {
            'mechanism_both':all(mechanism[f'output512/r{r}']['length_rate']<mechanism[f'control/r{r}']['length_rate']
                and mechanism[f'output512/r{r}']['complete_action_rate']>mechanism[f'control/r{r}']['complete_action_rate'] for r in repeats),
            'nonnegative_quality_both':all(metrics[f'output512/r{r}'][k]>=metrics[f'control/r{r}'][k] for r in repeats for k in ('f1','accuracy')),
            'primary_intervals':max(intervals[k]['ci95'][0] for k in intervals)>0 and min(intervals[k]['ci95'][0] for k in intervals)>=0,
            'constant_accuracy_positive_mcc_both':all(metrics[f'output512/r{r}']['accuracy']>constant['always_positive']['accuracy']
                and metrics[f'output512/r{r}']['mcc']>0 for r in repeats)}
    return {'metrics':metrics,'by_cwe':by_cwe,'api_accounting':accounting,
        'mechanism':mechanism,'input_checks':input_checks,'primary_family_intervals':intervals,
        'repeat_sensitivity':repeats_report,'constant_baselines':constant,'gates':gates,
        'actual_invocations':len(calls),'scheduled_results':len(expected),'auto_promoted':False,
        'quality_support':bool(gates) and all(v for k,v in gates.items() if k!='mechanism_both'),
        'scope':'Exposed SVEN development replay, not independent validation.',
        'limitations':['Family bootstrap reflects these observed groups, not future provider variability.',
            'Correlated/conflicting-label rows retained; repeated calls are not new samples.',
            'Unknown usage is unknown cost, not free; reported tokens are not exact money.',
            'More complete ACTION is not itself proof of quality or feasible execution.']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--prepared-root',type=Path,default=Path('output/sven_full_pipeline_inputs_20261006'))
    parser.add_argument('--workers',type=int,default=4)
    parser.add_argument('--preflight-only',action='store_true')
    parser.add_argument('--authorized-real-sven',action='store_true')
    parser.add_argument('--baseline-only',action='store_true')
    args = parser.parse_args()
    if not 1<=args.workers<=8 or args.output.exists():
        raise ValueError('Workers1..8 and a new output directory required')
    if not args.preflight_only and not args.authorized_real_sven:
        raise ValueError('New SVEN payload/budget authorization required')
    from evaluation.build_clean_development_pilot import SETTINGS
    settings = dict(SETTINGS,RECORD_REASONING_TRACE='1',USE_BACKWARD_SLICE='0',
                    BOUNDED_OUTPUT_CONTRACT='0',EVIDENCE_EXPANSION='0')
    os.environ.update(settings)
    import config
    from evaluation.evaluate_wiring_quality import effective_configuration
    effective = effective_configuration(config,settings)
    if config.LLM_BASE_URL.rstrip('/')!='https://api.deepseek.com/v1' or config.LLM_MODEL!='deepseek-chat':
        raise ValueError('Endpoint/model differs from authorization')
    from evaluation.evaluate_sven_full_pipeline import source_groups
    from graph.build_cpg import _source_fingerprint, _dot_has_func_method
    from graph.pipeline import run_hgl_pipeline
    from sven_eval.data.wrap_slice import wrap_slice
    from linearization.source_mapping import source_line_offset
    dataset = ROOT/'sven_eval/data/sven_test.json'
    data = json.loads(dataset.read_text(encoding='utf8'))
    if len(data)!=254:
        raise ValueError('Authorized dataset size changed')
    groups = source_groups(data)
    samples=[]
    for idx,item in enumerate(data):
        if item['output'] not in ('VULNERABLE','BENIGN'):
            raise ValueError('Unknown label')
        sid=f"{idx:04d}_{Path(item['file_name']).stem}"
        cache=(args.prepared_root/sid).resolve(); source=cache/'source.c'
        sample={'idx':idx,'sample_id':sid,'target':int(item['output']=='VULNERABLE'),
                'group_id':groups[idx],'cwe':item['cwe'],
                'source_sha256':hashlib.sha256(item['input'].encode()).hexdigest(),
                'source_path':str(source),'cache_path':str(cache)}
        try:
            wrapped,ok,reason=wrap_slice(item['input'],item['file_name'])
            if not ok or source.read_text(encoding='utf8')!=wrapped:
                raise ValueError('Deterministic wrapper mismatch')
            if source_line_offset(item['input'],wrapped)>len(wrapped.splitlines()):
                raise ValueError('Ambiguous wrapper mapping')
            dot=cache/'export/export.dot'
            metadata=json.loads((cache/'.hgl_cpg_cache.json').read_text(encoding='utf8'))
            if metadata['source_fingerprint']!=_source_fingerprint(wrapped,str(source)) or not _dot_has_func_method(str(dot)):
                raise ValueError('Stale/no-method graph')
            sample.update(wrapped_sha256=digest(source),cpg_sha256=digest(dot),wrapper_reason=reason)
        except Exception as exc:
            sample['preparation_error']=str(exc)
        samples.append(sample)
    hashes=code_hashes()
    profiles={'control':150} if args.baseline_only else PROFILES
    repeats=[1] if args.baseline_only else [1,2]
    manifest={'dataset':str(dataset),'dataset_sha256':digest(dataset),'samples':samples,
        'profiles':profiles,'repeats':repeats,'settings':settings,'effective_settings':effective,
        'code_hashes':hashes,'requested_model':config.LLM_MODEL,'base_url':config.LLM_BASE_URL,
        'protocol':'SVEN_BUDGET_PROTOCOL_20261008.md','planned_results':len(samples)*len(profiles)*len(repeats),
        'source_family_groups':len(set(groups)),'graph_budget':4096,'max_steps':2,
        'scope':'Exposed SVEN replay, not an independent test.', 'auto_promoted':False}
    args.output.mkdir(parents=True)
    def save(name,value):
        (args.output/name).write_text(json.dumps(value,indent=2,ensure_ascii=False),encoding='utf8')
    save('manifest.json',manifest)
    for name,expected in hashes.items():
        dest=args.output/'code_snapshot'/name
        dest.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(ROOT/name,dest)
        if digest(dest)!=expected: raise ValueError('Snapshot differs')
    errors=[s for s in samples if s.get('preparation_error')]
    print(f'PREFLIGHT n={len(samples)} errors={len(errors)} families={len(set(groups))}',flush=True)
    if errors:
        print(json.dumps(errors[:3],indent=2)); raise ValueError('Invalid preparation, no real calls')
    if args.preflight_only:
        loop=importlib.import_module('reasoning.reasoning_loop')
        api=importlib.import_module('reasoning.llm_api')
        shadow=[]
        def blocked(*a,**kw):raise AssertionError('External calls blocked')
        def mock(*a,**kw):return 'HYPOTHESIS: no vulnerability detected\nACTION: {"action":"Stop"}',0
        with patch.object(loop,'query_llm_with_retry',mock),patch.object(api,'query_llm',blocked),patch.object(api,'create_client',blocked), \
                (args.output/'shadow.log').open('w',encoding='utf8') as log,contextlib.redirect_stdout(log):
            for s in samples:
                try:
                    result=run_hgl_pipeline(s['source_path'],data[s['idx']]['input'],s['sample_id'],s['cache_path'],None,4096,return_details=True)
                    trace=result['arbitrate']['reasoning_trace']
                    if len(trace)!=1: raise ValueError('Expected one intercepted call')
                    shadow.append(dict(idx=s['idx'],system_prompt=trace[0]['system_prompt'],user_prompt=trace[0]['user_prompt'],module_audit=result['module_audit']))
                except Exception as exc:
                    shadow.append(dict(idx=s['idx'],error=str(exc)))
                print(f'SHADOW {len(shadow)}/254',file=sys.__stdout__,flush=True)
        save('shadow.json',shadow)
        if any(r.get('error') for r in shadow) or code_hashes()!=hashes:raise ValueError('Shadow failure/code mutation')
        print('PREFLIGHT PASS shadow254 api_calls0',flush=True);return
    preflight=ROOT/'output/sven_budget_preflight_20261008'
    earlier=json.loads((preflight/'manifest.json').read_text(encoding='utf8'))
    shadow=json.loads((preflight/'shadow.json').read_text(encoding='utf8'))
    if earlier['code_hashes']!=hashes or earlier['samples']!=samples or earlier['settings']!=settings or len(shadow)!=254 or any(s.get('error') for s in shadow):
        raise ValueError('Shadow does not match current frozen run')
    manifest['preflight_sha256']=digest(preflight/'manifest.json')
    manifest['shadow_sha256']=digest(preflight/'shadow.json');save('manifest.json',manifest)
    shadow_by_idx={s['idx']:s for s in shadow}
    from reasoning.llm_api import create_client
    client=create_client().with_options(max_retries=0,timeout=90)
    lock=threading.Lock();rows=[];calls=[]
    loop=importlib.import_module('reasoning.reasoning_loop')
    original_execute=loop._execute_action
    thread_state=threading.local()
    def record_execute(engine,action,current_paths,graph):
        result=original_execute(engine,action,current_paths,graph)
        thread_state.events.append({'action':action,'returned_paths':len(result),
                                    'graph_nodes':len(graph)})
        return result
    def append(name,row):
        with lock:
            with (args.output/name).open('a',encoding='utf8') as f:f.write(json.dumps(row,ensure_ascii=False)+'\n')
    def run(s,profile,repeat):
        base={k:s[k] for k in ('idx','sample_id','target','group_id','cwe','source_sha256')}
        base.update(profile=profile,repeat=repeat)
        own=[]
        thread_state.events=[]
        def observed(**kwargs):
            request=budget_request(kwargs,profiles[profile]);call=dict(base,request=request)
            if not own:
                frozen=shadow_by_idx[s['idx']]
                expected_messages=[{'role':'system','content':frozen['system_prompt']},
                                   {'role':'user','content':frozen['user_prompt']}]
                if request['messages']!=expected_messages:
                    raise ValueError('First prompt differs from frozen shadow')
            try:
                response=client.chat.completions.create(**request)
                u=response.usage
                call.update(model=response.model,answer=response.choices[0].message.content,
                    finish_reason=response.choices[0].finish_reason,usage_known=u is not None,
                    **{k:getattr(u,k,None) for k in ('prompt_tokens','completion_tokens','total_tokens')})
                return response
            except Exception as exc:
                call.update(error=str(exc),usage_known=False);raise
            finally:
                own.append(call);append('api_receipts.jsonl',call)
                with lock:calls.append(call)
        observer=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=observed)))
        try:
            if digest(s['source_path'])!=s['wrapped_sha256'] or digest(Path(s['cache_path'])/'export/export.dot')!=s['cpg_sha256']:
                raise ValueError('Source/graph changed')
            result=run_hgl_pipeline(s['source_path'],data[s['idx']]['input'],s['sample_id'],s['cache_path'],observer,4096,return_details=True)
            if any(result['module_audit'].get(k) for k in ('learned_scoring','graph_security_net')):
                raise ValueError('Unexpected rejected module')
            return dict(base,**result,tool_execution_receipts=list(thread_state.events))
        except Exception as exc:
            return dict(base,prediction=None,error=str(exc),tokens_used=sum(c.get('total_tokens') or 0 for c in own),
                        tool_execution_receipts=list(thread_state.events))
    with patch.object(loop,'_execute_action',record_execute), \
            (args.output/'execution.log').open('w',encoding='utf8') as log,contextlib.redirect_stdout(log):
        for repeat in repeats:
            for profile in profiles:
                if code_hashes()!=hashes:raise ValueError('Frozen code changed')
                with ThreadPoolExecutor(max_workers=args.workers) as pool:
                    for future in as_completed([pool.submit(run,s,profile,repeat) for s in samples]):
                        row=future.result();rows.append(row);append('results.jsonl',row)
                        print(f"SVEN BUDGET {len(rows)}/{manifest['planned_results']} {profile}/r{repeat} idx={row['idx']} error={bool(row.get('error'))}",file=sys.__stdout__,flush=True)
                log.flush()
    if code_hashes()!=hashes or digest(dataset)!=manifest['dataset_sha256']:raise ValueError('Freeze changed')
    report=summarize(rows,calls,manifest);report['frozen_code_matches']=True
    save('report.json',report)
    print(json.dumps({'metrics':report['metrics'],'gates':report['gates'],'actual_invocations':len(calls)},indent=2),flush=True)


if __name__=='__main__':main()
