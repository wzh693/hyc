"""One authorized full254 whole-evidence-v2 batch; frozen foundation ranking."""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import contextlib
import importlib
import io
import json
import os
from pathlib import Path
import random
import re
import shutil
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from evaluation.preflight_graph_evidence_cards_v2 import prepare as verify_sources
from evaluation.preflight_graph_display import graph_hash, digest as value_hash
from evaluation.evaluate_reconstructed_llm import digest, read_json, score
from evaluation.evaluate_sven_complete_src import checked_rows, extended_score, request_hash
from evaluation.audit_type_coverage_baseline import memoized_search

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'development/graph_evidence_cards_v2_candidate_20261009/src'
SHADOW=ROOT/'output/graph_evidence_cards_preflight_v2_20261009'
PROTOCOL=ROOT/'evaluation/GRAPH_EVIDENCE_CARDS_LLM_PROTOCOL_20261009.md'
PROFILES=['control','display']


def prepare():
    current,data=verify_sources(); frozen=read_json(SHADOW/'manifest.json')
    if current!=frozen: raise ValueError('Original v2 source/tool/input freeze changed')
    audit=read_json(SHADOW/'verification.json')
    if not audit['passed']: raise ValueError('Unverified full v2 preflight')
    for name,expected in audit['hashes'].items():
        if digest(SHADOW/name)!=expected: raise ValueError('V2 artifact changed')
    stage_rows=[json.loads(line) for line in (SHADOW/'rows.jsonl').read_text(encoding='utf8').splitlines()]
    stages={(r['idx'],r['profile']):r for r in stage_rows}
    if len(stage_rows)!=508 or len(stages)!=508 or set(stages)!={(i,p) for i in range(254) for p in PROFILES}:
        raise ValueError('Not a complete paired retrieval cache')
    samples=current['samples']
    if any(s['target']!=int(data[s['idx']]['output']=='VULNERABLE') or s['cwe']!=data[s['idx']]['cwe'] for s in samples):
        raise ValueError('Labels changed')
    requests={key:r['request'] for key,r in stages.items()}
    # All46 shared modules must be identical; only serialization is dispatched.
    control_hashes={n.replace('\\','/'):h for n,h in current['source_hashes']['control'].items()}
    assert {n for n,h in control_hashes.items() if current['source_hashes']['display'][n]!=h}=={'linearization/typed_paths.py'}
    tools=['evaluation/evaluate_graph_evidence_cards_llm.py','evaluation/audit_graph_evidence_cards_llm.py',
           'evaluation/test_graph_evidence_cards_llm.py',str(PROTOCOL.relative_to(ROOT)),
           'evaluation/evaluate_sven_complete_src.py','evaluation/evaluate_reconstructed_llm.py',
           'evaluation/audit_type_coverage_baseline.py']
    tool_hashes=dict(current['tooling_hashes']);tool_hashes.update({n:digest(ROOT/n) for n in tools})
    order=list(range(254)); random.Random(20261009).shuffle(order)
    manifest=dict(samples=samples,profiles=PROFILES,repeats=[1,2],planned_results=1016,
        source_roots=current['source_roots'],source_hashes=current['source_hashes'],
        tooling_hashes=tool_hashes,settings=current['settings'],
        dataset=current['dataset'],dataset_sha256=current['dataset_sha256'],
        stage_artifact_sha256=audit['hashes'],stage_root=str(SHADOW),
        first_request_sha256={f'{p}/{i}':request_hash(r) for (i,p),r in requests.items()},
        sample_order=order,pair_order_rule='control first iff (idx+repeat)%2==0; opposite in repeat2',
        candidate_input_changes=sum(requests[i,'control']!=requests[i,'display'] for i in range(254)),
        endpoint='https://api.deepseek.com/v1',requested_model='deepseek-chat',
        output_cap=150,max_steps=2,max_attempts_per_step=3,sdk_retries=0,timeout_seconds=90,
        workers=4,graph_budget=4096,bootstrap_seed=20261009,bootstrap_draws=2000,
        exact_sources=len({s['source_sha256'] for s in samples}),family_groups=len({s['group_id'] for s in samples}),
        automatic_promotion=False,scope='All254 local exposed SVEN rows; not independent final or all upstream SVEN.',
        retrieval_cache='Unchanged foundation TopK from full254 v2 preflight; exact graph/candidate hashes before reuse.',
        serialization_dispatch='control=byte-equivalent legacy body; display=whole_graph_evidence_v2; thread-local profile')
    return manifest,requests,stages,data


def pair_order(idx,repeat): return PROFILES if (idx+repeat)%2==0 else list(reversed(PROFILES))


def usage_record(usage):
    fields={k:getattr(usage,k,None) for k in ('prompt_tokens','completion_tokens','total_tokens')}
    known=all(isinstance(v,int) and not isinstance(v,bool) and v>=0 for v in fields.values())
    known=known and fields['prompt_tokens']+fields['completion_tokens']==fields['total_tokens']
    return dict(usage_known=known,**fields)


def checked_selection(graph,candidates,stage):
    if graph_hash(graph)!=stage['path_graph_hash'] or value_hash(candidates)!=stage['candidate_paths_sha256']:
        raise ValueError('Frozen retrieval cache does not match actual graph/candidates')
    if not stage['all_selected_from_candidates'] or any(p not in candidates for p in stage['topk']):
        raise ValueError('Cached path not from candidate set')
    return [list(p) for p in stage['topk']]


def summarize(rows,calls,manifest,draws=None):
    indexed,own=checked_rows(rows,calls,manifest)
    samples=manifest['samples']; batches={f'{p}/r{rep}':[indexed[s['idx'],p,rep] for s in samples] for p in PROFILES for rep in (1,2)}
    metrics={k:extended_score(v) for k,v in batches.items()}
    by_cwe={k:{c:extended_score([r for r in batch if r['cwe']==c]) for c in sorted({s['cwe'] for s in samples})} for k,batch in batches.items()}
    accounting={}
    for p in PROFILES:
        for rep in (1,2):
            observed=[c for c in calls if c['profile']==p and c['repeat']==rep]
            accounting[f'{p}/r{rep}']=dict(invocations=len(observed),successful_invocations=sum(not c.get('error') for c in observed),
                failed_invocations=sum(bool(c.get('error')) for c in observed),unknown_usage=sum(not c.get('usage_known') for c in observed),
                actual_models=dict(Counter(c.get('model','unavailable') for c in observed)),length_calls=sum(c.get('finish_reason')=='length' for c in observed),
                **{k:sum(c.get(k) or 0 for c in observed) for k in ('prompt_tokens','completion_tokens','total_tokens')})
    constant={name:extended_score([dict(s,prediction=p) for s in samples]) for name,p in [('always_positive',1),('always_negative',0)]}
    intervals={}; draws=manifest['bootstrap_draws'] if draws is None else draws
    for name,subset in [('global',samples),('CWE-125',[s for s in samples if s['cwe']=='CWE-125'])]:
        groups=defaultdict(list)
        for s in subset: groups[s['group_id']].append(s['idx'])
        rng=random.Random(manifest['bootstrap_seed']); values={k:[] for k in ('f1','accuracy')}
        for _ in range(draws):
            ids=[i for group in rng.choices(list(groups.values()),k=len(groups)) for i in group]
            a,b=[score([indexed[i,p,1] for i in ids]) for p in PROFILES]
            for k in values: values[k].append(b[k]-a[k])
        a=metrics['control/r1'] if name=='global' else by_cwe['control/r1'][name]
        b=metrics['display/r1'] if name=='global' else by_cwe['display/r1'][name]
        intervals[name]={k:dict(delta=b[k]-a[k],ci95=[sorted(v)[int(draws*.025)],sorted(v)[min(draws-1,int(draws*.975))]]) for k,v in values.items()}
    gates=dict(global_nonnegative_both=all(metrics[f'display/r{r}'][k]>=metrics[f'control/r{r}'][k] for r in (1,2) for k in ('f1','accuracy')),
        cwe125_improves_both=all(by_cwe[f'display/r{r}']['CWE-125'][k]>by_cwe[f'control/r{r}']['CWE-125'][k] for r in (1,2) for k in ('f1','accuracy')),
        primary_family_intervals_positive=intervals['global']['f1']['ci95'][0]>0 and intervals['CWE-125']['accuracy']['ci95'][0]>0,
        other_types_balanced_accuracy_within_002=all(by_cwe[f'display/r{r}'][c]['balanced_accuracy']>=by_cwe[f'control/r{r}'][c]['balanced_accuracy']-.02 for r in (1,2) for c in ('CWE-190','CWE-416')),
        beats_constant_both=all(metrics[f'display/r{r}']['f1']>constant['always_positive']['f1'] and metrics[f'display/r{r}']['accuracy']>constant['always_positive']['accuracy'] and metrics[f'display/r{r}']['mcc']>0 for r in (1,2)))
    models={c.get('model') for c in calls if not c.get('error')}
    functional=all(not m['errors'] and not m['uncertain'] for m in metrics.values()) and all(not a['failed_invocations'] and not a['unknown_usage'] for a in accounting.values()) and len(models)==1 and None not in models
    effective={}
    for label,changed in [('changed_first_input',True),('unchanged_first_input',False)]:
        ids=[s['idx'] for s in samples if (manifest['first_request_sha256'][f'control/{s["idx"]}']!=manifest['first_request_sha256'][f'display/{s["idx"]}'])==changed]
        effective[label]=dict(rows=len(ids),repeats={})
        for rep in (1,2):
            a=[indexed[i,'control',rep] for i in ids]; b=[indexed[i,'display',rep] for i in ids]
            effective[label]['repeats'][str(rep)]=dict(prediction_differences=sum(x['prediction']!=y['prediction'] for x,y in zip(a,b)),
                gained_correct=sum(x['prediction']!=x['target'] and y['prediction']==y['target'] for x,y in zip(a,b)),
                lost_correct=sum(x['prediction']==x['target'] and y['prediction']!=y['target'] for x,y in zip(a,b)))
    return dict(scheduled_results=len(rows),metrics=metrics,by_cwe=by_cwe,api_accounting=accounting,
        actual_invocations=len(calls),total_reported_tokens=sum(c.get('total_tokens') or 0 for c in calls),
        constant_baselines=constant,repeat_prediction_disagreements={p:sum(indexed[s['idx'],p,1]['prediction']!=indexed[s['idx'],p,2]['prediction'] for s in samples) for p in PROFILES},
        primary_family_intervals=intervals,input_change_decomposition=effective,functional_gate=functional,gates=gates,
        exploratory_support=functional and all(gates.values()),auto_promoted=False,scope=manifest['scope'],
        limitations=['Development-exposed, correlated/conflicting rows retained; repeats are not new independent samples.',
                     'r1 family intervals are descriptive, not independent causal/generalization proof.',
                     'Frozen deterministic retrieval cache, not a retrieval speed benchmark.',
                     'Whole graph cards are not complete source/capacity/dominance proof; graph decoding/SRC/150-output limits retained.',
                     'No automatic activation, reruns, locked Devign, GitHub upload or paper-readiness claim.'])


class Runtime:
    def __init__(self,manifest,stages,offline):
        if not offline:
            env=ROOT/'.env'
            if env.exists():
                for line in env.read_text(encoding='utf8').splitlines():
                    if line.strip() and not line.lstrip().startswith('#') and '=' in line:
                        k,v=line.split('=',1); os.environ.setdefault(k.strip(),v.strip().strip('"').strip("'"))
        os.environ.update(manifest['settings']); os.environ.update(LLM_MODEL='deepseek-chat',OPENAI_BASE_URL=manifest['endpoint'])
        if offline: os.environ['OPENAI_API_KEY']='offline-not-a-key'
        sys.dont_write_bytecode=True; sys.path.insert(0,str(SOURCE))
        self.config=importlib.import_module('config'); self.pipeline=importlib.import_module('graph.pipeline'); self.api=importlib.import_module('reasoning.llm_api')
        for module in (self.config,self.pipeline,self.api):
            if not Path(module.__file__).resolve().is_relative_to(SOURCE): raise ValueError('Wrong isolated source imported')
        for name,value in manifest['settings'].items():
            if hasattr(self.config,name):
                actual=getattr(self.config,name); expected=value=='1' if isinstance(actual,bool) else int(value) if isinstance(actual,int) else value
                if actual!=expected: raise ValueError('Runtime setting mismatch: '+name)
        if not offline and (not self.config.LLM_API_KEY or self.config.LLM_API_KEY=='offline-not-a-key' or self.config.LLM_MODEL!='deepseek-chat' or self.config.LLM_BASE_URL.rstrip('/')!=manifest['endpoint']):
            raise ValueError('Credential/endpoint/model mismatch')
        self.local=threading.local(); self.stages=stages; self.blocked_attempts=0
        self.typed=importlib.import_module('linearization.typed_paths')
        self.control_serializer=self.typed._legacy_labeled_compact_path
        self.candidate_serializer=self.typed._labeled_compact_path
        self.originals={n:getattr(self.pipeline,n) for n in ('load_graph','summarize_graph','extract_all_candidate_paths')}

    def blocked(self,*a,**k): self.blocked_attempts+=1; raise RuntimeError('Unobserved client/process forbidden')

    def cache(self,name,*a,**k):
        key=(name,tuple(a[0].nodes()) if name!='load_graph' else None)
        if key not in self.local.prepared: self.local.prepared[key]=self.originals[name](*a,**k)
        value=self.local.prepared[key]
        return value.copy() if name in ('load_graph','summarize_graph') else [list(p) for p in value]

    def retrieve(self,graph,candidates,*a,**k):
        if a or k.get('learned_scores') is not None or k.get('vuln_type','Generic')!='Generic': raise ValueError('Unsupported retrieval-cache arguments')
        return checked_selection(graph,candidates,self.stages[self.local.idx,self.local.profile])

    def serialize(self,*a,**k):
        profile=self.local.profile
        if profile not in PROFILES: raise ValueError('Unknown serialization profile')
        serializer=self.control_serializer if profile=='control' else self.candidate_serializer
        return serializer(*a,**k)

    def patches(self,offline):
        stack=contextlib.ExitStack()
        stack.enter_context(patch.object(self.api,'create_client',self.blocked)); stack.enter_context(patch('subprocess.Popen',self.blocked))
        stack.enter_context(patch.object(self.pipeline,'build_cpg',side_effect=lambda source,cache:str(Path(cache)/'export')))
        for name in self.originals:
            stack.enter_context(patch.object(self.pipeline,name,side_effect=lambda *a,_name=name,**k:self.cache(_name,*a,**k)))
        stack.enter_context(patch.object(self.pipeline,'retrieve_topk',side_effect=self.retrieve))
        stack.enter_context(patch.object(self.typed,'_labeled_compact_path',side_effect=self.serialize))
        stack.enter_context(patch.object(re,'search',memoized_search(re.search)))
        if offline:
            stack.enter_context(patch.object(socket.socket,'connect',self.blocked)); stack.enter_context(patch.object(socket,'create_connection',self.blocked))
        re._MAXCACHE=32768
        if hasattr(re,'_MAXCACHE2'): re._MAXCACHE2=16384
        return stack


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path); parser.add_argument('--preflight-only',action='store_true')
    parser.add_argument('--preflight',type=Path); parser.add_argument('--authorized-real-1016',action='store_true')
    args=parser.parse_args()
    if args.output.exists(): raise ValueError('Fresh output required; no resume/rerun')
    if not args.preflight_only and (not args.preflight or not args.authorized_real_1016): raise ValueError('Frozen runtime preflight and this batch authorization required')
    manifest,requests,stages,data=prepare()
    if not args.preflight_only:
        frozen=read_json(args.preflight/'manifest.json')
        if frozen!=manifest: raise ValueError('Runtime freeze changed')
        proof=read_json(args.preflight/'runtime_verification.json')
        if not proof['passed'] or proof['rows']!=1016 or proof['request_records_sha256']!=digest(args.preflight/'requests.jsonl') or proof['results_sha256']!=digest(args.preflight/'results.jsonl') or proof['manifest_sha256']!=digest(args.preflight/'manifest.json'):
            raise ValueError('Runtime preflight not complete/intact')
    runtime=Runtime(manifest,stages,args.preflight_only)
    args.output.mkdir(parents=True)
    def save(name,value): (args.output/name).write_text(json.dumps(value,indent=2,ensure_ascii=False),encoding='utf8')
    save('manifest.json',manifest)
    lock=threading.Lock(); rows=[]; calls=[]; mock_records=[]
    def append(name,value):
        with lock:
            with (args.output/name).open('a',encoding='utf8') as f:f.write(json.dumps(value,ensure_ascii=False)+'\n')
    if args.preflight_only: client=None
    else:
        for group,hashes,source in [('code_snapshot',manifest['source_hashes']['display'],SOURCE),
                                   ('control_snapshot',manifest['source_hashes']['control'],Path(manifest['source_roots']['control'])),
                                   ('tooling_snapshot',manifest['tooling_hashes'],ROOT)]:
            for name,expected in hashes.items():
                dest=args.output/group/name; dest.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(source/name,dest)
                if digest(dest)!=expected: raise ValueError('Snapshot hash mismatch')
        from openai import OpenAI
        import httpx
        client=OpenAI(api_key=runtime.config.LLM_API_KEY,base_url=runtime.config.LLM_BASE_URL,max_retries=0,timeout=90,
                      http_client=httpx.Client(trust_env=False,timeout=90))
    def one(sample,profile,rep):
        base={k:sample[k] for k in ('idx','sample_id','target','group_id','cwe','source_sha256')}; base.update(profile=profile,repeat=rep)
        runtime.local.profile=profile; own=[]; first=False; attempts=Counter(); step_requests={}
        def observed(**request):
            nonlocal first
            step=1+sum(not c.get('error') for c in own); attempt=attempts[step]+1
            if step>2 or attempt>3 or len(own)>=6: raise ValueError('Authorized step/attempt bound exceeded')
            if request.get('model')!='deepseek-chat' or request.get('max_tokens')!=150 or request.get('temperature')!=0: raise ValueError('Unauthorized call parameters')
            if step==1:
                if request!=requests[sample['idx'],profile]: raise ValueError('Actual first request differs from full freeze')
                first=True
            if step in step_requests and step_requests[step]!=request: raise ValueError('Retry request mutated')
            step_requests[step]=request; attempts[step]+=1
            if args.preflight_only:
                record=dict(base,request=request); mock_records.append(record); append('requests.jsonl',record)
                return SimpleNamespace(model='offline-mock',usage=SimpleNamespace(total_tokens=0,prompt_tokens=0,completion_tokens=0),
                    choices=[SimpleNamespace(finish_reason='stop',message=SimpleNamespace(content='HYPOTHESIS: no vulnerability detected\nACTION: {"action":"Stop"}'))])
            record=dict(base,request=request,step=step,attempt=attempt,started_at=datetime.now(timezone.utc).isoformat()); started=time.monotonic()
            try:
                response=client.chat.completions.create(**request); usage=response.usage
                record.update(answer=response.choices[0].message.content,model=response.model,finish_reason=response.choices[0].finish_reason,
                    **usage_record(usage))
                return response
            except Exception as exc:
                record.update(error=str(exc).replace(runtime.config.LLM_API_KEY,'[REDACTED]'),usage_known=False)
                raise RuntimeError(record['error']) from None
            finally:
                record['elapsed_seconds']=time.monotonic()-started; own.append(record); append('api_receipts.jsonl',record)
                with lock:calls.append(record)
        observer=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=observed)))
        try:
            if digest(sample['source_path'])!=sample['wrapped_source_sha256'] or digest(Path(sample['cache_path'])/'export/export.dot')!=sample['cpg_sha256']: raise ValueError('Input changed')
            value=runtime.pipeline.run_hgl_pipeline(sample['source_path'],data[sample['idx']]['input'],sample['sample_id'],sample['cache_path'],observer,4096,return_details=True)
            if not first or value['reasoning_steps']>2: raise ValueError('Unobserved/extra step')
            value['tokens_used']=sum(c.get('total_tokens') or 0 for c in own)
            return dict(base,**value,first_request_verified=first)
        except Exception as exc:
            return dict(base,prediction=None,error=str(exc).replace(runtime.config.LLM_API_KEY,'[REDACTED]'),tokens_used=sum(c.get('total_tokens') or 0 for c in own),first_request_verified=first)
    def paired(sample):
        runtime.local.idx=sample['idx']; runtime.local.prepared={}
        for rep in (1,2):
            for profile in pair_order(sample['idx'],rep):
                row=one(sample,profile,rep); append('results.jsonl',row)
                with lock:rows.append(row); done=len(rows)
                if not args.preflight_only or done%40==0:
                    print(f'{"OFFLINE" if args.preflight_only else "LLM"} display {done}/1016 {profile}/r{rep} idx={sample["idx"]} error={bool(row.get("error"))}',file=sys.__stdout__,flush=True)
        runtime.local.prepared.clear()
    samples={s['idx']:s for s in manifest['samples']}
    try:
        with runtime.patches(args.preflight_only),(args.output/'execution.log').open('w',encoding='utf8') as log,contextlib.redirect_stdout(log):
            with ThreadPoolExecutor(max_workers=4) as pool:
                for future in as_completed([pool.submit(paired,samples[i]) for i in manifest['sample_order']]):future.result()
    finally:
        if client is not None:client.close()
    after,_,_,_=prepare()
    if after!=manifest or runtime.blocked_attempts:raise ValueError('Freeze drift/forbidden external attempt; all records preserved')
    if args.preflight_only:
        expected={(i,p,r) for i in range(254) for p in PROFILES for r in (1,2)}
        if len(rows)!=1016 or len(mock_records)!=1016 or {(r['idx'],r['profile'],r['repeat']) for r in mock_records}!=expected or any(r.get('error') for r in rows):
            raise ValueError('Incomplete full runtime preflight; keep failures')
        save('runtime_verification.json',dict(passed=True,rows=1016,source_rows=254,new_api_calls=0,
            request_records_sha256=digest(args.output/'requests.jsonl'),results_sha256=digest(args.output/'results.jsonl'),
            manifest_sha256=digest(args.output/'manifest.json'),blocked_external_attempts=runtime.blocked_attempts))
        print('FULL RUNTIME PREFLIGHT PASS254 rows/1016 mock requests/no API');return
    report=summarize(rows,calls,manifest);save('report.json',report)
    print(json.dumps(dict(metrics=report['metrics'],by_cwe=report['by_cwe'],gates=report['gates'],tokens=report['total_reported_tokens']),indent=2))


if __name__=='__main__':main()
