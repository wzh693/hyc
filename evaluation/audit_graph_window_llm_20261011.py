"""Read-only actual-answer replay, full receipts and denominator audit."""
import argparse
from collections import defaultdict
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch
from evaluation import run_graph_window_llm_20261011 as runner


def replay(run,arm):
    manifest,requests,stages,data=runner.prepare()
    runner.SOURCE=Path(manifest['source_roots'][arm])
    runtime=runner.Runtime(manifest,stages,True)
    rows=[json.loads(line) for line in (run/'results.jsonl').read_text(encoding='utf8').splitlines() if json.loads(line)['profile']==arm]
    calls=defaultdict(list)
    for line in (run/'api_receipts.jsonl').read_text(encoding='utf8').splitlines():
        call=json.loads(line)
        if call['profile']==arm: calls[call['idx'],call['repeat']].append(call)
    samples={s['idx']:s for s in manifest['samples']}
    with runtime.patches(True),patch('time.sleep',lambda seconds:None),contextlib.redirect_stdout(io.StringIO()):
        for row in rows:
            sample=samples[row['idx']]; own=calls[row['idx'],row['repeat']]; position=[0]
            runtime.local.idx=row['idx']; runtime.local.profile=arm; runtime.local.prepared={}
            def answer(**request):
                if position[0]>=len(own): raise ValueError('Replay lacks saved response')
                call=own[position[0]];position[0]+=1
                if request!=call['request']: raise ValueError('Actual request differs in replay')
                if call.get('error'): raise RuntimeError(call['error'])
                return SimpleNamespace(model=call.get('model'),usage=SimpleNamespace(**{k:call.get(k) for k in ('total_tokens','prompt_tokens','completion_tokens')}),
                    choices=[SimpleNamespace(finish_reason=call.get('finish_reason'),message=SimpleNamespace(content=call['answer']))])
            client=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=answer)))
            try:
                value=runtime.pipeline.run_hgl_pipeline(sample['source_path'],data[row['idx']]['input'],sample['sample_id'],sample['cache_path'],client,4096,return_details=True)
                value['tokens_used']=sum(c.get('total_tokens') or 0 for c in own)
                if row.get('error'): raise ValueError('Saved error did not replay')
                for key in ('prediction','vulnerability_type','reasoning_steps','module_audit','arbitrate','tokens_used','conclusion'):
                    if value[key]!=row[key]: raise ValueError('Replay result mismatch: '+key)
            except Exception:
                if not row.get('error'): raise
            if position[0]!=len(own): raise ValueError('Unconsumed response')
    if len(rows)!=508 or runtime.blocked_attempts: raise ValueError('Incomplete replay/external attempt')
    return len(rows)


def audit(run):
    manifest,requests,_,_=runner.prepare()
    if runner.read_json(run/'manifest.json')!=manifest: raise ValueError('Freeze mismatch')
    for group,hashes in [('code_snapshot',manifest['source_hashes']['display']),('control_snapshot',manifest['source_hashes']['control']),('tooling_snapshot',manifest['tooling_hashes'])]:
        for name,expected in hashes.items():
            if runner.digest(run/group/name)!=expected: raise ValueError('Snapshot mismatch')
    rows=[json.loads(line) for line in (run/'results.jsonl').read_text(encoding='utf8').splitlines()]
    calls=[json.loads(line) for line in (run/'api_receipts.jsonl').read_text(encoding='utf8').splitlines()]
    report=runner.summarize(rows,calls,manifest)
    if report!=runner.read_json(run/'report.json'): raise ValueError('Report recomputation mismatch')
    own=defaultdict(list)
    for c in calls: own[c['idx'],c['profile'],c['repeat']].append(c)
    for key,records in own.items():
        successes=0;attempts=defaultdict(int);frozen={}
        for call in records:
            step=successes+1;attempts[step]+=1
            if call['step']!=step or call['attempt']!=attempts[step] or step>2 or attempts[step]>3: raise ValueError('Bound/order violation')
            if step==1 and call['request']!=requests[key[0],key[1]]: raise ValueError('First request mismatch')
            if step in frozen and call['request']!=frozen[step]: raise ValueError('Retry mutation')
            frozen[step]=call['request'];successes+=not bool(call.get('error'))
            if call.get('usage_known') and call['prompt_tokens']+call['completion_tokens']!=call['total_tokens']: raise ValueError('Usage mismatch')
    replayed=0
    for arm in runner.PROFILES:
        result=subprocess.run([sys.executable,'-B','-m','evaluation.audit_graph_window_llm_20261011','--run',str(run),'--replay-arm',arm],cwd=runner.ROOT,capture_output=True,text=True,encoding='utf8',errors='replace')
        if result.returncode: raise ValueError('Replay failed '+arm+': '+result.stdout+result.stderr)
        replayed+=508
    return dict(passed=True,scheduled_results=len(rows),replayed_results=replayed,actual_invocations=len(calls),
        source_files={p:len(v) for p,v in manifest['source_hashes'].items()},new_api_calls=0,
        functional_gate=report['functional_gate'],exploratory_support=report['exploratory_support'],
        artifact_sha256={n:runner.digest(run/n) for n in ('manifest.json','results.jsonl','api_receipts.jsonl','report.json')})


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--run',required=True,type=Path);parser.add_argument('--replay-arm',choices=runner.PROFILES)
    args=parser.parse_args()
    if args.replay_arm: print(replay(args.run,args.replay_arm))
    else:
        result=audit(args.run);dest=args.run/'audit.json'
        if dest.exists(): raise ValueError('Audit already exists')
        dest.write_text(json.dumps(result,indent=2),encoding='utf8');print(json.dumps(result,indent=2))
