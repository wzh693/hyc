"""Execute one real pipeline/mock per row, not duplicated cached requests."""
import argparse
import contextlib
import importlib
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch

from evaluation.preflight_graph_display import read, sha, digest, graph_hash
from evaluation.test_graph_guided_foundation import verify_foundation

ROOT=Path(__file__).resolve().parents[1]
STAGE=ROOT/'output/source_statement_fidelity_preflight_20261011'


def bindings():
    base=verify_foundation()
    manifest=read(STAGE/'manifest.json')
    report=read(STAGE/'report.json')
    if not report['pass'] or sha(STAGE/'rows.jsonl')!=report['rows_sha256']:
        raise ValueError('Full paired stage preflight missing or changed')
    for arm,hashes in manifest['source_hashes'].items():
        for name,expected in hashes.items():
            if sha(Path(manifest['source_roots'][arm])/name)!=expected:
                raise ValueError('Source drift')
    for name,expected in manifest['tooling_hashes'].items():
        if sha(ROOT/name)!=expected: raise ValueError('Stage tool drift')
    return base,manifest,report


def worker(output,arm):
    base,manifest,_=bindings()
    os.environ.update(base['settings'])
    os.environ['OPENAI_API_KEY']='offline-not-a-key'
    source=Path(manifest['source_roots'][arm])
    sys.path.insert(0,str(source))
    pipeline=importlib.import_module('graph.pipeline')
    api=importlib.import_module('reasoning.llm_api')
    if not Path(pipeline.__file__).resolve().is_relative_to(source): raise ValueError('Wrong source root')
    from evaluation.audit_type_coverage_baseline import memoized_search
    stages={r['idx']:r for r in (json.loads(s) for s in (STAGE/'rows.jsonl').read_text(encoding='utf8').splitlines()) if r['profile']==arm}
    data=read(manifest['dataset'])
    originals={n:getattr(pipeline,n) for n in ('load_graph','summarize_graph','extract_all_candidate_paths')}
    prepared={}
    external=[0]
    active={}
    def blocked(*a,**k): external[0]+=1; raise RuntimeError('External access forbidden')
    def cached(name,*a,**k):
        key=(active['identity'],name,graph_hash(a[0]) if name=='extract_all_candidate_paths' else None)
        if key not in prepared: prepared[key]=originals[name](*a,**k)
        value=prepared[key]
        return value.copy() if name!='extract_all_candidate_paths' else [list(p) for p in value]
    def retrieve(graph,candidates,*a,**k):
        stage=stages[active['idx']]
        if graph_hash(graph)!=stage['path_graph_hash'] or digest(candidates)!=stage['candidate_paths_sha256']:
            raise ValueError('Regenerated graph/candidates differ from fully ranked stage')
        if any(p not in candidates for p in stage['topk']): raise ValueError('Invalid cached TopK')
        return [list(p) for p in stage['topk']]
    output.mkdir(parents=True)
    rows=[]
    with contextlib.ExitStack() as stack:
        for obj,name in [(socket.socket,'connect'),(socket,'create_connection'),(api,'create_client')]:
            stack.enter_context(patch.object(obj,name,blocked))
        stack.enter_context(patch('subprocess.Popen',blocked))
        stack.enter_context(patch.object(pipeline,'build_cpg',side_effect=lambda src,cache:str(Path(cache)/'export')))
        for name in originals:
            stack.enter_context(patch.object(pipeline,name,side_effect=lambda *a,_name=name,**k:cached(_name,*a,**k)))
        stack.enter_context(patch.object(pipeline,'retrieve_topk',side_effect=retrieve))
        stack.enter_context(patch.object(re,'search',memoized_search(re.search)))
        for sample in manifest['samples']:
            idx=sample['idx']; active.update(idx=idx,identity=(sample['source_sha256'],sample['cpg_sha256']))
            own=[]
            def mock(**request):
                own.append(request)
                return SimpleNamespace(model='offline-mock',usage=SimpleNamespace(total_tokens=0,prompt_tokens=0,completion_tokens=0),
                    choices=[SimpleNamespace(finish_reason='stop',message=SimpleNamespace(content='HYPOTHESIS: no vulnerability detected\nACTION: {"action":"Stop"}'))])
            row=dict(idx=idx,arm=arm,error=None)
            try:
                if sha(sample['source_path'])!=sample['wrapped_source_sha256'] or sha(Path(sample['cache_path'])/'export/export.dot')!=sample['cpg_sha256']:
                    raise ValueError('Input drift')
                code=data[idx]['input']
                import hashlib
                if hashlib.sha256(code.encode()).hexdigest()!=sample['source_sha256']: raise ValueError('Source drift')
                client=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=mock)))
                with contextlib.redirect_stdout(io.StringIO()):
                    pipeline.run_hgl_pipeline(sample['source_path'],code,sample['sample_id'],sample['cache_path'],client,4096,return_details=True)
                if len(own)!=1 or own[0]!=stages[idx]['request']:
                    raise ValueError('Actual per-row request differs from stage recipe/count')
                row['request_sha256']=digest(own[0])
            except Exception as exc:
                row['error']=repr(exc)
            row['actual_mock_calls']=len(own)
            rows.append(row)
            with (output/'rows.jsonl').open('a',encoding='utf8') as handle:
                handle.write(json.dumps(row,ensure_ascii=False)+'\n')
    bindings()
    result=dict(rows=len(rows),actual_mock_calls=sum(r['actual_mock_calls'] for r in rows),
        errors=sum(bool(r['error']) for r in rows),external_attempts=external[0])
    (output/'report.json').write_text(json.dumps(result,indent=2),encoding='utf8')
    if result['errors'] or external[0] or result['actual_mock_calls']!=254: raise SystemExit('Runtime proof failed')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--arm',choices=['control','display'])
    args=parser.parse_args()
    if os.environ.get('PYTHONHASHSEED')!='0': raise ValueError('Startup seed0 required')
    if args.output.exists(): raise ValueError('Fresh output required')
    if args.arm: return worker(args.output,args.arm)
    _,manifest,stage_report=bindings()
    frozen=dict(tool_sha256=sha(__file__),stage_rows_sha256=stage_report['rows_sha256'],manifest=manifest)
    args.output.mkdir(parents=True)
    (args.output/'manifest.json').write_text(json.dumps(frozen,indent=2,ensure_ascii=False),encoding='utf8')
    def launch(arm):
        result=subprocess.run([sys.executable,'-B','-m','evaluation.verify_source_statement_runtime_20261011',
            '--output',str((args.output/arm).resolve()),'--arm',arm],cwd=ROOT,capture_output=True,text=True,encoding='utf8',errors='replace')
        (args.output/f'{arm}.log').write_text(result.stdout+'\n'+result.stderr,encoding='utf8')
        return result.returncode
    with ThreadPoolExecutor(max_workers=2) as pool: codes=list(pool.map(launch,['control','display']))
    parts={arm:read(args.output/arm/'report.json') for arm in ('control','display')}
    result=dict(arms=parts,exit_codes=codes,actual_mock_calls=sum(r['actual_mock_calls'] for r in parts.values()),new_api_calls=0,
        passed=not any(codes) and all(r['rows']==254 and r['actual_mock_calls']==254 and not r['errors'] and not r['external_attempts'] for r in parts.values()),
        clarification='Stage tool materializes508 recipes with exact-input cache reuse; this proof actually executes508 per-row pipelines/mocks.')
    if sha(__file__)!=frozen['tool_sha256'] or bindings()[1]!=manifest: raise ValueError('Freeze drift')
    (args.output/'report.json').write_text(json.dumps(result,indent=2),encoding='utf8')
    print(json.dumps(result,indent=2),flush=True)
    if not result['passed']: raise SystemExit('Runtime proof failed')


if __name__=='__main__': main()
