"""New group-sampled development inputs. Local Joern only; all model calls blocked."""
import argparse
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
import contextlib
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import random
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SETTINGS = {
    'USE_LEARNED_NODE_IMPORTANCE':'0','USE_LEARNED_SUMMARIZE':'0','USE_LEARNED_PATH_RANK':'0',
    'MAX_REASONING_STEPS':'2','STEP1_CONFIRM_STOP':'1','SOURCE_SLICE_ASSIGNMENT_FIX':'0',
    'COMPACT_THREE_PART_CONTEXT':'1','USE_LLM_ARBITRATION':'0','SELECTIVE_SECOND_PASS':'1',
    'USE_ZERO_TOKEN_SECURITY_NET':'1','SECURITY_NET_THRESHOLD':'4','GRAPH_SECURITY_NET':'0',
    'STRICT_OPERATION_TAGS':'0','F1_EVIDENCE_ROUTING':'0','STRUCTURED_PRIOR_SUMMARY':'0',
    'COMPACT_VERDICT_PROMPT':'0','FOCUSED_GRAPH_ANCHORS':'0','TYPE_COVERAGE_ROUTING':'0',
    'TYPE_COVERAGE_PROMPT':'1','HGL_ABL':'','JOERN_TIMEOUT_SECONDS':'180',
    'BUDGETED_EVIDENCE_GROUPS':'0','ACTION_BEFORE_REASONING':'0','OBSERVED_STATE_CANDIDATE':'0'}


def select_rows(rows,n,seed):
    groups=defaultdict(list)
    for r in rows: groups[r['group_id']].append(r)
    rng=random.Random(seed)
    keys=sorted(groups); rng.shuffle(keys)
    return [min(groups[key],key=lambda r:r['idx']) for key in keys[:n]]


def worker(meta,source,outdir):
    os.environ.update(SETTINGS)
    compare=importlib.import_module('modes.compare_devign')
    loop=importlib.import_module('reasoning.reasoning_loop')
    api=importlib.import_module('reasoning.llm_api')
    from linearization.evidence_windows import source_windows
    directory=Path(outdir)
    codepath=directory/'samples'/f"sample_{meta['idx']:06d}.c"
    cache=directory/'cpg'/meta['sample_id']
    captured=[]
    def blocked(*args,**kwargs): raise RuntimeError('model calls prohibited in preparation')
    def capture(prompt,client=None):
        captured.append(prompt)
        return 'HYPOTHESIS: no vulnerability detected\nACTION: {"action":"Stop"}',0
    try:
        with patch.object(api,'create_client',blocked),patch.object(api,'query_llm',blocked), \
                patch.object(loop,'query_llm_with_retry',capture),contextlib.redirect_stdout(io.StringIO()):
            compare._run_hgl_pipeline(str(codepath),source,meta['sample_id'],str(cache),None,4096)
            nodes,edges=compare.find_export_files(str(cache/'export'))
            graph=compare.load_graph(nodes,edges)
        if len(captured)!=1: raise ValueError('expected exactly one intercepted prompt')
        prompt=captured[0]
        prefix,tail=prompt.split('\n\nDEP PATHS:',1)
        old_src=prefix.removeprefix('SRC:\n')
        new_src=source_windows(source,graph,[],len(old_src)) or old_src
        return {'idx':meta['idx'],'target':meta['target'],'group_id':meta['group_id'],
            'source_sha256':hashlib.sha256(source.encode()).hexdigest(),
            'arbitrate':{'reasoning_trace':[{'step':1,'user_prompt':prompt}]},
            'experimental_user_prompt':'SRC:\n'+new_src+'\n\nDEP PATHS:'+tail,
            'graph_nodes':graph.number_of_nodes(),'graph_edges':graph.number_of_edges()}
    except Exception as exc:
        return {'idx':meta['idx'],'error':str(exc)}


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--n',type=int,default=30)
    p.add_argument('--workers',type=int,default=2)
    a=p.parse_args()
    os.environ.update(SETTINGS)
    from config import DEVIGN_JSON_PATH,JOERN_PARSE_CMD,JOERN_EXPORT_CMD
    protocol_dir=ROOT/'evaluation/protocol_clone_v2_20261005'
    audit=json.loads((protocol_dir/'audit.json').read_text(encoding='utf8'))
    blob=Path(DEVIGN_JSON_PATH).read_bytes()
    if hashlib.sha256(blob).hexdigest()!=audit['dataset_sha256']: raise ValueError('dataset changed')
    if not Path(JOERN_PARSE_CMD).is_file() or not Path(JOERN_EXPORT_CMD).is_file():
        raise FileNotFoundError('existing Joern installation missing')
    raw=json.loads(blob)
    development=json.loads((protocol_dir/'development.json').read_text(encoding='utf8'))
    if a.n<1 or a.n>len({r['group_id'] for r in development}): raise ValueError('invalid sample count')
    selected=select_rows(development,a.n,20261005)
    a.output.mkdir(parents=True,exist_ok=False)
    (a.output/'samples').mkdir()
    (a.output/'manifest.json').write_text(json.dumps(selected,indent=2),encoding='utf8')
    metadata=[];sources={}
    from evaluation.build_clean_protocol import code_hash
    for row in selected:
        code=raw[row['idx']]['func']
        if code_hash(code)!=row['source_sha256']: raise ValueError('manifest source mismatch')
        path=a.output/'samples'/f"sample_{row['idx']:06d}.c"
        path.write_text(code,encoding='utf8')
        metadata.append({**row,'target':raw[row['idx']]['target'],'sample_id':f"sample_{row['idx']:06d}",
                         'file_path':str(path.resolve())})
        sources[str(row['idx'])]={'input':code}
    (a.output/'metadata.json').write_text(json.dumps({'samples':metadata},indent=2),encoding='utf8')
    (a.output/'sources.json').write_text(json.dumps(sources,ensure_ascii=False),encoding='utf8')
    results=[]
    with (a.output/'preparation.jsonl').open('w',encoding='utf8') as out,ProcessPoolExecutor(max_workers=a.workers) as pool:
        jobs=[pool.submit(worker,m,sources[str(m['idx'])]['input'],str(a.output.resolve())) for m in metadata]
        for job in as_completed(jobs):
            record=job.result();results.append(record)
            out.write(json.dumps(record,ensure_ascii=False)+'\n');out.flush()
            print(f"Prepared {len(results)}/{a.n}: idx={record['idx']}, {'ERROR' if 'error' in record else 'OK'}",flush=True)
    successful=[r for r in results if 'error' not in r]
    with (a.output/'prompts.jsonl').open('w',encoding='utf8') as out:
        for r in sorted(successful,key=lambda r:r['idx']):out.write(json.dumps(r,ensure_ascii=False)+'\n')
    report={'seed':20261005,'requested':a.n,'prepared':len(successful),'errors':len(results)-len(successful),
        'sampling':'shuffle sorted development clone groups; lowest index representative, no label balancing',
        'api_calls':0,'configuration':SETTINGS,'dataset_sha256':audit['dataset_sha256'],
        'selection_manifest_sha256':hashlib.sha256((a.output/'manifest.json').read_bytes()).hexdigest(),
        'scope':'new development pilot, not independent final test; no silent replacement of failures',
        'planned_comparison':'type-covered HGL frozen first pass vs SRC-only windows, 60 calls if all 30 prepared'}
    (a.output/'protocol.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps(report,indent=2))


if __name__ == '__main__': main()
