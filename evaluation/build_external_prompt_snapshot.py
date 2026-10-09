"""Prepare a balanced non-SVEN development check with model access blocked."""
import contextlib
from concurrent.futures import ProcessPoolExecutor, as_completed
import importlib
import io
import json
from pathlib import Path
import random
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def worker(meta):
    compare = importlib.import_module('modes.compare_devign')
    loop = importlib.import_module('reasoning.reasoning_loop')
    api = importlib.import_module('reasoning.llm_api')
    def blocked(*args, **kwargs):
        raise RuntimeError('model access prohibited during snapshot preparation')
    prompts = []
    def capture(prompt, client=None):
        prompts.append(prompt)
        return 'HYPOTHESIS: no vulnerability detected\nACTION: {"action":"Stop"}', 0
    source = ROOT/'output/devign_calib_v21/samples'/f"sample_{meta['idx']:06d}.c"
    code = source.read_text(encoding='utf8',errors='replace')
    cache = ROOT/'output/devign_calib_v21/cpg'/meta['sample_id']
    export = cache/'export'
    if not (export/'export.dot').exists():
        raise ValueError('existing CPG cache required')
    with patch.object(api,'create_client',blocked), patch.object(api,'query_llm',blocked), \
            patch.object(compare,'build_cpg',return_value=str(export)), \
            patch.object(loop,'query_llm_with_retry',capture), contextlib.redirect_stdout(io.StringIO()):
        compare._run_hgl_pipeline(str(source),code,meta['sample_id'],str(cache),None,4096)
    if len(prompts)!=1: raise ValueError('first-pass interception failed')
    return {'idx':meta['idx'],'target':meta['target'], 'arbitrate':{
        'reasoning_trace':[{'step':1,'user_prompt':prompts[0]}]}}, {'input':code}


def main():
    metadata = json.loads((ROOT/'output/devign_calib_v21/metadata.json').read_text(encoding='utf8'))['samples']
    rng = random.Random(20261003)
    selected = []
    for label in (0,1):
        group = sorted([m for m in metadata if m['target']==label],key=lambda m:m['idx'])
        selected.extend(rng.sample(group,15))
    outdir = ROOT/'sven_eval/external_type_check'
    outdir.mkdir(exist_ok=True)
    if any(outdir.iterdir()): raise ValueError('output directory must be empty')
    rows, sources = [], {}
    with ProcessPoolExecutor(max_workers=4) as pool:
        jobs = [pool.submit(worker,m) for m in selected]
        for n, job in enumerate(as_completed(jobs),1):
            row, source = job.result()
            rows.append(row); sources[str(row['idx'])] = source
            print(f'{n}/{len(jobs)} snapshots, zero model calls',flush=True)
    with (outdir/'prompts.jsonl').open('w',encoding='utf8') as out:
        for row in sorted(rows,key=lambda r:r['idx']):out.write(json.dumps(row,ensure_ascii=False)+'\n')
    (outdir/'sources.json').write_text(json.dumps(sources,ensure_ascii=False),encoding='utf8')
    (outdir/'protocol.json').write_text(json.dumps({'dataset':'Devign existing calibration subset',
        'seed':20261003,'n':len(rows),'selection':'15 per label, seeded random',
        'api_calls':0,'cpg_protocol':'existing cached DOT, no Joern rebuild; original cache provenance is historical',
        'not_independent_publication_test':True},indent=2),encoding='utf8')


if __name__ == '__main__':
    main()
