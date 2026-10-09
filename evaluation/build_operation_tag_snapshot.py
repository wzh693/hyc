"""Prepare fixed development pairs with model access blocked in worker()."""
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path
from unittest.mock import patch
from evaluation.build_external_prompt_snapshot import worker, ROOT


def prepare(meta, expected):
    with patch('config.STRICT_OPERATION_TAGS', False):
        control, source = worker(meta)
    baseline = control['arbitrate']['reasoning_trace'][0]['user_prompt']
    if baseline != expected['arbitrate']['reasoning_trace'][0]['user_prompt']:
        raise ValueError(f"baseline prompt mismatch {meta['idx']}")
    with patch('config.STRICT_OPERATION_TAGS', True):
        candidate, candidate_source = worker(meta)
    if source != candidate_source:
        raise ValueError('source mismatch')
    control['experimental_user_prompt'] = candidate['arbitrate']['reasoning_trace'][0]['user_prompt']
    control['source_sha256'] = hashlib.sha256(source['input'].encode()).hexdigest()
    return control


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--output',type=Path,required=True)
    a = p.parse_args()
    folder = ROOT/'sven_eval/external_type_check'
    rows = [json.loads(s) for s in (folder/'prompts.jsonl').read_text(encoding='utf8').splitlines()]
    metadata = {m['idx']:m for m in json.loads((ROOT/'output/devign_calib_v21/metadata.json').read_text(encoding='utf8'))['samples']}
    if len(rows)!=30: raise ValueError('fixed 30-function scope required')
    a.output.mkdir(parents=True,exist_ok=False)
    results = []
    with ProcessPoolExecutor(max_workers=4) as pool:
        jobs = [pool.submit(prepare,metadata[r['idx']],r) for r in rows]
        for job in as_completed(jobs):
            results.append(job.result())
            print(f'Prepared {len(results)}/30 pairs, zero model calls',flush=True)
    with (a.output/'prompts.jsonl').open('w',encoding='utf8') as out:
        for r in sorted(results,key=lambda r:r['idx']): out.write(json.dumps(r,ensure_ascii=False)+'\n')
    report = {'samples':30,'api_calls':0,
        'changed_inputs':sum(r['experimental_user_prompt']!=r['arbitrate']['reasoning_trace'][0]['user_prompt'] for r in results),
        'protocol':'STRICT_OPERATION_TAGS only; cached graphs; fixed development rows; old baseline inputs verified',
        'changes_include_ranking_and_anchors':True}
    (a.output/'protocol.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps(report,indent=2))


if __name__ == '__main__': main()
