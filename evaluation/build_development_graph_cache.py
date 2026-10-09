"""Freeze a larger label-blind development batch; prepare CPGs only, no LLM."""
import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path

from evaluation.build_clean_development_pilot import select_rows
from evaluation.build_clean_protocol import code_hash

ROOT = Path(__file__).resolve().parents[1]


def select_unexposed(rows, exclusions, n, seed):
    excluded_groups = {r['group_id'] for r in exclusions}
    eligible = [r for r in rows if r['group_id'] not in excluded_groups]
    if not 0 < n <= len({r['group_id'] for r in eligible}):
        raise ValueError('Requested size exceeds unexposed development groups')
    return select_rows(eligible,n,seed)


def prepare_one(meta, code, directory):
    os.environ['JOERN_TIMEOUT_SECONDS']='180'
    from graph.build_cpg import build_cpg
    from graph.load_graph import load_graph_from_dot
    from learning.gat_model import graph_to_arrays
    from learning.train_gat import GRAPH_CACHE_VER
    import numpy as np
    import torch
    torch.set_num_threads(1)
    directory=Path(directory)
    sample=directory/meta['sample_id']
    source_path=sample/'source.c'
    sample.mkdir(exist_ok=True)
    if source_path.exists():
        if source_path.read_text(encoding='utf8') != code:
            raise ValueError('Refusing to overwrite a different source')
    else:
        source_path.write_text(code,encoding='utf8')
    result={**meta,'source_raw_sha256':hashlib.sha256(code.encode()).hexdigest()}
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            build_cpg(str(source_path),str(sample))
            graph=load_graph_from_dot(str(sample/'export/export.dot'))
            arrays=graph_to_arrays(graph,code)
        if arrays is None:raise ValueError('Empty feature graph')
        arrays['target']=int(meta['target'])
        np.savez(sample/(GRAPH_CACHE_VER+'.npz'),**arrays)
        result.update(graph_nodes=graph.number_of_nodes(),graph_edges=graph.number_of_edges(),
                      positioned_nodes=sum(n.get('line_number') is not None for _,n in graph.nodes(data=True)),
                      graph_cache_ver=GRAPH_CACHE_VER)
    except Exception as exc:
        result['error']=str(exc)
    return result


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--n',type=int,default=300)
    parser.add_argument('--seed',type=int,default=20261006)
    parser.add_argument('--workers',type=int,default=2)
    parser.add_argument('--resume',action='store_true')
    parser.add_argument('--exclude-current-exposure', action='store_true',
                        help='Exclude whole development groups present in all recorded local exposure')
    args=parser.parse_args()
    if args.workers<1:parser.error('workers must be positive')
    from config import DEVIGN_JSON_PATH, JOERN_PARSE_CMD, JOERN_EXPORT_CMD
    print('PREP preflight: checking installed Joern',flush=True)
    if not all(Path(p).is_file() for p in (JOERN_PARSE_CMD,JOERN_EXPORT_CMD)):
        raise FileNotFoundError('Existing Joern installation unavailable')
    protocol=ROOT/'evaluation/protocol_clone_v2_20261005'
    audit=json.loads((protocol/'audit.json').read_text(encoding='utf8'))
    print('PREP preflight: reading fixed dataset',flush=True)
    blob=Path(DEVIGN_JSON_PATH).read_bytes()
    if hashlib.sha256(blob).hexdigest()!=audit['dataset_sha256']:
        raise ValueError('Dataset version mismatch')
    rows=json.loads((protocol/'development.json').read_text(encoding='utf8'))
    # Exclude whole groups, not just the 30 selected function indices.
    prior=ROOT/'output/devign_clean_pilot_20261005/manifest.json'
    exclusions=json.loads(prior.read_text(encoding='utf8'))
    exposure_receipt = None
    if args.exclude_current_exposure:
        print('PREP preflight: inventorying recorded exposure',flush=True)
        from evaluation.build_clean_protocol import inventory_exposure
        exposed, hashes, artifacts = inventory_exposure(ROOT, audit['n_raw'], read_sources=False)
        current = [r for r in rows if r['idx'] in exposed or r['source_sha256'] in hashes]
        exclusions += current
        exposure_receipt = {'excluded_development_groups':len({r['group_id'] for r in exclusions}),
            'artifacts':[{**entry, 'sha256':hashlib.sha256((ROOT/entry['path']).read_bytes()).hexdigest()}
                         for entry in artifacts], 'limitations':'Only recorded local exposure is known.'}
        print(f'PREP preflight: excluded {len(exclusions)} recorded development rows',flush=True)
    selected=select_unexposed(rows,exclusions,args.n,args.seed)
    manifest_bytes=json.dumps(selected,indent=2).encode('utf8')
    protocol_record={'seed':args.seed,'requested':args.n,'dataset_sha256':audit['dataset_sha256'],
        'manifest_sha256':hashlib.sha256(manifest_bytes).hexdigest(),
        'excluded_manifest_sha256':hashlib.sha256(prior.read_bytes()).hexdigest(),
        'sampling':'one lowest-index representative per shuffled unexposed development group; no label balancing',
        'api_calls':0,'status':'CPG development preparation only; validation and locked_test untouched',
        'failures':'record all failures; no sample replacement or favorable subset selection'}
    if exposure_receipt is not None:
        protocol_record['current_exposure_exclusion'] = exposure_receipt
    if args.resume:
        if (args.output/'manifest.json').read_bytes()!=manifest_bytes:
            raise ValueError('Resume selection mismatch')
        if json.loads((args.output/'protocol.json').read_text(encoding='utf8'))!=protocol_record:
            raise ValueError('Resume protocol mismatch')
    else:
        args.output.mkdir(parents=True,exist_ok=False)
        (args.output/'manifest.json').write_bytes(manifest_bytes)
        (args.output/'protocol.json').write_text(json.dumps(protocol_record,indent=2),encoding='utf8')
    raw=json.loads(blob)
    metadata=[]
    for row in selected:
        source=raw[row['idx']]
        if code_hash(source['func'])!=row['source_sha256']:
            raise ValueError('Manifest source mismatch')
        metadata.append({**row,'sample_id':f"sample_{row['idx']:06d}",'target':int(source['target'])})
    receipts=args.output/'preparation.jsonl'
    previous={}
    if receipts.exists():
        for line in receipts.read_text(encoding='utf8').splitlines():
            r=json.loads(line);previous[r['sample_id']]=r
    from graph.build_cpg import _dot_has_func_method
    for record in previous.values():
        if 'error' not in record and not _dot_has_func_method(str(args.output/record['sample_id']/'export/export.dot')):
            record['error']='Cached graph failed updated defined-function validation; retry required'
    jobs_meta=[m for m in metadata if m['sample_id'] not in previous or 'error' in previous[m['sample_id']]]
    with receipts.open('a',encoding='utf8') as handle,ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures=[pool.submit(prepare_one,m,raw[m['idx']]['func'],str(args.output.resolve())) for m in jobs_meta]
        completed=0
        for future in as_completed(futures):
            record=future.result();previous[record['sample_id']]=record;completed+=1
            handle.write(json.dumps(record,ensure_ascii=False)+'\n');handle.flush()
            print(f"CPG {completed}/{len(jobs_meta)} idx={record['idx']} "+
                  (('ERROR '+record['error'][:120]) if 'error' in record else f"OK nodes={record['graph_nodes']}"),flush=True)
    # Include failures in metadata, so downstream training reports excluded rows.
    (args.output/'meta.json').write_text(json.dumps(previous,indent=2),encoding='utf8')
    errors=[r for r in previous.values() if 'error' in r]
    report={**protocol_record,'prepared':len(previous)-len(errors),'errors':len(errors),
            'labels_after_selection':dict(Counter(str(m['target']) for m in metadata)),
            'error_indices':[r['idx'] for r in errors]}
    (args.output/'preparation_report.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps(report,indent=2),flush=True)


if __name__=='__main__':main()
