"""Label-blind, cached development-only API smoke; NOT a quality benchmark.

These CPGs were used for GAT training. GAT is disabled; nevertheless this tool
must not supply paper metrics or select thresholds. Its purpose is integration
and independent switch verification. Saves real requests, usage and failures.
"""
import argparse
import contextlib
import hashlib
import io
import json
import sys
from pathlib import Path
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cache', type=Path, default=ROOT/'output/devign_development300_20261005')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--n', type=int, default=3)
    parser.add_argument('--profiles', nargs='+', choices=['control','slice_only','contract_only',
                                                        'expansion_only','wired_candidate'])
    args = parser.parse_args()
    if args.n < 1:
        parser.error('n must be positive')
    if args.output.exists():
        raise ValueError('Use a new output directory; smoke receipts cannot be overwritten')
    args.output.mkdir(parents=True)
    import config
    from graph.pipeline import run_hgl_pipeline
    from reasoning.llm_api import create_client
    records = json.loads((args.cache/'meta.json').read_text(encoding='utf-8'))
    ordered = sorted((r for r in records.values() if not r.get('error')),
                     key=lambda r:(r['graph_nodes'], r['sample_id']))
    n = min(args.n, len(ordered))
    selected = [ordered[round(i*(len(ordered)-1)/max(1,n-1))] for i in range(n)]
    profiles = {'control': (False,False,False), 'slice_only': (True,False,False),
                'contract_only': (False,True,False), 'expansion_only': (False,False,True),
                'wired_candidate': (True,True,True)}
    if args.profiles:
        profiles = {name:profiles[name] for name in args.profiles}
    manifest = {'purpose':'API wiring smoke only; training-exposed development graphs, not paper metrics',
                'selection':'graph-size quantiles; labels ignored', 'profiles':profiles,
                'samples':selected, 'failed_features_enabled':False,
                'code_hashes':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
                    for folder in ('graph','linearization','reasoning','retrieval','planning')
                    for p in sorted((ROOT/folder).glob('*.py'))},
                'source_hashes':{r['sample_id']:hashlib.sha256(
                    (args.cache/r['sample_id']/'source.c').read_bytes()).hexdigest() for r in selected}}
    (args.output/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    client = create_client()
    # Configuration is changed only between batches, never while worker calls run.
    fixed = {'GRAPH_SECURITY_NET':False, 'USE_LEARNED_SUMMARIZE':False,
             'USE_LEARNED_PATH_RANK':False, 'USE_LEARNED_NODE_IMPORTANCE':False,
             'RECORD_REASONING_TRACE':True, 'COMPACT_THREE_PART_CONTEXT':True,
             'USE_LLM_ARBITRATION':False}
    rows = []
    for profile, (slicing,contract,expansion) in profiles.items():
        def run(record):
            sid = record['sample_id']
            source_path = args.cache/sid/'source.c'
            code = source_path.read_text(encoding='utf-8')
            try:
                result = run_hgl_pipeline(str(source_path), code, sid, str(args.cache/sid),
                                          client, ablation='', return_details=True)
                return {'profile':profile,'sample_id':sid,**result}
            except Exception as exc:
                return {'profile':profile,'sample_id':sid,'prediction':None,'error':str(exc)}
        settings = dict(fixed, USE_BACKWARD_SLICE=slicing, BOUNDED_OUTPUT_CONTRACT=contract,
                        EVIDENCE_EXPANSION=expansion)
        # scorer imports flags by value; explicitly freeze those too.
        import learning.scorer as scorer
        with contextlib.ExitStack() as stack:
            for name,value in settings.items():
                stack.enter_context(patch.object(config,name,value))
            for name in ('USE_LEARNED_SUMMARIZE','USE_LEARNED_PATH_RANK','USE_LEARNED_NODE_IMPORTANCE'):
                stack.enter_context(patch.object(scorer,name,False))
            with ThreadPoolExecutor(max_workers=min(3,n)) as pool:
                for row in pool.map(run, selected):
                    rows.append(row)
                    with (args.output/'receipts.jsonl').open('a',encoding='utf-8') as handle:
                        handle.write(json.dumps(row,ensure_ascii=False)+'\n')
                    print(f"SMOKE {profile} {row['sample_id']} steps={row.get('reasoning_steps')} tokens={row.get('tokens_used')} error={row.get('error')}",flush=True)
    summary = {}
    for profile in profiles:
        data = [r for r in rows if r['profile']==profile]
        traces = [t for r in data for t in r.get('arbitrate',{}).get('reasoning_trace',[])]
        summary[profile] = {'samples':len(data),'errors':sum(bool(r.get('error')) for r in data),
            'calls':len(traces),'total_tokens':sum(r.get('tokens_used',0) for r in data),
            'truncated_calls':sum(t.get('output_truncated',False) for t in traces),
            'incomplete_calls':sum(not t.get('output_fields_complete',False) for t in traces),
            'uncertain_samples':sum(r.get('prediction') is None for r in data),
            'slice_fallbacks':sum(r.get('module_audit',{}).get('backward_slice',{}).get('fallback',False) for r in data),
            'new_path_events':sum(len(r.get('module_audit',{}).get('expansion',{}).get('events',[])) for r in data)}
    (args.output/'summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    print(json.dumps(summary,indent=2))


if __name__ == '__main__':
    main()
