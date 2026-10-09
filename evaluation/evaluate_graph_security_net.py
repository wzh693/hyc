"""Fresh, shared LLM predictions; paired old/graph verifier development check."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import contextlib
import hashlib
import io
import importlib
import json
from pathlib import Path
from unittest.mock import patch

from evaluation.calibrate_security_net import metrics
from graph.security_net import zero_token_verify
from graph.security_net_graph import zero_token_graph_verify
from reasoning.llm_api import create_client
from reasoning.prompts import SYSTEM_PROMPT
from reasoning.reasoning_loop import _extract_vulnerability_type
from config import LLM_MODEL, SECURITY_NET_THRESHOLD

ROOT = Path(__file__).resolve().parents[1]


def prepare(row, source, metadata):
    import modes.compare_devign as compare
    loop = importlib.import_module('reasoning.reasoning_loop')
    import reasoning.llm_api as api
    cache = ROOT/'output/devign_calib_v21/cpg'/metadata['sample_id']
    export = cache/'export'
    if not (export/'export.dot').exists():
        raise ValueError('cached graph required')
    captured = {}
    original = compare.retrieve_topk
    def retrieve(*args, **kwargs):
        paths = original(*args, **kwargs)
        captured['paths'] = paths
        return paths
    def blocked(*args, **kwargs):
        raise RuntimeError('model access blocked during preparation')
    def capture(prompt, client=None):
        captured['prompt'] = prompt
        return 'HYPOTHESIS: no vulnerability detected\nACTION: {"action":"Stop"}', 0
    with patch.object(compare, 'build_cpg', return_value=str(export)), \
            patch.object(compare, 'retrieve_topk', retrieve), \
            patch.object(api, 'create_client', blocked), patch.object(api, 'query_llm', blocked), \
            patch.object(loop, 'query_llm_with_retry', capture), \
            contextlib.redirect_stdout(io.StringIO()):
        compare._run_hgl_pipeline('', source, metadata['sample_id'], str(cache), None, 4096)
        nodes, edges = compare.find_export_files(str(export))
        graph = compare.load_graph(nodes, edges)
    prompt = row['arbitrate']['reasoning_trace'][0]['user_prompt']
    if captured.get('prompt') != prompt:
        raise ValueError(f"frozen prompt mismatch: {row['idx']}")
    return graph, captured['paths']


def call(row, source, graph, paths, repeat, system):
    prompt = row['arbitrate']['reasoning_trace'][0]['user_prompt']
    base = {'idx': row['idx'], 'target': row['target'], 'repeat': repeat,
            'prompt_sha256': hashlib.sha256(prompt.encode()).hexdigest(),
            'source_sha256': hashlib.sha256(source.encode()).hexdigest()}
    try:
        response = create_client().chat.completions.create(model=LLM_MODEL,
            messages=[{'role':'system', 'content':system}, {'role':'user', 'content':prompt}],
            temperature=0, max_tokens=150)
        answer = response.choices[0].message.content or ''
        main = int(_extract_vulnerability_type(answer, is_final=False) != 'Unknown')
        old, old_info = zero_token_verify(main, source, SECURITY_NET_THRESHOLD)
        new, new_info = zero_token_graph_verify(main, graph, paths, SECURITY_NET_THRESHOLD)
        return {**base, 'main_prediction':main, 'old_prediction':old, 'new_prediction':new,
                'old_security_net':old_info, 'new_security_net':new_info, 'raw_answer':answer,
                'model':response.model, 'finish_reason':response.choices[0].finish_reason,
                'tokens_used':response.usage.total_tokens if response.usage else None}
    except Exception as exc:
        return {**base, 'error':str(exc), 'main_prediction':None,
                'old_prediction':None, 'new_prediction':None}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    folder = ROOT/'sven_eval/external_type_check'
    rows = [json.loads(line) for line in (folder/'prompts.jsonl').read_text(encoding='utf8').splitlines()]
    sources = json.loads((folder/'sources.json').read_text(encoding='utf8'))
    meta = {m['idx']:m for m in json.loads((ROOT/'output/devign_calib_v21/metadata.json').read_text(encoding='utf8'))['samples']}
    if len(rows) != 30 or len({r['idx'] for r in rows}) != 30:
        raise ValueError('fixed 30-function scope required')
    a.output.mkdir(parents=True, exist_ok=False)
    system = SYSTEM_PROMPT.replace('Buffer Overflow, Taint',
        'Buffer Overflow, Out-of-Bounds Read, Integer Overflow, Taint')
    protocol = {'samples':30, 'repeats':2, 'planned_api_calls':60, 'system_prompt':system,
        'configured_model':LLM_MODEL, 'threshold':SECURITY_NET_THRESHOLD,
        'scope':'existing development functions; single-pass, not full adaptive evaluation',
        'comparison':'one shared fresh answer per function/repeat; two zero-token verifiers',
        'limitations':['Not independent held-out evidence.', 'Graph reachability is not symbolic feasibility.',
                       'Repeated calls are not additional independent functions.'],
        'pipeline_fingerprint':__import__('modes.compare_devign',fromlist=['_pipeline_fingerprint'])._pipeline_fingerprint()}
    (a.output/'protocol.json').write_text(json.dumps(protocol,indent=2),encoding='utf8')
    prepared = {}
    for i, row in enumerate(rows, 1):
        prepared[row['idx']] = prepare(row, sources[str(row['idx'])]['input'], meta[row['idx']])
        print(f'Prepared {i}/30, no model calls',flush=True)
    results = []
    with (a.output/'results.jsonl').open('w',encoding='utf8') as out, ThreadPoolExecutor(max_workers=4) as pool:
        jobs = [pool.submit(call,r,sources[str(r['idx'])]['input'],*prepared[r['idx']],repeat,system)
                for repeat in range(2) for r in rows]
        for job in as_completed(jobs):
            record = job.result(); results.append(record)
            out.write(json.dumps(record,ensure_ascii=False)+'\n'); out.flush()
            print(f'Completed {len(results)}/60 calls',flush=True)
    report = {**protocol,'n_errors':sum('error' in r for r in results),'runs':[]}
    for repeat in range(2):
        group = [r for r in results if r['repeat']==repeat and 'error' not in r]
        for name in ('main','old','new'):
            report['runs'].append({'repeat':repeat,'variant':name,
                'metrics':metrics(group,[r[name+'_prediction'] for r in group])})
    report['changed_predictions'] = [r for r in results if r['old_prediction'] != r['new_prediction']]
    report['actual_reported_tokens'] = sum(r.get('tokens_used') or 0 for r in results)
    (a.output/'report.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('changed_predictions','system_prompt')},indent=2))


if __name__ == '__main__': main()
