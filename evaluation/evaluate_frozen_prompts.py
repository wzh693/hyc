"""Repeat paired first-pass calls on frozen evidence; no graph or extra retrieval."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import re
from pathlib import Path

from reasoning.llm_api import create_client
from reasoning.prompts import SYSTEM_PROMPT, COMPACT_SYSTEM_PROMPT, BOUNDED_OBSERVATION_PROMPT
from reasoning.reasoning_loop import _extract_vulnerability_type
from graph.security_net import zero_token_verify
from config import LLM_MODEL, SECURITY_NET_THRESHOLD
from evaluation.calibrate_security_net import metrics


def run_pair(row, source, repeat, variant):
    trace = row['arbitrate']['reasoning_trace']
    prompt = trace[0]['user_prompt']
    if variant == 'focused_anchors' and prompt == row['experimental_user_prompt']:
        saved = trace[0]
        answer = saved['answer']
        kind = _extract_vulnerability_type(answer, is_final=False)
        pred, net = zero_token_verify(int(kind != 'Unknown'), source, SECURITY_NET_THRESHOLD)
        base = {'idx':row['idx'], 'target':row['target'], 'repeat':repeat,
            'prediction':pred, 'raw_answer':answer, 'tokens_used':saved['tokens_used'],
            'completion_tokens':saved.get('completion_tokens'), 'finish_reason':saved.get('finish_reason'),
            'model':saved.get('model'), 'reused_unchanged_evidence':True,
            'prompt_sha256':hashlib.sha256(prompt.encode('utf8')).hexdigest(),
            'source_prompt_sha256':hashlib.sha256(prompt.encode('utf8')).hexdigest(),
            'max_output_tokens':150, 'security_net':net}
        return [{**base, 'variant':name} for name in ('control', variant)]
    client = create_client()
    records = []
    covered = SYSTEM_PROMPT.replace('Buffer Overflow, Taint',
        'Buffer Overflow, Out-of-Bounds Read, Integer Overflow, Taint')
    experimental = {'format_only': COMPACT_SYSTEM_PROMPT,
                    'bounded_observation': BOUNDED_OBSERVATION_PROMPT,
                    'token_rebalance': SYSTEM_PROMPT,
                    'focused_anchors': SYSTEM_PROMPT,
                    'type_coverage': covered, 'covered_compact_state':covered,
                    'strict_operation_tags':covered, 'evidence_windows':covered}[variant]
    control_system = covered if variant in ('covered_compact_state','strict_operation_tags','evidence_windows') else SYSTEM_PROMPT
    variants = [('control', control_system), (variant, experimental)]
    if (row['idx'] + repeat) % 2:
        variants.reverse()
    for name, system in variants:
        actual_prompt = prompt
        max_tokens = 150
        if name in ('focused_anchors','strict_operation_tags','evidence_windows'):
            actual_prompt = row['experimental_user_prompt']
        if name in ('token_rebalance', 'covered_compact_state'):
            actual_prompt = re.sub(r'EXPLORATION STATE:\n.*?\n\nAnalyze SRC',
                'EXPLORATION STATE: initial; no actions executed.\n\nAnalyze SRC',
                prompt, count=1, flags=re.S)
            if actual_prompt == prompt:
                raise ValueError('expected initial exploration state block')
            max_tokens = 220 if name == 'token_rebalance' else 150
        response = client.chat.completions.create(model=LLM_MODEL,
            messages=[{'role':'system','content':system}, {'role':'user','content':actual_prompt}],
            temperature=0, max_tokens=max_tokens)
        answer = response.choices[0].message.content or ''
        kind = _extract_vulnerability_type(answer, is_final=False)
        pred, net = zero_token_verify(int(kind != 'Unknown'), source, SECURITY_NET_THRESHOLD)
        records.append({'idx':row['idx'], 'target':row['target'], 'repeat':repeat,
            'variant':name, 'prediction':pred, 'raw_answer':answer,
            'tokens_used':response.usage.total_tokens if response.usage else 0,
            'completion_tokens':response.usage.completion_tokens if response.usage else None,
            'finish_reason':response.choices[0].finish_reason, 'model':response.model,
            'prompt_sha256':hashlib.sha256(actual_prompt.encode('utf8')).hexdigest(),
            'source_prompt_sha256':hashlib.sha256(prompt.encode('utf8')).hexdigest(),
            'max_output_tokens':max_tokens, 'security_net':net})
    return records


def main():
    p = argparse.ArgumentParser()
    p.add_argument('input', type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--repeats', type=int, default=2)
    p.add_argument('--workers', type=int, default=4)
    p.add_argument('--sources', type=Path)
    p.add_argument('--variant', choices=['format_only', 'bounded_observation', 'token_rebalance', 'focused_anchors', 'type_coverage', 'covered_compact_state', 'strict_operation_tags', 'evidence_windows'], default='format_only')
    a = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    sources = json.loads((a.sources or root/'sven_eval/data/sven_test.json').read_text(encoding='utf8'))
    rows = [json.loads(line) for line in a.input.read_text(encoding='utf8').splitlines() if line.strip()]
    if any(not r.get('arbitrate', {}).get('reasoning_trace') for r in rows):
        raise ValueError('complete frozen first-pass traces required')
    # This experiment isolates one call. Do not compare its metrics to a multi-step full run.
    a.output.mkdir(parents=True, exist_ok=False)
    results = []
    with (a.output/'results.jsonl').open('w', encoding='utf8') as out, ThreadPoolExecutor(max_workers=a.workers) as pool:
        futures = [pool.submit(run_pair, r,
                   sources[str(r['idx']) if isinstance(sources,dict) else r['idx']]['input'], repeat, a.variant)
                   for repeat in range(a.repeats) for r in rows]
        for i, future in enumerate(as_completed(futures), 1):
            pair = future.result()
            results.extend(pair)
            for record in pair:
                out.write(json.dumps(record, ensure_ascii=False)+'\n')
            out.flush()
            print(f'{i}/{len(futures)} paired calls completed', flush=True)
    report = {'protocol':'frozen first-pass user prompts; paired interleaved calls; single-pass parser plus security net',
              'samples':len(rows), 'repeats':a.repeats,
              'actual_api_calls':sum(not r.get('reused_unchanged_evidence', False) for r in results),
              'reused_records':sum(r.get('reused_unchanged_evidence', False) for r in results),
              'system_prompts': {'control': (SYSTEM_PROMPT.replace('Buffer Overflow, Taint',
                   'Buffer Overflow, Out-of-Bounds Read, Integer Overflow, Taint')
                   if a.variant in ('covered_compact_state','strict_operation_tags','evidence_windows') else SYSTEM_PROMPT), a.variant:
                  {'format_only':COMPACT_SYSTEM_PROMPT, 'bounded_observation':BOUNDED_OBSERVATION_PROMPT,
                   'token_rebalance':SYSTEM_PROMPT, 'focused_anchors':SYSTEM_PROMPT,
                   'type_coverage':SYSTEM_PROMPT.replace('Buffer Overflow, Taint',
                       'Buffer Overflow, Out-of-Bounds Read, Integer Overflow, Taint'),
                   'strict_operation_tags':SYSTEM_PROMPT.replace('Buffer Overflow, Taint',
                       'Buffer Overflow, Out-of-Bounds Read, Integer Overflow, Taint'),
                   'evidence_windows':SYSTEM_PROMPT.replace('Buffer Overflow, Taint',
                       'Buffer Overflow, Out-of-Bounds Read, Integer Overflow, Taint'),
                   'covered_compact_state':SYSTEM_PROMPT.replace('Buffer Overflow, Taint',
                       'Buffer Overflow, Out-of-Bounds Read, Integer Overflow, Taint')}[a.variant]},
              'runs':[]}
    for repeat in range(a.repeats):
        for variant in ('control', a.variant):
            group = [r for r in results if r['repeat']==repeat and r['variant']==variant]
            report['runs'].append({'repeat':repeat, 'variant':variant,
                'metrics':metrics(group,[r['prediction'] for r in group]),
                'mean_tokens':sum(r['tokens_used'] for r in group)/len(group),
                'truncated':sum(r['finish_reason']=='length' for r in group),
                'missing_action':sum('action:' not in r['raw_answer'].lower() for r in group)})
    (a.output/'report.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps(report,indent=2))


if __name__ == '__main__':
    main()
