"""Audit saved model receipts and compare actual first-pass evidence."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from evaluation.calibrate_security_net import metrics


def load(path):
    rows = [json.loads(line) for line in path.read_text(encoding='utf8').splitlines() if line.strip()]
    return {r['idx']: r for r in rows if r.get('prediction') in (0, 1)}


def summarize(rows):
    calls = [t for r in rows.values() for t in r.get('arbitrate', {}).get('reasoning_trace', [])]
    errors = []
    for r in rows.values():
        if r['target'] != r['prediction']:
            errors.append({'idx': r['idx'], 'cwe': r.get('cwe'),
                'kind': 'FP' if r['prediction'] else 'FN', 'answer': r.get('raw_answer'),
                'steps': r.get('arbitrate', {}).get('reasoning_steps')})
    return {'metrics': metrics(list(rows.values()), [r['prediction'] for r in rows.values()]),
            'calls': len(calls), 'finish_reasons': dict(Counter(t.get('finish_reason') for t in calls)),
            'mean_completion_tokens': sum(t.get('completion_tokens') or 0 for t in calls) / max(1, len(calls)),
            'missing_action_calls': sum('action:' not in t.get('answer', '').lower() for t in calls),
            'steps': dict(Counter(r.get('arbitrate', {}).get('reasoning_steps') for r in rows.values())),
            'errors': errors}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('left', type=Path)
    p.add_argument('right', type=Path)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    left, right = load(a.left), load(a.right)
    if set(left) != set(right):
        raise ValueError('paired sample sets differ')
    mismatches = []
    for idx in sorted(left):
        if left[idx]['target'] != right[idx]['target']:
            raise ValueError('paired targets differ')
        traces = [r[idx].get('arbitrate', {}).get('reasoning_trace', []) for r in (left, right)]
        if not all(traces) or any('user_prompt' not in t[0] for t in traces):
            raise ValueError('complete first-pass trace required')
        if traces[0][0]['user_prompt'] != traces[1][0]['user_prompt']:
            mismatches.append(idx)
    report = {'protocol': 'fresh calls; paired evidence audited, API variability not isolated',
              'first_pass_user_prompt_mismatches': mismatches,
              'left': summarize(left), 'right': summarize(right)}
    a.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf8')
    print(json.dumps({**report, 'left': {k:v for k,v in report['left'].items() if k != 'errors'},
                     'right': {k:v for k,v in report['right'].items() if k != 'errors'}}, indent=2))


if __name__ == '__main__':
    main()
