"""Conservative replay of the API-presence override on saved Devign runs."""
import argparse
import json
import re
from pathlib import Path

from evaluation.calibrate_security_net import metrics
from graph.security_net import zero_token_verify
from reasoning.reasoning_loop import _extract_vulnerability_type


def replay(path):
    payload = json.loads(path.read_text(encoding='utf8'))
    rows = [r for r in payload['results_b'] if r.get('prediction') in (0, 1)]
    after = []
    changes = []
    missing = 0
    for row in rows:
        pred = row['prediction']
        audit = row.get('arbitrate') or {}
        text = row.get('raw_answer', '')
        hypothesis = re.search(r'HYPOTHESIS:\s*([^\n]+)', text, re.I)
        # Only replace a recorded generic override, never a concrete type or a
        # separate arbitration verdict. Do not infer from a cut-off hypothesis.
        candidate = (pred == 1 and audit.get('vulnerability_type') == 'Generic Vulnerability'
                     and not audit.get('triggered') and hypothesis
                     and '\n' in text[hypothesis.start():]
                     and _extract_vulnerability_type(text, True) == 'Unknown')
        if candidate:
            source = path.parent / 'samples' / f"sample_{int(row['idx']):06d}.c"
            if not source.exists():
                missing += 1
            else:
                pred, record = zero_token_verify(0, source.read_text(encoding='utf8'), 4)
                if pred != row['prediction']:
                    changes.append({'idx': row['idx'], 'target': row['target'],
                                    'hypothesis': hypothesis.group(1), 'signal': record['signal']})
        after.append(pred)
    return {'input': str(path), 'protocol': 'saved-response replay, no API calls',
            'before': metrics(rows, [r['prediction'] for r in rows]),
            'after': metrics(rows, after), 'changes': changes,
            'corrected_fp': sum(c['target'] == 0 for c in changes),
            'introduced_fn': sum(c['target'] == 1 for c in changes),
            'missing_source': missing, 'extra_tokens': 0}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('reports', nargs='+', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    results = [replay(path) for path in args.reports]
    args.output.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding='utf8')
    for result in results:
        print(json.dumps({k: v for k, v in result.items() if k != 'changes'}, indent=2))


if __name__ == '__main__':
    main()
