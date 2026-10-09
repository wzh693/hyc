"""Summarize development experiments without treating repeated rows as new samples."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import random

from evaluation.calibrate_security_net import metrics


def summarize(directory, sources):
    rows = [json.loads(s) for s in (directory/'results.jsonl').read_text(encoding='utf8').splitlines() if s.strip()]
    paired = defaultdict(dict)
    variants = {r['variant'] for r in rows} - {'control'}
    if len(variants) != 1:
        raise ValueError('one experimental variant expected')
    variant = variants.pop()
    for r in rows:
        key = (r['idx'], r['repeat'])
        if r['variant'] in paired[key]:
            raise ValueError('duplicate paired receipt')
        paired[key][r['variant']] = r
    if any(set(pair) != {'control',variant} for pair in paired.values()):
        raise ValueError('incomplete paired calls')
    clusters = defaultdict(list)
    for key, pair in paired.items():
        a, b = pair['control'], pair[variant]
        # Earlier pure-system-format experiments used identical user prompts
        # and stored their hash directly, before transformed prompts were added.
        ah = a.get('source_prompt_sha256', a['prompt_sha256'])
        bh = b.get('source_prompt_sha256', b['prompt_sha256'])
        if a['target'] != b['target'] or ah != bh:
            raise ValueError('paired source or target mismatch')
        source = sources[str(key[0]) if isinstance(sources, dict) else key[0]]['input']
        digest = hashlib.sha256(source.encode('utf8')).hexdigest()
        clusters[digest].append(pair)
    def score(pairs):
        a = [p['control'] for p in pairs]
        b = [p[variant] for p in pairs]
        return metrics(a,[r['prediction'] for r in a]), metrics(b,[r['prediction'] for r in b])
    original = list(paired.values())
    a, b = score(original)
    rng = random.Random(42)
    groups = list(clusters.values())
    deltas = []
    for _ in range(2000):
        sample = [pair for group in rng.choices(groups,k=len(groups)) for pair in group]
        x, y = score(sample)
        deltas.append(y['f1']-x['f1'])
    deltas.sort()
    repeat_predictions = defaultdict(lambda:defaultdict(set))
    for row in rows:
        repeat_predictions[row['variant']][row['idx']].add(row['prediction'])
    report = json.loads((directory/'report.json').read_text(encoding='utf8'))
    return {'directory':str(directory), 'variant':variant,
        'samples':len({r['idx'] for r in rows}), 'unique_source_clusters':len(clusters),
        'repeat_count':len({r['repeat'] for r in rows}),
        'control_pooled_calls_metrics':a, 'experimental_pooled_calls_metrics':b,
        'delta_f1':b['f1']-a['f1'], 'source_cluster_delta_f1_ci95':[deltas[50],deltas[1950]],
        'repeat_prediction_disagreements':{v:sum(len(p)>1 for p in values.values())
                                            for v,values in repeat_predictions.items()},
        'runs':report['runs'], 'actual_api_calls':report.get('actual_api_calls',len(rows)),
        'note':'Development only. Pooled calls are not independent samples. CI resamples source clusters over fixed receipts; it does not estimate all future API variability.'}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('directories', nargs='+', type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--sources', type=Path)
    a = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    sources = json.loads((a.sources or root/'sven_eval/data/sven_test.json').read_text(encoding='utf8'))
    reports = [summarize(d,sources) for d in a.directories]
    a.output.write_text(json.dumps(reports,ensure_ascii=False,indent=2),encoding='utf8')
    for report in reports:
        print(json.dumps({k:v for k,v in report.items() if k != 'runs'},indent=2))


if __name__ == '__main__':
    main()
