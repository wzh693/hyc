"""Compare SVEN runs with source-cluster confidence intervals."""
import argparse
import json
import random
from collections import defaultdict
from pathlib import Path

from sven_eval.data.compare_sven_runs import _load_run, _metrics, compare


def clustered_comparison(left, right, dataset, repeats=2000):
    report = compare(left, right)
    _, a = _load_run(left)
    _, b = _load_run(right)
    data = json.loads(dataset.read_text(encoding='utf8'))
    groups = defaultdict(list)
    for idx in sorted(a.keys() & b.keys()):
        expected = int(data[idx]['output'] == 'VULNERABLE')
        if a[idx]['target'] != expected or b[idx]['target'] != expected:
            raise ValueError(f'dataset label mismatch at {idx}')
        groups[data[idx]['input']].append(idx)
    clusters = list(groups.values())
    rng = random.Random(42)
    deltas = {'accuracy': [], 'f1': []}
    for _ in range(repeats):
        indices = [i for group in rng.choices(clusters, k=len(clusters)) for i in group]
        lm = _metrics([a[i] for i in indices])
        rm = _metrics([b[i] for i in indices])
        for metric in deltas:
            deltas[metric].append(rm[metric] - lm[metric])
    intervals = {}
    for metric, values in deltas.items():
        values.sort()
        intervals[metric] = [values[int(repeats * .025)], values[min(repeats - 1, int(repeats * .975))]]
    consistent = [g for g in clusters if len({a[i]['target'] for i in g}) == 1]
    # Deterministic representative: lowest dataset index, selected independently
    # of predictions. Exclusion is supplementary; official rows remain above.
    representatives = [min(g) for g in consistent]
    report['source_clusters'] = {
        'n_unique': len(clusters), 'n_conflicting': len(clusters) - len(consistent),
        'bootstrap_repeats': repeats, 'seed': 42,
        'delta_95pct_ci': intervals,
        'consistent_unique_lowest_index': {
            'left': _metrics([a[i] for i in representatives]),
            'right': _metrics([b[i] for i in representatives]),
        },
        'note': 'Row McNemar assumes independent rows; source-cluster CI accounts for exact duplicates. Neither isolates API run variability.'
    }
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('left', type=Path)
    parser.add_argument('right', type=Path)
    parser.add_argument('--dataset', type=Path, default=Path('sven_eval/data/sven_test.json'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = clustered_comparison(args.left, args.right, args.dataset)
    args.output.write_text(json.dumps(report, indent=2), encoding='utf8')
    print(json.dumps({'left': report['left']['metrics'], 'right': report['right']['metrics'],
                      'paired': report['paired'], 'source_clusters': report['source_clusters']}, indent=2))


if __name__ == '__main__':
    main()
