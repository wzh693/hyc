"""Paired verifier summary; repeated answers stay in the same source cluster."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import random
from evaluation.calibrate_security_net import metrics


def summarize(rows):
    successful = [r for r in rows if 'error' not in r]
    keys = [(r['idx'], r['repeat']) for r in rows]
    if len(keys) != len(set(keys)):
        raise ValueError('duplicate function/repeat receipt')
    groups = defaultdict(list)
    for r in successful:
        groups[r['source_sha256']].append(r)
    def score(sample, name):
        return metrics(sample, [r[name+'_prediction'] for r in sample])
    changes = [r for r in successful if r['old_prediction'] != r['new_prediction']]
    counts = {'removed_fp':0, 'lost_tp':0, 'recovered_tp':0, 'added_fp':0}
    for r in changes:
        key = ('removed_fp' if r['target']==0 else 'lost_tp') if r['new_prediction']==0 \
              else ('recovered_tp' if r['target']==1 else 'added_fp')
        counts[key] += 1
    rng = random.Random(42)
    deltas = {'f1':[], 'accuracy':[]}
    clusters = list(groups.values())
    if not clusters:
        raise ValueError('no successful calls')
    for _ in range(2000):
        sample = [r for group in rng.choices(clusters,k=len(clusters)) for r in group]
        old, new = score(sample,'old'), score(sample,'new')
        for key in deltas:
            deltas[key].append(new[key]-old[key])
    return {'n_functions':len({r['idx'] for r in rows}), 'n_unique_source_clusters':len(groups),
        'n_calls':len(rows), 'n_errors':len(rows)-len(successful),
        'pooled_receipt_metrics':{name:score(successful,name) for name in ('main','old','new')},
        'changes_over_receipts':counts,
        'changed_function_indices':sorted({r['idx'] for r in changes}),
        'flip_counts':{name:sum(r[name+'_security_net']['flipped'] for r in successful)
                       for name in ('old','new')},
        'threshold_signal_counts':{name:sum(r[name+'_security_net']['triggered'] for r in successful)
                                   for name in ('old','new')},
        'repeat_disagreements':{name:sum(len({r[name+'_prediction'] for r in successful if r['idx']==idx})>1
            for idx in {r['idx'] for r in successful}) for name in ('main','old','new')},
        'delta_ci95_fixed_receipts':{key:[sorted(v)[50],sorted(v)[1950]] for key,v in deltas.items()},
        'total_reported_tokens':sum(r.get('tokens_used') or 0 for r in successful),
        'mean_shared_tokens':sum(r.get('tokens_used') or 0 for r in successful)/len(successful),
        'truncated_calls':sum(r['finish_reason']=='length' for r in successful),
        'note':'Development only; 60 calls do not equal 60 independent functions. '
               'CI resamples exact source clusters, not future API variability. '
               'Both verifiers share the same paid calls; neither adds LLM tokens.'}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('directory',type=Path)
    a = p.parse_args()
    rows = [json.loads(s) for s in (a.directory/'results.jsonl').read_text(encoding='utf8').splitlines()]
    result = summarize(rows)
    (a.directory/'summary.json').write_text(json.dumps(result,indent=2),encoding='utf8')
    print(json.dumps(result,indent=2))


if __name__ == '__main__': main()
