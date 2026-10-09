"""Archive pilot and prespecified negative-recovery replay without extra calls."""
import argparse
import json
from pathlib import Path
from evaluation.calibrate_security_net import metrics


def summarize(pilot):
    rows=[json.loads(s) for s in (pilot/'window_pairs/results.jsonl').read_text(encoding='utf8').splitlines()]
    hgl={r['idx']:r for r in rows if r['variant']=='control'}
    direct={r['idx']:r for r in map(json.loads,(pilot/'direct_llm/results.jsonl').read_text(encoding='utf8').splitlines())}
    if set(hgl)!=set(direct): raise ValueError('baseline indices mismatch')
    valid=[]
    for idx,a in sorted(hgl.items()):
        b=direct[idx]
        if a['target']!=b['target']: raise ValueError('label mismatch')
        if b['prediction'] is None: continue
        valid.append((a,b))
    labels=[a for a,b in valid]
    result={'paired_valid_functions':len(valid),'n_direct_errors':len(direct)-len(valid),
        'hgl_metrics':metrics(labels,[a['prediction'] for a,b in valid]),
        'direct_metrics':metrics(labels,[b['prediction'] for a,b in valid]),
        'offline_negative_recovery':{
            'metrics':metrics(labels,[max(a['prediction'],b['prediction']) for a,b in valid]),
            'selected_second_pass_calls':sum(a['prediction']==0 for a,b in valid),
            'replayed_mean_tokens':sum(a['tokens_used']+(b['tokens_used'] if a['prediction']==0 else 0)
                                       for a,b in valid)/len(valid),
            'policy':'Keep HGL positive; only HGL negative receives full-source binary check.',
            'status':'Post-hoc feasibility replay, not an implemented/fresh adaptive run.'},
        'actual_total_api_calls':len(rows)+len(direct),
        'actual_total_reported_tokens':sum(r.get('tokens_used') or 0 for r in rows+list(direct.values())),
        'limitations':['One new development batch, not held-out validation.',
                       'Direct calls occurred after paired HGL calls; not interleaved.',
                       'Different baseline formats/output budgets; not sole-graph causal ablation.',
                       'Replay does not measure adaptive state effects or future provider variability.',
                       'No rules or thresholds selected from individual error labels.']}
    return result


def main():
    p=argparse.ArgumentParser();p.add_argument('pilot',type=Path);a=p.parse_args()
    report=summarize(a.pilot)
    (a.pilot/'comparison.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps(report,indent=2))


if __name__ == '__main__': main()
