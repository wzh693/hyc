"""Post-hoc saved-receipt diagnosis, not another test or causal proof."""
from collections import defaultdict
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT/'output/sven_complete_src_eval_20261008'


def main():
    def read(path): return json.loads(path.read_text(encoding='utf-8-sig'))
    manifest, report = read(RUN/'manifest.json'), read(RUN/'report.json')
    data = read(Path(manifest['dataset']))
    rows = [json.loads(s) for s in (RUN/'results.jsonl').read_text(encoding='utf8').splitlines()]
    calls = [json.loads(s) for s in (RUN/'api_receipts.jsonl').read_text(encoding='utf8').splitlines()]
    indexed = {(r['idx'], r['profile'], r['repeat']): r for r in rows}
    first = {}
    for c in calls: first.setdefault((c['idx'], c['profile'], c['repeat']), c)
    flips, group_scores = {}, defaultdict(lambda: dict(n=0, control_correct=0, candidate_correct=0, files=set()))
    for rep in (1, 2):
        for cwe in ('CWE-125', 'CWE-190', 'CWE-416'):
            lost, gained = [], []
            for s in manifest['samples']:
                if s['cwe'] != cwe: continue
                a, b = indexed[s['idx'], 'control', rep], indexed[s['idx'], 'complete_src', rep]
                ga, gb = a['prediction'] == s['target'], b['prediction'] == s['target']
                if ga and not gb: lost.append(s['idx'])
                if gb and not ga: gained.append(s['idx'])
                if cwe == 'CWE-125' and rep == 1:
                    group = group_scores[s['group_id']]
                    group['n'] += 1; group['control_correct'] += ga; group['candidate_correct'] += gb
                    group['files'].add(data[s['idx']]['file_name'])
            flips[f'{cwe}/r{rep}'] = dict(correct_to_wrong=len(lost), wrong_to_correct=len(gained), lost_indices=lost, gained_indices=gained)
    ranked = []
    for group_id, scores in group_scores.items():
        scores['files'] = sorted(scores['files'])
        scores['net_correct_delta'] = scores['candidate_correct']-scores['control_correct']
        ranked.append(dict(group_id=group_id, **scores))
    ranked.sort(key=lambda g: (g['net_correct_delta'], g['group_id']))
    cases = []
    # Fixed descriptive selection after results: first loss of each label in the
    # three most negative groups. Never use them as independent confirmation.
    for group in ranked[:3]:
        for target in (0, 1):
            eligible = [s for s in manifest['samples'] if s['cwe'] == 'CWE-125' and s['group_id'] == group['group_id'] and s['target'] == target and s['idx'] in flips['CWE-125/r1']['lost_indices']]
            if not eligible: continue
            s = min(eligible, key=lambda s: s['idx'])
            cases.append(dict(idx=s['idx'], target=target, file=data[s['idx']]['file_name'], group_id=s['group_id'],
                control_answer=first[s['idx'], 'control', 1]['answer'], candidate_answer=first[s['idx'], 'complete_src', 1]['answer']))
    source_usage = {}
    for rep in (1, 2):
        a, b = report['metrics'][f'control/r{rep}'], report['metrics'][f'complete_src/r{rep}']
        first_a = sum(first[s['idx'], 'control', rep]['prompt_tokens'] for s in manifest['samples'])
        first_b = sum(first[s['idx'], 'complete_src', rep]['prompt_tokens'] for s in manifest['samples'])
        source_usage[str(rep)] = dict(all_call_token_growth_pct=100*(b['total_tokens']/a['total_tokens']-1),
                                    first_prompt_tokens_control=first_a, first_prompt_tokens_candidate=first_b,
                                    first_prompt_growth_pct=100*(first_b/first_a-1))
    result = dict(new_api_calls=0, source_usage=source_usage, flips=flips, primary_cwe125_groups=ranked, posthoc_cases=cases,
        limitations=['Groups and cases selected descriptively after results, not causal or independent evidence.',
                     'Do not use these cases to tune and retest within the consumed authorization.'])
    destination = RUN/'failure_diagnosis.json'
    if destination.exists(): raise ValueError('Do not overwrite diagnosis')
    destination.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf8')
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == '__main__': main()
