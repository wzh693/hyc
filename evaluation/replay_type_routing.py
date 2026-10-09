"""Development replay of source-operation routing; zero API calls."""
import json
from pathlib import Path

from reasoning.prompts import needs_expanded_types
from evaluation.calibrate_security_net import metrics


def main():
    root = Path(__file__).resolve().parents[1]
    def load(name):
        return {r['idx']:r for r in map(json.loads,
            (root/'sven_eval'/name/'sven_results.jsonl').read_text(encoding='utf8').splitlines())}
    base = load('output_type_coverage_control_full')
    covered = load('output_type_coverage_full')
    if set(base) != set(covered): raise ValueError('incomplete paired runs')
    rows = []
    chosen = []
    for idx in sorted(base):
        a, b = base[idx], covered[idx]
        prompt = a['arbitrate']['reasoning_trace'][0]['user_prompt']
        if prompt != b['arbitrate']['reasoning_trace'][0]['user_prompt']:
            raise ValueError('evidence mismatch')
        use = needs_expanded_types(prompt)
        row = dict(b if use else a)
        row['mode'] = 'type_routing_saved_replay'
        row['pipeline_fp'] = 'saved_response_routing_not_fresh'
        row['routing_covered'] = use
        rows.append(row)
        if use: chosen.append(idx)
    path = root/'sven_eval/type_routing_saved_replay.jsonl'
    with path.open('w',encoding='utf8') as out:
        for row in rows: out.write(json.dumps(row,ensure_ascii=False)+'\n')
    result = {'protocol':'development saved-response routing replay, not fresh benchmark; zero API calls',
        'selected_coverage_rows':len(chosen), 'selected_indices':chosen,
        'metrics':metrics(rows,[r['prediction'] for r in rows]),
        'mean_replayed_tokens':sum(r['tokens_used'] for r in rows)/len(rows), 'by_cwe':{}}
    for cwe in sorted({r['cwe'] for r in rows}):
        group = [r for r in rows if r['cwe']==cwe]
        result['by_cwe'][cwe] = metrics(group,[r['prediction'] for r in group])
    (root/'sven_eval/type_routing_saved_replay_report.json').write_text(json.dumps(result,indent=2),encoding='utf8')
    print(json.dumps({k:v for k,v in result.items() if k!='selected_indices'},indent=2))


if __name__ == '__main__':
    main()
