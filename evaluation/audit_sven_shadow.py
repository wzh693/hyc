"""Label-blind SRC visibility proxy on frozen SVEN shadow; zero model calls."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
from evaluation.audit_evidence_preservation import classify_lines,src_segment,visible_lines,CATEGORIES


def main():
    p=argparse.ArgumentParser();p.add_argument('--preflight',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    if args.output.exists():raise ValueError('Never overwrite an audit')
    manifest=json.loads((args.preflight/'manifest.json').read_text(encoding='utf8'))
    dataset=Path(manifest['dataset'])
    if hashlib.sha256(dataset.read_bytes()).hexdigest()!=manifest['dataset_sha256']:raise ValueError('Dataset changed')
    data=json.loads(dataset.read_text(encoding='utf8'))
    shadows=json.loads((args.preflight/'shadow.json').read_text(encoding='utf8'))
    samples={s['idx']:s for s in manifest['samples']}
    if {s['idx'] for s in shadows}!=set(samples) or len(shadows)!=len(samples):raise ValueError('Schedule differs')
    rows=[]
    for shadow in shadows:
        idx=shadow['idx'];source=data[idx]['input']
        categories=classify_lines(source)
        segment=src_segment(shadow['user_prompt'])
        shown,ambiguous=visible_lines(source,segment)
        rows.append({'idx':idx,'group_id':samples[idx]['group_id'],
            'source_sha256':samples[idx]['source_sha256'],'source_chars':len(source),'src_chars':len(segment),
            'categories':{name:{'source_candidate_lines':len(lines),'unique_visible':len(lines&shown),
                'ambiguous_visible':len(lines&ambiguous),'not_exactly_visible':len(lines-shown-ambiguous)}
                for name,lines in categories.items()}})
    exact=defaultdict(list)
    for row in rows:exact[row['source_sha256']].append(row)
    # Source duplicates can have different graph contexts; averages, not chosen best representatives.
    totals={name:{field:sum(r['categories'][name][field] for r in rows)
                  for field in ('source_candidate_lines','unique_visible','ambiguous_visible','not_exactly_visible')}
            for name in CATEGORIES}
    report={'samples':len(rows),'unique_sources':len(exact),'category_row_totals':totals,
        'samples_with_not_exactly_visible_by_category':{name:sum(r['categories'][name]['not_exactly_visible']>0 for r in rows) for name in CATEGORIES},
        'rows':rows,'api_calls':0,'prediction_changes':0,'ground_truth_used':False,
        'limitations':['Regex candidates are not proven guards or vulnerabilities.',
            'Exact unique whole-line visibility proxy; duplicated lines are ambiguous and counted separately.',
            'Absence from SRC does not establish absence from DEP/STATE, lost semantics or causal prediction error.',
            'Rows correlated; no quality subgroup selection or hypothesis promotion.']}
    args.output.write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps({k:v for k,v in report.items() if k!='rows'},indent=2))


if __name__=='__main__':main()
