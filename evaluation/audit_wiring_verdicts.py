"""Offline diagnosis of completed receipts; no relabelling or model calls."""
import argparse
from collections import Counter
import hashlib
import importlib
import json
from pathlib import Path
import re
from evaluation.evaluate_wiring_quality import prediction_code_hashes


def audit(directory):
    manifest=json.loads((directory/'manifest.json').read_text(encoding='utf-8'))
    rows=[json.loads(line) for line in (directory/'results.jsonl').read_text(encoding='utf-8').splitlines()]
    module=importlib.import_module('reasoning.reasoning_loop')
    last_answers={}
    for line in (directory/'api_receipts.jsonl').read_text(encoding='utf-8').splitlines():
        receipt=json.loads(line)
        if not receipt.get('error'):
            last_answers[(receipt['sample_id'],receipt['profile'],receipt['repeat'])]=receipt.get('answer','')
    results={}
    for profile in manifest['profiles']:
        batch=[r for r in rows if r['profile']==profile and r['repeat']==1]
        hypotheses=Counter();missed=[];invalid=0
        for row in batch:
            trace=row.get('arbitrate',{}).get('reasoning_trace',[])
            answer=(trace[-1].get('answer') if trace else None) or last_answers.get(
                (row['sample_id'],profile,1),'')
            match=re.search(r'HYPOTHESIS:\s*([^\n]*)',answer,re.I)
            hypothesis=match.group(1).strip() if match else '(missing)'
            hypotheses[hypothesis]+=1
            invalid+=bool(row.get('module_audit',{}).get('output_incomplete'))
            # Narrow unambiguous, standard-vocabulary positives only. Never
            # reinterpret Benign/Uncertain or qualified hypotheses as labels.
            if hypothesis.lower() in {'uaf','use-after-free','double free','buffer overflow',
                'out-of-bounds read','integer overflow','taint','null deref','memory leak'}:
                if module._extract_vulnerability_type(answer,is_final=True)=='Unknown':
                    missed.append({'sample_id':row['sample_id'],'hypothesis':hypothesis})
        slice_audits=[r.get('module_audit',{}).get('backward_slice',{}) for r in batch]
        events=[event for r in batch for event in r.get('module_audit',{}).get('expansion',{}).get('events',[])]
        results[profile]={'hypothesis_counts':dict(hypotheses),'unambiguous_type_parser_misses':missed,
            'incomplete_output_samples':invalid,
            'slice_fallbacks':sum(bool(a.get('fallback')) for a in slice_audits),
            'slices_with_budget_omissions':sum(a.get('omitted_lines',0)>0 for a in slice_audits),
            'slice_node_cap_hits':sum(bool(a.get('node_cap_hit')) for a in slice_audits),
            'expansion_events':len(events),'events_with_new_paths':sum(e['new_paths']>0 for e in events),
            'two_step_samples':sum(r.get('reasoning_steps',0)>1 for r in batch)}
    return {'prediction_code_matches_current':manifest['code_hashes']==prediction_code_hashes(),
            'profiles':results,'api_calls':0,'prediction_changes':0,
            'scope':'Offline standard-vocabulary parser and execution audit; no reinterpretation of ground truth.'}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('directory',type=Path)
    parser.add_argument('--filename',default='verdict_audit.json');args=parser.parse_args()
    if Path(args.filename).name!=args.filename:raise ValueError('Audit filename must be a basename')
    result=audit(args.directory);destination=args.directory/args.filename
    if destination.exists():raise ValueError('Refusing to overwrite audit')
    destination.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
