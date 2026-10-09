"""Saved-input-defined exposure decomposition, not a selected-success score."""
from collections import Counter
import json
from pathlib import Path
from evaluation.evaluate_reconstructed_llm import read_json, digest

ROOT=Path(__file__).resolve().parents[1]
RUN=ROOT/'output/graph_read_slice_llm120_20261009'


def main():
    manifest=read_json(RUN/'manifest.json')
    rows=[json.loads(s) for s in (RUN/'results.jsonl').read_text(encoding='utf8').splitlines()]
    indexed={(r['idx'],r['profile'],r['repeat']):r for r in rows}
    if len(indexed)!=120 or len(rows)!=120: raise ValueError('Incomplete/duplicate planned rows')
    changed={s['idx'] for s in manifest['samples'] if manifest['first_request_sha256'][f'control/{s["idx"]}']!=manifest['first_request_sha256'][f'read_slice/{s["idx"]}']}
    scopes={}
    for name,indices in [('changed_input',changed),('unchanged_input',{s['idx'] for s in manifest['samples']}-changed)]:
        values=[s for s in manifest['samples'] if s['idx'] in indices]
        per_repeat={}
        for rep in (1,2):
            lost=gained=differ=0
            for s in values:
                a,b=[indexed[s['idx'],p,rep]['prediction'] for p in ('control','read_slice')]
                differ+=a!=b; lost+=a==s['target'] and b!=s['target']; gained+=a!=s['target'] and b==s['target']
            per_repeat[str(rep)]=dict(prediction_disagreements=differ,control_correct_candidate_wrong=lost,
                                     control_wrong_candidate_correct=gained,net_correct_delta=gained-lost)
        scopes[name]=dict(rows=len(values),indices=sorted(indices),by_cwe=dict(Counter(s['cwe'] for s in values)),repeats=per_repeat)
    result=dict(scopes=scopes,new_api_calls=0,selection_rule='Exact first-request hashes frozen before live model calls, independent of answers/labels.',
                full_scored_denominator=120,report_sha256=digest(RUN/'report.json'),
                limitations=['Changed-input subset is diagnostic, not a replacement score denominator or independent evaluation.',
                             'Unchanged-input disagreement reflects stochastic/provider/time or later-step differences, not first-SRC policy benefit.',
                             'Both profiles share150 output budget and retained legacy decisions; no causal significance claim.'])
    destination=RUN/'effective_pairs.json'
    if destination.exists(): raise ValueError('Do not overwrite decomposition')
    destination.write_text(json.dumps(result,indent=2),encoding='utf8'); print(json.dumps(result,indent=2))


if __name__=='__main__': main()
