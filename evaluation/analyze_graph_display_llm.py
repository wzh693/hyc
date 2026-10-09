"""Post-run full-cohort diagnostics, never new primary quality gates or tuning."""
import argparse
from collections import Counter,defaultdict
import json
from pathlib import Path
from evaluation.evaluate_reconstructed_llm import digest,read_json


def analyze(run):
    manifest=read_json(run/'manifest.json');audit=read_json(run/'audit.json')
    if not audit['passed']:raise ValueError('Audit required before post-hoc diagnostics')
    for name,expected in audit['artifact_sha256'].items():
        if digest(run/name)!=expected:raise ValueError('Audited run changed')
    rows=[json.loads(line) for line in (run/'results.jsonl').read_text(encoding='utf8').splitlines()]
    calls=[json.loads(line) for line in (run/'api_receipts.jsonl').read_text(encoding='utf8').splitlines()]
    summaries={}
    for profile in manifest['profiles']:
        for rep in (1,2):
            batch=[r for r in rows if r['profile']==profile and r['repeat']==rep]
            if len(batch)!=254:raise ValueError('Not a full-cohort diagnostic')
            macro={}
            for unit in ('source_sha256','group_id'):
                groups=defaultdict(list)
                for r in batch:groups[r[unit]].append(r)
                macro[unit]=dict(units=len(groups),mean_accuracy=sum(sum(r.get('prediction')==r['target'] for r in group)/len(group) for group in groups.values())/len(groups))
            summaries[f'{profile}/r{rep}']=dict(macro_accuracy=macro,
                source_security_net_flips=sum(bool(r.get('arbitrate',{}).get('security_net',{}).get('flipped')) for r in batch),
                reasoning_step_counts=dict(Counter(r.get('reasoning_steps','failed') for r in batch)),
                effective_output_rate=sum(r.get('prediction') in (0,1) and not r.get('error') for r in batch)/254)
    source_groups=defaultdict(list)
    for sample in manifest['samples']:source_groups[sample['source_sha256']].append(sample)
    conflicts=[members for members in source_groups.values() if len({s['target'] for s in members})>1]
    example=[]
    for r in rows:
        if r['idx']!=214:continue
        observed=[c for c in calls if (c['idx'],c['profile'],c['repeat'])==(r['idx'],r['profile'],r['repeat'])]
        contexts=[''.join(c['request']['messages'][1]['content'].split()) for c in observed]
        example.append(dict(profile=r['profile'],repeat=r['repeat'],target=r['target'],prediction=r.get('prediction'),
            main_pred=r.get('arbitrate',{}).get('main_pred'),reasoning_steps=r.get('reasoning_steps'),
            len_update_in_any_actual_request=any('len=ptr-line' in text for text in contexts),
            pointer_update_in_any_actual_request=any('line=ptr+1' in text for text in contexts),
            first_answer=next((c.get('answer') for c in observed if not c.get('error')),None)))
    result=dict(post_hoc=True,primary_denominator_unchanged=1016,full_cohort_summaries=summaries,
        exact_source_conflict_groups=len(conflicts),conflict_rows=sum(len(g) for g in conflicts),
        fixed_preexisting_mechanism_example_214=example,new_model_calls=0,
        input_artifact_sha256=audit['artifact_sha256'],analysis_tool_sha256=digest(__file__),
        limitations=['Macro accuracy is supplemental and uses all74 sources/36 groups, not a selected-read subset.',
            'Security-net flips are counts, not an alternate primary prediction or proof of net benefit.',
            'idx214 is a preexisting diagnostic example, not a success selected to establish causality.',
            'Equal expressions cannot distinguish occurrences; source/guard/capacity completeness remains unknown.'])
    dest=run/'posthoc_diagnostics.json'
    if dest.exists():raise ValueError('Do not overwrite post-hoc diagnostics')
    dest.write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf8')
    print(json.dumps(result,indent=2,ensure_ascii=False))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--run',required=True,type=Path);analyze(parser.parse_args().run)
