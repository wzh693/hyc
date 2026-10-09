"""Historical actual inputs vs repaired frozen shadow; no causal quality claim."""
import argparse
import hashlib
import json
from pathlib import Path
from evaluation.audit_evidence_preservation import src_segment


def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    if args.output.exists():raise ValueError('Never overwrite a comparison')
    root=Path(__file__).resolve().parents[1]
    old=root/'output/sven_full_pipeline_eval_20261006'
    new=root/'output/sven_budget_preflight_20261008'
    a=json.loads((old/'manifest.json').read_text(encoding='utf8'))
    b=json.loads((new/'manifest.json').read_text(encoding='utf8'))
    if a['dataset_sha256']!=b['dataset_sha256']:raise ValueError('Dataset differs')
    calls=[json.loads(line) for line in (old/'api_receipts.jsonl').read_text(encoding='utf8').splitlines()]
    first={}
    old_results={r['idx']:r for r in (json.loads(line) for line in (old/'results.jsonl').read_text(encoding='utf8').splitlines()) if r['profile']=='control'}
    old_samples={s['idx']:s for s in a['samples']}
    new_samples={s['idx']:s for s in b['samples']}
    for call in calls:
        if call['profile']=='control' and not call.get('error'):
            first.setdefault(call['idx'],call['request']['messages'])
    rows=[]
    for s in json.loads((new/'shadow.json').read_text(encoding='utf8')):
        old_messages=first[s['idx']]
        if [m['role'] for m in old_messages]!=['system','user']:raise ValueError('Unexpected historical roles')
        a_user=old_messages[1]['content'];b_user=s['user_prompt']
        a_src=src_segment(a_user);b_src=src_segment(b_user)
        # Compare complete non-SRC text rather than implying graph-only change.
        a_rest=a_user.replace(a_src,'<SRC>',1);b_rest=b_user.replace(b_src,'<SRC>',1)
        old_nodes=old_results[s['idx']]['compressed_nodes']
        new_nodes=len(s['module_audit']['evidence_lineage']['compressed_node_ids'])
        rows.append({'idx':s['idx'],'system_changed':old_messages[0]['content']!=s['system_prompt'],
            'user_changed':a_user!=b_user,'src_changed':a_src!=b_src,'non_src_text_changed':a_rest!=b_rest,
            'full_cpg_bytes_changed':old_samples[s['idx']]['cpg_sha256']!=new_samples[s['idx']]['cpg_sha256'],
            'compression_node_count_changed':old_nodes!=new_nodes,
            'old_compressed_nodes':old_nodes,'repaired_compressed_nodes':new_nodes})
    report={'samples':len(rows),**{k:sum(r[k] for r in rows) for k in (
        'system_changed','user_changed','src_changed','non_src_text_changed',
        'full_cpg_bytes_changed','compression_node_count_changed')},
        'old_total_compressed_nodes':sum(r['old_compressed_nodes'] for r in rows),
        'repaired_total_compressed_nodes':sum(r['repaired_compressed_nodes'] for r in rows),
        'rows':rows,'input_sha256':{str(path.relative_to(root)):hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (old/'manifest.json',old/'api_receipts.jsonl',old/'results.jsonl',new/'manifest.json',new/'shadow.json')},
        'api_calls':0,'prediction_changes':0,
        'scope':'Historical actual request vs repaired shadow, not matched fresh quality comparison.',
        'limitations':['Multiple common repairs/code versions and provider time differ; no causal attribution.',
            'Non-SRC text includes DEP/STATE/exploration; not solely graph evidence.',
            'No old predictions substituted into current evaluation, no label tuning.']}
    args.output.write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('rows','input_sha256')},indent=2))


if __name__=='__main__':main()
