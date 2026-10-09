"""Offline production-TopK group/budget checks, no real model calls."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import contextlib
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--cache',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():raise ValueError('New output path required')
    from evaluation.build_clean_development_pilot import SETTINGS
    os.environ.update(dict(SETTINGS,RECORD_REASONING_TRACE='1',USE_BACKWARD_SLICE='0',
        BOUNDED_OUTPUT_CONTRACT='0',EVIDENCE_EXPANSION='0',BUDGETED_EVIDENCE_GROUPS='0'))
    from graph.pipeline import run_hgl_pipeline
    from graph.load_graph import load_graph
    from linearization.backward_slice import backward_evidence_slice
    loop=importlib.import_module('reasoning.reasoning_loop')
    api=importlib.import_module('reasoning.llm_api')
    from evaluation.evaluate_wiring_quality import prediction_code_hashes
    hashes=prediction_code_hashes()
    meta=json.loads((args.cache/'meta.json').read_text(encoding='utf-8'))
    args.output.mkdir(parents=True)
    def blocked(*a,**k):raise RuntimeError('Real model calls prohibited')
    def synthetic(*a,**k):return 'HYPOTHESIS: no vulnerability detected\nACTION: {"action":"Stop","reason":"offline interception"}',0
    def run(s):
        sid=s['sample_id']; path=args.cache/sid/'source.c'
        base={'sample_id':sid,'idx':s['idx'],'group_id':s['group_id']}
        if s.get('error'):return dict(base,error=s['error'])
        code=path.read_text(encoding='utf-8')
        if hashlib.sha256(code.encode()).hexdigest()!=s['source_raw_sha256']:raise ValueError('Source changed')
        result=run_hgl_pipeline(str(path),code,sid,str(args.cache/sid),None,4096,return_details=True)
        lineage=result['module_audit']['evidence_lineage']
        graph=load_graph(str(args.cache/sid/'export/export.dot'))
        kw=dict(line_offset=lineage['source_line_offset'],max_chars=min(1100,max(600,len(code)//8)))
        plain,a=backward_evidence_slice(graph,lineage['initial_topk_node_ids'],code,**kw)
        grouped,b=backward_evidence_slice(graph,lineage['initial_topk_node_ids'],code,atomic_groups=True,**kw)
        audit=b['atomic_groups']
        if len(grouped)>len(plain) or len(grouped.encode())>len(plain.encode()):raise ValueError('Payload grew')
        for group in audit.get('groups',[]):
            if group['admitted'] and not group['mapped_lines_complete_in_output']:raise ValueError('Admitted group split')
        if not set(audit.get('protected_plain_lines',[]))<=set(b['source_lines']):raise ValueError('Protected evidence lost')
        return dict(base,changed=grouped!=plain,plain_chars=len(plain),grouped_chars=len(grouped),
            group_audit=audit,plain_source_lines=a['source_lines'],grouped_source_lines=b['source_lines'])
    rows=[]
    with patch.object(loop,'query_llm_with_retry',synthetic),patch.object(api,'create_client',blocked),patch.object(api,'query_llm',blocked), \
            (args.output/'execution.log').open('w',encoding='utf-8') as log,contextlib.redirect_stdout(log):
        with ThreadPoolExecutor(max_workers=4) as pool:
            for future in as_completed([pool.submit(run,s) for s in meta.values()]):
                rows.append(future.result())
                print(f'SHADOW {len(rows)}/{len(meta)}',file=sys.__stdout__,flush=True)
    if hashes!=prediction_code_hashes():raise ValueError('Prediction code changed during shadow check')
    groups=[g for r in rows for g in r.get('group_audit',{}).get('groups',[])]
    report={'samples':len(rows),'preparation_errors':sum(bool(r.get('error')) for r in rows),
        'changed_source_samples':sum(r.get('changed',False) for r in rows),'groups':len(groups),
        'admitted_groups':sum(g['admitted'] for g in groups),
        'admitted_with_control_and_exit':sum(g['admitted'] and bool(g['control_node_ids']) and bool(g['exit_node_ids']) for g in groups),
        'api_calls':0,'payload_growth':0,'admitted_group_splits':0,'protected_line_losses':0,
        'code_hashes':hashes,'scope':'Label-blind offline invariants, no detection-quality claim.'}
    (args.output/'rows.json').write_text(json.dumps(sorted(rows,key=lambda r:r['idx']),indent=2),encoding='utf-8')
    (args.output/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='code_hashes'},indent=2))


if __name__=='__main__':main()
