"""Label-free, blocked-API shadow of a single SRC preservation switch."""
import argparse
import contextlib
import hashlib
import importlib
import json
import os
from pathlib import Path
from unittest.mock import patch


def compare_prompts(control, candidate):
    marker='\n\nDEP PATHS:'
    a, atail=control.split(marker,1)
    b, btail=candidate.split(marker,1)
    if atail!=btail or not a.startswith('SRC:\n') or not b.startswith('SRC:\n'):
        raise ValueError('Non-SRC context changed')
    return {'changed':a!=b,'control_src_chars':len(a[5:]),'candidate_src_chars':len(b[5:]),
            'control_prompt_sha256':hashlib.sha256(control.encode()).hexdigest(),
            'candidate_prompt_sha256':hashlib.sha256(candidate.encode()).hexdigest()}


def main():
    p=argparse.ArgumentParser();p.add_argument('--cache',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    if args.output.exists():raise ValueError('Never overwrite a shadow')
    from evaluation.build_clean_development_pilot import SETTINGS
    os.environ.update(dict(SETTINGS,RECORD_REASONING_TRACE='1',USE_BACKWARD_SLICE='0',
                          BOUNDED_OUTPUT_CONTRACT='0',EVIDENCE_EXPANSION='0'))
    import config
    from graph.pipeline import run_hgl_pipeline
    from evaluation.evaluate_wiring_quality import prediction_code_hashes
    loop=importlib.import_module('reasoning.reasoning_loop')
    api=importlib.import_module('reasoning.llm_api')
    hashes=prediction_code_hashes()
    samples=json.loads((args.cache/'meta.json').read_text(encoding='utf8'))
    rows=[];args.output.mkdir(parents=True)
    def blocked(*a,**kw):raise AssertionError('External calls forbidden in shadow')
    def mock(*a,**kw):return 'HYPOTHESIS: no vulnerability detected\nACTION: {"action":"Stop"}',0
    with patch.object(loop,'query_llm_with_retry',mock),patch.object(api,'create_client',blocked), \
            patch.object(api,'query_llm',blocked),(args.output/'execution.log').open('w',encoding='utf8') as log, \
            contextlib.redirect_stdout(log):
        for sid,sample in samples.items():
            if sample.get('error'):
                rows.append(dict(sample_id=sid,error=sample['error']));continue
            path=args.cache/sid/'source.c';code=path.read_text(encoding='utf8')
            if hashlib.sha256(code.encode()).hexdigest()!=sample['source_raw_sha256']:
                raise ValueError('Source changed')
            prompts={};lineages=[]
            for name in ('control','assignment_evidence'):
                config.SOURCE_SLICE_ASSIGNMENT_FIX=name=='assignment_evidence'
                result=run_hgl_pipeline(str(path),code,sid,str(path.parent),None,4096,return_details=True)
                trace=result['arbitrate']['reasoning_trace']
                if len(trace)!=1:raise ValueError('Expected single intercepted call')
                prompts[name]=trace[0]['user_prompt']
                lineages.append(result['module_audit']['evidence_lineage'])
            if lineages[0]!=lineages[1]:raise ValueError('Graph retrieval changed')
            row=dict(sample_id=sid,**compare_prompts(*prompts.values()),prompts=prompts)
            rows.append(row)
            print('ASSIGNMENT SHADOW '+sid,file=__import__('sys').__stdout__,flush=True)
    config.SOURCE_SLICE_ASSIGNMENT_FIX=False
    if hashes!=prediction_code_hashes():raise ValueError('Code changed during shadow')
    valid=[r for r in rows if not r.get('error')]
    report={'samples':len(rows),'valid':len(valid),'errors':len(rows)-len(valid),
            'changed_inputs':sum(r['changed'] for r in valid),'api_calls':0,'non_src_changes':0,
            'code_hashes':hashes,'selection_sha256':hashlib.sha256((args.cache/'manifest.json').read_bytes()).hexdigest(),
            'src_character_growth_samples':sum(r['candidate_src_chars']>r['control_src_chars'] for r in valid),
            'limitations':['Label-free mechanism audit, no quality claim.','No claim of provider-token no-growth.']}
    (args.output/'rows.json').write_text(json.dumps(rows,indent=2),encoding='utf8')
    (args.output/'report.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps({k:v for k,v in report.items() if k!='code_hashes'},indent=2))


if __name__=='__main__':main()
