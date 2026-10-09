"""No-label, no-API production initial-prompt shadow for STATE confirmation."""
import argparse
import contextlib
import hashlib
import importlib
import json
import os
from pathlib import Path
from unittest.mock import patch


def compare_prompts(control, disabled, candidate):
    marker = '\nSTATE:\n'
    if marker not in control or marker not in candidate or marker in disabled:
        raise ValueError('STATE injection/ablation mismatch')
    prefix, state_and_tail = control.split(marker, 1)
    cp, candidate_state_and_tail = candidate.split(marker, 1)
    state, tail = state_and_tail.split('\n\nEXPLORATION STATE:', 1)
    candidate_state, candidate_tail = candidate_state_and_tail.split('\n\nEXPLORATION STATE:', 1)
    if prefix != cp or tail != candidate_tail:
        raise ValueError('Non-STATE prompt changed')
    if disabled != prefix + '\n\n\nEXPLORATION STATE:' + tail:
        # Disabled renderer retains its trailing empty context separator; exact
        # content comparison permits only this separator, never SRC/PATHS changes.
        if disabled.rstrip() != (prefix + '\n\nEXPLORATION STATE:' + tail).rstrip():
            raise ValueError('STATE-disabled arm changed other content')
    if len(candidate_state)>len(state) or len(candidate_state.encode())>len(state.encode()):
        raise ValueError('STATE character/byte payload grew')
    if candidate_state and candidate_state != 'MAY;unordered:' and not candidate_state.endswith(';'):
        raise ValueError('Candidate event serialization split')
    return {'control_state':state,'candidate_state':candidate_state,
            'control_prompt_chars':len(control),'candidate_prompt_chars':len(candidate),
            'control_prompt_bytes':len(control.encode()),'candidate_prompt_bytes':len(candidate.encode())}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():raise ValueError('New output directory required')
    from evaluation.build_clean_development_pilot import SETTINGS
    os.environ.update(dict(SETTINGS,RECORD_REASONING_TRACE='1',USE_BACKWARD_SLICE='0',
                          BOUNDED_OUTPUT_CONTRACT='0',EVIDENCE_EXPANSION='0'))
    import config
    from graph.pipeline import run_hgl_pipeline
    from graph.load_graph import load_graph
    from planning.observed_state import ObservedProgramState
    from evaluation.evaluate_wiring_quality import prediction_code_hashes
    loop=importlib.import_module('reasoning.reasoning_loop')
    api=importlib.import_module('reasoning.llm_api')
    hashes=prediction_code_hashes()
    meta=json.loads((args.cache/'meta.json').read_text(encoding='utf-8'))
    # Targets are deliberately removed; no metrics or labels in shadow artifacts.
    samples=[{k:v for k,v in s.items() if k!='target'} for s in meta.values()]
    args.output.mkdir(parents=True)
    rows=[]
    def blocked(*a,**k):raise AssertionError('Real API prohibited in shadow')
    def synthetic(*a,**k):return 'HYPOTHESIS: no vulnerability detected\nACTION: {"action":"Stop","reason":"offline shadow"}',0
    with patch.object(loop,'query_llm_with_retry',synthetic),patch.object(api,'create_client',blocked), \
            patch.object(api,'query_llm',blocked), (args.output/'execution.log').open('w',encoding='utf-8') as log, contextlib.redirect_stdout(log):
        for sample in samples:
            sid=sample['sample_id']
            row={'sample_id':sid,'group_id':sample['group_id']}
            if sample.get('error'):
                rows.append(dict(row,error=sample['error']))
                continue
            path=args.cache/sid/'source.c'
            code=path.read_text(encoding='utf-8')
            if hashlib.sha256(code.encode()).hexdigest()!=sample['source_raw_sha256']:raise ValueError('Source changed')
            arms={}
            for name in ('control','state_disabled','observed_state'):
                config.OBSERVED_STATE_CANDIDATE=name=='observed_state'
                result=run_hgl_pipeline(str(path),code,sid,str(args.cache/sid),None,4096,
                    ablation='no_state' if name=='state_disabled' else '',return_details=True)
                trace=result['arbitrate']['reasoning_trace']
                if len(trace)!=1:raise ValueError('Shadow must have one intercepted first call')
                arms[name]={'prompt':trace[0]['user_prompt'], 'lineage':result['module_audit']['evidence_lineage']}
            if not arms['control']['lineage']==arms['state_disabled']['lineage']==arms['observed_state']['lineage']:
                raise ValueError('Evidence retrieval changed between STATE arms')
            audit=compare_prompts(*(arms[p]['prompt'] for p in ('control','state_disabled','observed_state')))
            graph=load_graph(str(args.cache/sid/'export/export.dot'))
            tracker=ObservedProgramState()
            tracker.track_vars(code)
            source_count=len(tracker.events)
            for nodes in arms['control']['lineage']['initial_topk_node_ids']:
                for node in nodes:tracker.observe_graph_node(node,graph.nodes.get(node,{}),1)
            rows.append(dict(row,**audit,arms=arms,source_event_count=source_count,
                emitted_initial_units=audit['candidate_state'].count(';')-1 if audit['candidate_state'] else 0,
                graph_added_events=len(tracker.events)-source_count,
                unresolved_graph_events=sum(e['line'] is None for e in tracker.events)))
            print('STATE SHADOW '+sid,file=__import__('sys').__stdout__,flush=True)
    config.OBSERVED_STATE_CANDIDATE=False
    if hashes!=prediction_code_hashes():raise ValueError('Prediction code changed')
    valid=[r for r in rows if not r.get('error')]
    report={'samples':len(rows),'valid':len(valid),'preparation_errors':len(rows)-len(valid),
        'api_calls':0,'non_state_changes':0,'payload_growth':0,
        'selection_manifest_sha256':hashlib.sha256((args.cache/'manifest.json').read_bytes()).hexdigest(),
        'code_hashes':hashes,'source_events':sum(r['source_event_count'] for r in valid),
        'emitted_initial_units':sum(r['emitted_initial_units'] for r in valid),
        'graph_added_events':sum(r['graph_added_events'] for r in valid),
        'unresolved_graph_events':sum(r['unresolved_graph_events'] for r in valid),
        'limitations':['No labels or quality claim.','Graph-added events use full graph replay; synthetic compressed nodes may be absent.',
            'May-events do not prove scope/execution/alias/lifetime; omission persists.',
            'Character/byte caps, not provider-token proof.']}
    (args.output/'rows.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding='utf-8')
    (args.output/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='code_hashes'},indent=2))


if __name__=='__main__':main()
