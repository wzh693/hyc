"""Frozen development-only factorial evaluation; no winner auto-activation."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import contextlib
import hashlib
import json
import os
from pathlib import Path
import random
import sys
import threading
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
PROFILES = {
    'control': (0,0,0), 'slice_only': (1,0,0), 'contract_only': (0,1,0),
    'expansion_only': (0,0,1), 'combined': (1,1,1),
    'combined_no_slice': (0,1,1), 'combined_no_contract': (1,0,1),
    'combined_no_expansion': (1,1,0),
}
REPEAT_PROFILES = ('control','contract_only','combined')


def prediction_code_hashes():
    files = [ROOT/'config.py', ROOT/'evaluation/__init__.py', ROOT/'evaluation/metrics.py', Path(__file__)]
    for folder in ('graph','retrieval','linearization','reasoning','planning','learning'):
        files.extend(sorted((ROOT/folder).glob('*.py')))
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}


def score(rows):
    """All scheduled rows count. Abstentions count as errors, never dropped."""
    from evaluation.metrics import compute_metrics
    metric = compute_metrics([r['target'] for r in rows], [r.get('prediction') for r in rows])
    tp, tn, fp, fn = (metric[k] for k in ('tp','tn','fp','fn'))
    valid = metric['n_valid']
    return {'f1':2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0,
            'accuracy':(tp+tn)/len(rows) if rows else 0,
            'tp':tp,'tn':tn,'fp_including_abstentions':fp,'fn_including_abstentions':fn,
            'n':len(rows),'coverage':valid/len(rows) if rows else 0,
            'errors':sum(bool(r.get('error')) for r in rows),
            'uncertain':sum(r.get('prediction') is None and not r.get('error') for r in rows),
            'total_tokens':sum(r.get('tokens_used',0) for r in rows)}


def summarize(rows, manifest, api_rows, bootstrap=2000):
    expected = {(r['sample_id'],p,repeat) for r in manifest['samples']
                for repeat, profiles in ((1,PROFILES),(2,REPEAT_PROFILES)) for p in profiles}
    indexed = {}
    for row in rows:
        key = (row['sample_id'],row['profile'],row['repeat'])
        if key in indexed:
            raise ValueError('Duplicate evaluation receipt')
        indexed[key] = row
    if set(indexed) != expected:
        raise ValueError('Incomplete or unexpected evaluation receipts')
    results = {f'{p}/r{rep}':score([indexed[(s['sample_id'],p,rep)] for s in manifest['samples']])
               for rep, profiles in ((1,PROFILES),(2,REPEAT_PROFILES)) for p in profiles}
    comparisons = [(p,'control') for p in PROFILES if p!='control']
    if 'combined' in PROFILES:
        comparisons += [('combined','combined_no_slice'),('combined','combined_no_contract'),
                        ('combined','combined_no_expansion')]
    if 'grouped_slice' in PROFILES:
        comparisons += [('grouped_slice','slice_only')]
    if 'observed_state' in PROFILES:
        comparisons += [('observed_state','state_disabled')]
    intervals = {}
    # One function per group; each bootstrap unit is a frozen group, not a call.
    ids = [s['sample_id'] for s in manifest['samples']]
    for candidate, baseline in comparisons:
        rng = random.Random(20261007)
        delta_f1, delta_acc = [], []
        for _ in range(bootstrap):
            sampled = rng.choices(ids,k=len(ids))
            a = score([indexed[(sid,baseline,1)] for sid in sampled])
            b = score([indexed[(sid,candidate,1)] for sid in sampled])
            delta_f1.append(b['f1']-a['f1'])
            delta_acc.append(b['accuracy']-a['accuracy'])
        delta_f1.sort();delta_acc.sort()
        lo,hi = int(bootstrap*.025), min(bootstrap-1,int(bootstrap*.975))
        intervals[f'{candidate}-vs-{baseline}'] = {
            'delta_f1':results[candidate+'/r1']['f1']-results[baseline+'/r1']['f1'],
            'delta_accuracy':results[candidate+'/r1']['accuracy']-results[baseline+'/r1']['accuracy'],
            'group_delta_f1_ci95':[delta_f1[lo],delta_f1[hi]],
            'group_delta_accuracy_ci95':[delta_acc[lo],delta_acc[hi]],
            'multiplicity':'Exploratory marginal intervals; not multiplicity-adjusted significance.'}
    repeats = {p:{'prediction_disagreements':sum(indexed[(sid,p,1)].get('prediction') !=
                    indexed[(sid,p,2)].get('prediction') for sid in ids),
                  'delta_f1':results[p+'/r2']['f1']-results[p+'/r1']['f1'],
                  'delta_accuracy':results[p+'/r2']['accuracy']-results[p+'/r1']['accuracy']}
               for p in REPEAT_PROFILES}
    api = {}
    for rep,profiles in ((1,PROFILES),(2,REPEAT_PROFILES)):
        for profile in profiles:
            calls = [r for r in api_rows if r['profile']==profile and r['repeat']==rep]
            api[f'{profile}/r{rep}'] = {'invocations':len(calls),
                'failed_invocations':sum(bool(r.get('error')) for r in calls),
                'truncated_calls':sum(r.get('finish_reason')=='length' for r in calls),
                'prompt_tokens':sum(r.get('prompt_tokens',0) or 0 for r in calls),
                'completion_tokens':sum(r.get('completion_tokens',0) or 0 for r in calls),
                'total_tokens':sum(r.get('total_tokens',0) or 0 for r in calls),
                'actual_model_names':dict(Counter(r.get('model','unavailable') for r in calls))}
    return {'metrics':results,'paired_group_intervals':intervals,'repeat_sensitivity':repeats,
            'api_accounting':api,'scheduled_samples':len(ids),
            'actual_invocations':len(api_rows),'auto_promoted':False,
            'limitations':['Development only, not official benchmark folds or independent final test.',
                'Absence of unrecorded historical exposure cannot be proven.',
                'Bootstrap reflects these groups/receipts, not all future provider variability.',
                'Repeated calls are not new samples; first repeat is the primary factorial analysis.',
                'Abstentions penalized in conservative F1 and full-denominator Accuracy.',
                'No threshold tuning, sample replacement, checkpoint activation or test evaluation.']}


def effective_configuration(config, settings):
    receipt = {}
    for name,expected in settings.items():
        if not hasattr(config,name):
            continue  # Process-only Joern timeout/HGL_ABL.
        value = getattr(config,name)
        if isinstance(value,bool):
            matches = value == (expected=='1')
        elif isinstance(value,int):
            matches = value == int(expected)
        else:
            matches = str(value)==expected
        if not matches:
            raise ValueError(f'Effective configuration mismatch before API calls: {name}')
        receipt[name] = value
    return receipt


def main():
    global PROFILES, REPEAT_PROFILES
    parser = argparse.ArgumentParser()
    parser.add_argument('--cache',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--workers',type=int,default=4)
    parser.add_argument('--preflight-only',action='store_true',help='Verify actual config/inputs and save manifest; no API client or calls')
    parser.add_argument('--grouped-confirmation', action='store_true', help='Control/plain/grouped slice, two predeclared repeats each')
    parser.add_argument('--action-order-confirmation', action='store_true', help='Standard/control versus field-order-only candidate, each twice')
    parser.add_argument('--state-confirmation', action='store_true', help='Standard/STATE-disabled/observed-STATE each twice')
    parser.add_argument('--assignment-confirmation', action='store_true', help='Only assignment/dereference SRC preservation differs; two repeats')
    parser.add_argument('--assignment-shadow',type=Path,help='Required zero-call assignment shadow')
    parser.add_argument('--state-shadow', type=Path, help='Required pre-call offline STATE shadow report directory')
    args = parser.parse_args()
    if sum((args.grouped_confirmation, args.action_order_confirmation, args.state_confirmation, args.assignment_confirmation)) > 1:
        parser.error('Choose one confirmation mode')
    if args.grouped_confirmation:
        PROFILES = {'control': (0,0,0), 'slice_only': (1,0,0), 'grouped_slice': (1,0,0)}
        REPEAT_PROFILES = tuple(PROFILES)
    if args.action_order_confirmation:
        PROFILES = {'control': (0,0,0), 'action_first': (0,0,0)}
        REPEAT_PROFILES = tuple(PROFILES)
    if args.state_confirmation:
        PROFILES = {'control': (0,0,0), 'state_disabled': (0,0,0), 'observed_state': (0,0,0)}
        REPEAT_PROFILES = tuple(PROFILES)
    if args.assignment_confirmation:
        PROFILES = {'control': (0,0,0), 'assignment_evidence': (0,0,0)}
        REPEAT_PROFILES = tuple(PROFILES)
    if not 1<=args.workers<=8:
        parser.error('workers must be 1..8')
    if args.output.exists():
        raise ValueError('Use a new directory: frozen evaluations cannot be overwritten or favorably resumed')
    from evaluation.build_clean_development_pilot import SETTINGS
    # Must happen before importing config/scorer/reasoning; inherited flags ignored.
    fixed = dict(SETTINGS, USE_BACKWARD_SLICE='0',BOUNDED_OUTPUT_CONTRACT='0',
                 EVIDENCE_EXPANSION='0',RECORD_REASONING_TRACE='1',BUDGETED_EVIDENCE_GROUPS='0',ACTION_BEFORE_REASONING='0',
                 OBSERVED_STATE_CANDIDATE='0')
    os.environ.update(fixed)
    import config
    actual_settings = effective_configuration(config,fixed)
    if args.assignment_confirmation and (config.LLM_BASE_URL.rstrip('/') != 'https://api.deepseek.com/v1'
                                         or config.LLM_MODEL != 'deepseek-chat'):
        raise ValueError('Assignment confirmation destination/model differs from human authorization')
    from graph.pipeline import run_hgl_pipeline
    from reasoning.llm_api import create_client
    from evaluation.build_clean_protocol import code_hash
    metadata = json.loads((args.cache/'meta.json').read_text(encoding='utf-8'))
    selected = json.loads((args.cache/'manifest.json').read_text(encoding='utf-8'))
    preparation = json.loads((args.cache/'protocol.json').read_text(encoding='utf-8'))
    if not preparation.get('current_exposure_exclusion'):
        raise ValueError('Required current-exposure exclusion receipt is missing')
    if len({s['group_id'] for s in selected}) != len(selected):
        raise ValueError('Expected exactly one function per disjoint group')
    samples = []
    for item in selected:
        sid = f"sample_{item['idx']:06d}"
        record = metadata[sid]
        path = args.cache/sid/'source.c'
        code = path.read_text(encoding='utf-8')
        if code_hash(code) != item['source_sha256'] or record['group_id']!=item['group_id']:
            raise ValueError('Source/group identity mismatch')
        graph_path = path.parent/'export/export.dot'
        samples.append(dict(record,source_path=str(path.resolve()),
            cpg_sha256=hashlib.sha256(graph_path.read_bytes()).hexdigest() if not record.get('error') else None))
    hashes = prediction_code_hashes()
    assignment_shadow_hash = None
    if args.assignment_confirmation:
        if args.assignment_shadow is None:raise ValueError('Required assignment shadow missing')
        shadow_data=(args.assignment_shadow/'report.json').read_bytes()
        assignment_shadow=json.loads(shadow_data)
        if (assignment_shadow['code_hashes']!=hashes or assignment_shadow['api_calls']!=0
                or assignment_shadow['non_src_changes']!=0 or assignment_shadow['samples']!=len(samples)
                or assignment_shadow['selection_sha256']!=hashlib.sha256((args.cache/'manifest.json').read_bytes()).hexdigest()):
            raise ValueError('Assignment shadow does not match frozen inputs/code')
        assignment_shadow_hash=hashlib.sha256(shadow_data).hexdigest()
    shadow_receipt = None
    if args.state_confirmation:
        if args.state_shadow is None:
            raise ValueError('STATE confirmation requires an offline shadow receipt')
        shadow_bytes = (args.state_shadow/'report.json').read_bytes()
        shadow_receipt = json.loads(shadow_bytes)
        if (shadow_receipt['code_hashes'] != hashes or shadow_receipt['api_calls'] != 0
                or shadow_receipt['samples'] != len(samples)
                or shadow_receipt['non_state_changes'] != 0 or shadow_receipt['payload_growth'] != 0
                or shadow_receipt['selection_manifest_sha256'] != hashlib.sha256((args.cache/'manifest.json').read_bytes()).hexdigest()):
            raise ValueError('STATE shadow receipt/config/input mismatch')
    manifest = {'samples':samples,'profiles':PROFILES,'repeat_profiles':REPEAT_PROFILES,
        'assignment_shadow_sha256':assignment_shadow_hash,
        'first_repeat_primary':True,'settings':fixed,'effective_settings':actual_settings,'code_hashes':hashes,
        'selection_manifest_sha256':hashlib.sha256((args.cache/'manifest.json').read_bytes()).hexdigest(),
        'preparation_protocol_sha256':hashlib.sha256((args.cache/'protocol.json').read_bytes()).hexdigest(),
        'requested_model':config.LLM_MODEL,'endpoint':config.LLM_BASE_URL,'budget':4096,'output_token_ceiling':150,
        'retry_policy':'SDK retries disabled; wrapper max 3 observed invocations; timeout 90s.',
        'planned_sample_profile_pairs':len(samples)*(len(PROFILES)+len(REPEAT_PROFILES)),
        'protocol': ('Assignment evidence confirmation, single SRC preservation switch; two repeats; no activation.' if args.assignment_confirmation else
                     'STATE confirmation: control/state_disabled/observed_state each twice; no activation.' if args.state_confirmation else
                     'Field-order-only confirmation, standard/control and action_first each twice; no activation.' if args.action_order_confirmation else
                     'Grouped evidence confirmation, control/plain/grouped each twice; no activation.' if args.grouped_confirmation else
                     'Complete factorial + preregistered second repeat of control/contract/combined; no activation.'),
        'atomic_group_profiles': ['grouped_slice'] if args.grouped_confirmation else [],
        'action_order_profiles': ['action_first'] if args.action_order_confirmation else [],
        'state_shadow_sha256': hashlib.sha256(shadow_bytes).hexdigest() if shadow_receipt is not None else None,
        'profile_ablation': {p:('no_state' if p=='state_disabled' else '') for p in PROFILES},
        'profile_effective_settings':{p:dict(actual_settings,
            USE_BACKWARD_SLICE=bool(flags[0]),BOUNDED_OUTPUT_CONTRACT=bool(flags[1]),
            EVIDENCE_EXPANSION=bool(flags[2]),BUDGETED_EVIDENCE_GROUPS=p=='grouped_slice',
            ACTION_BEFORE_REASONING=p=='action_first',OBSERVED_STATE_CANDIDATE=p=='observed_state',
            SOURCE_SLICE_ASSIGNMENT_FIX=p=='assignment_evidence') for p,flags in PROFILES.items()},
        'expansion_zero_level':'Legacy standard routing retained; no_expansion profile removes the new upgrade, not all legacy iteration.',
        'scope':'New group-disjoint development, no locked test or validation tuning.'}
    args.output.mkdir(parents=True)
    if args.assignment_confirmation:
        import shutil
        snapshot=args.output/'code_snapshot'
        for name in hashes:
            destination=snapshot/name
            destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(ROOT/name,destination)
        for name,digest in hashes.items():
            if hashlib.sha256((snapshot/name).read_bytes()).hexdigest()!=digest:
                raise ValueError('Snapshot failed verification')
    (args.output/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    if args.preflight_only:
        from reasoning.prompts import get_system_prompt
        system=get_system_prompt('SRC:\nint n = a[i];')
        field_order_check = None
        if args.action_order_confirmation:
            config.ACTION_BEFORE_REASONING=True
            try:
                candidate=get_system_prompt('SRC:\nint n = a[i];')
                field_order_check = Counter(system.splitlines())==Counter(candidate.splitlines()) and (
                    candidate.index('\nHYPOTHESIS:')<candidate.index('\nACTION:')<candidate.index('\nREASONING:'))
                if not field_order_check:raise ValueError('Candidate changed more than field order')
            finally:
                config.ACTION_BEFORE_REASONING=False
        print(json.dumps({'status':'preflight_pass','api_calls':0,'samples':len(samples),
            'effective_settings':actual_settings,
            'field_order_only_check':field_order_check,
            'expanded_types_present':all(t in system for t in ('Out-of-Bounds Read','Integer Overflow'))},indent=2))
        return
    client = create_client().with_options(max_retries=0,timeout=90)
    lock = threading.Lock()
    rows,api_rows = [],[]
    def append(filename,record):
        with lock:
            with (args.output/filename).open('a',encoding='utf-8') as file:
                file.write(json.dumps(record,ensure_ascii=False)+'\n')
    def run(sample,profile,repeat):
        sid = sample['sample_id']
        base = {'sample_id':sid,'idx':sample['idx'],'group_id':sample['group_id'],
                'target':sample['target'],'profile':profile,'repeat':repeat,
                'source_sha256':sample['source_raw_sha256']}
        if sample.get('error'):
            return dict(base,prediction=None,error='Preparation failed: '+sample['error'])
        spent = []
        def observed_create(**kwargs):
            receipt = {**base, 'request':kwargs}
            try:
                response = client.chat.completions.create(**kwargs)
                usage = response.usage
                receipt.update(model=response.model,finish_reason=response.choices[0].finish_reason,
                    usage_known=usage is not None,
                    answer=response.choices[0].message.content,
                    prompt_tokens=getattr(usage,'prompt_tokens',0),
                    completion_tokens=getattr(usage,'completion_tokens',0),
                    total_tokens=getattr(usage,'total_tokens',0))
                spent.append(receipt['total_tokens'] or 0)
                return response
            except Exception as exc:
                receipt['error'] = str(exc)
                raise
            finally:
                append('api_receipts.jsonl',receipt)
                with lock:
                    api_rows.append(receipt)
        observer = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=observed_create)))
        try:
            code = Path(sample['source_path']).read_text(encoding='utf-8')
            if hashlib.sha256(code.encode()).hexdigest()!=sample['source_raw_sha256']:
                raise ValueError('Source changed during evaluation')
            if hashlib.sha256((Path(sample['source_path']).parent/'export/export.dot').read_bytes()).hexdigest()!=sample['cpg_sha256']:
                raise ValueError('Graph changed during evaluation')
            result = run_hgl_pipeline(sample['source_path'],code,sid,str(args.cache/sid),
                                      observer,4096,ablation=manifest['profile_ablation'][profile],return_details=True)
            if args.state_confirmation:
                trace=result.get('arbitrate',{}).get('reasoning_trace',[])
                if not trace or ('\nSTATE:\n' in trace[0]['user_prompt']) != (profile!='state_disabled'):
                    raise ValueError('Actual STATE injection/ablation mismatch')
            audit = result.get('module_audit',{})
            if audit.get('learned_scoring') or audit.get('graph_security_net'):
                raise ValueError('Rejected feature was unexpectedly activated')
            return {**base,**result}
        except Exception as exc:
            return dict(base,prediction=None,error=str(exc),tokens_used=sum(spent))
    with (args.output/'execution.log').open('w',encoding='utf-8') as log, contextlib.redirect_stdout(log):
        for repeat,profiles in ((1,PROFILES),(2,REPEAT_PROFILES)):
            for profile in profiles:
                if hashes != prediction_code_hashes():
                    raise ValueError('Prediction code changed during evaluation; discard the unfinished batch')
                flags = dict(zip(('USE_BACKWARD_SLICE','BOUNDED_OUTPUT_CONTRACT','EVIDENCE_EXPANSION'),
                                 map(bool,PROFILES[profile])))
                for name,value in flags.items():
                    setattr(config,name,value)
                config.BUDGETED_EVIDENCE_GROUPS = profile == 'grouped_slice'
                config.ACTION_BEFORE_REASONING = profile == 'action_first'
                config.OBSERVED_STATE_CANDIDATE = profile == 'observed_state'
                config.SOURCE_SLICE_ASSIGNMENT_FIX = profile == 'assignment_evidence'
                effective_configuration(config,{name:('1' if value else '0') if isinstance(value,bool)
                    else str(value) for name,value in manifest['profile_effective_settings'][profile].items()})
                with ThreadPoolExecutor(max_workers=args.workers) as pool:
                    jobs = [pool.submit(run,sample,profile,repeat) for sample in samples]
                    for job in as_completed(jobs):
                        row=job.result();rows.append(row);append('results.jsonl',row)
                        print(f"QUALITY {len(rows)}/{manifest['planned_sample_profile_pairs']} {profile}/r{repeat} {row['sample_id']} tokens={row.get('tokens_used')} error={bool(row.get('error'))}",
                              file=sys.__stdout__,flush=True)
                log.flush()
    if hashes != prediction_code_hashes():raise ValueError('Code changed before finalization')
    report=summarize(rows,manifest,api_rows)
    (args.output/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({'metrics':report['metrics'],'repeat_sensitivity':report['repeat_sensitivity'],
                      'actual_invocations':report['actual_invocations'],'auto_promoted':False},indent=2))


if __name__=='__main__':
    main()
