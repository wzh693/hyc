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
    files = [ROOT/'config.py', ROOT/'evaluation/__init__.py', Path(__file__)]
    for folder in ('graph','retrieval','linearization','reasoning','planning','learning'):
        files.extend(sorted((ROOT/folder).glob('*.py')))
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}


def score(rows):
    """All scheduled rows count. Abstentions count as errors, never dropped."""
    tp = sum(r['target']==1 and r.get('prediction')==1 for r in rows)
    tn = sum(r['target']==0 and r.get('prediction')==0 for r in rows)
    fp = sum(r['target']==0 and r.get('prediction')!=0 for r in rows)
    fn = sum(r['target']==1 and r.get('prediction')!=1 for r in rows)
    valid = sum(r.get('prediction') in (0,1) for r in rows)
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
    comparisons = [(p,'control') for p in PROFILES if p!='control'] + [
        ('combined','combined_no_slice'),('combined','combined_no_contract'),
        ('combined','combined_no_expansion')]
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
    parser = argparse.ArgumentParser()
    parser.add_argument('--cache',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--workers',type=int,default=4)
    parser.add_argument('--preflight-only',action='store_true',help='Verify actual config/inputs and save manifest; no API client or calls')
    args = parser.parse_args()
    if not 1<=args.workers<=8:
        parser.error('workers must be 1..8')
    if args.output.exists():
        raise ValueError('Use a new directory: frozen evaluations cannot be overwritten or favorably resumed')
    from evaluation.build_clean_development_pilot import SETTINGS
    # Must happen before importing config/scorer/reasoning; inherited flags ignored.
    fixed = dict(SETTINGS, USE_BACKWARD_SLICE='0',BOUNDED_OUTPUT_CONTRACT='0',
                 EVIDENCE_EXPANSION='0',RECORD_REASONING_TRACE='1')
    os.environ.update(fixed)
    import config
    actual_settings = effective_configuration(config,fixed)
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
        samples.append(dict(record,source_path=str(path.resolve())))
    hashes = prediction_code_hashes()
    manifest = {'samples':samples,'profiles':PROFILES,'repeat_profiles':REPEAT_PROFILES,
        'first_repeat_primary':True,'settings':fixed,'effective_settings':actual_settings,'code_hashes':hashes,
        'selection_manifest_sha256':hashlib.sha256((args.cache/'manifest.json').read_bytes()).hexdigest(),
        'preparation_protocol_sha256':hashlib.sha256((args.cache/'protocol.json').read_bytes()).hexdigest(),
        'requested_model':config.LLM_MODEL,'budget':4096,'output_token_ceiling':150,
        'retry_policy':'SDK retries disabled; wrapper max 3 observed invocations; timeout 90s.',
        'planned_sample_profile_pairs':len(samples)*(len(PROFILES)+len(REPEAT_PROFILES)),
        'protocol':'Complete factorial + preregistered second repeat of control/contract/combined; no activation.',
        'expansion_zero_level':'Legacy standard routing retained; no_expansion profile removes the new upgrade, not all legacy iteration.',
        'scope':'New group-disjoint development, no locked test or validation tuning.'}
    args.output.mkdir(parents=True)
    (args.output/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    if args.preflight_only:
        from reasoning.prompts import get_system_prompt
        system=get_system_prompt('SRC:\nint n = a[i];')
        print(json.dumps({'status':'preflight_pass','api_calls':0,'samples':len(samples),
            'effective_settings':actual_settings,
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
        def observed_create(**kwargs):
            receipt = {**base, 'request':kwargs}
            try:
                response = client.chat.completions.create(**kwargs)
                usage = response.usage
                receipt.update(model=response.model,finish_reason=response.choices[0].finish_reason,
                    answer=response.choices[0].message.content,
                    prompt_tokens=getattr(usage,'prompt_tokens',0),
                    completion_tokens=getattr(usage,'completion_tokens',0),
                    total_tokens=getattr(usage,'total_tokens',0))
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
            result = run_hgl_pipeline(sample['source_path'],code,sid,str(args.cache/sid),
                                      observer,4096,ablation='',return_details=True)
            audit = result.get('module_audit',{})
            if audit.get('learned_scoring') or audit.get('graph_security_net'):
                raise ValueError('Rejected feature was unexpectedly activated')
            return {**base,**result}
        except Exception as exc:
            return dict(base,prediction=None,error=str(exc))
    with (args.output/'execution.log').open('w',encoding='utf-8') as log, contextlib.redirect_stdout(log):
        for repeat,profiles in ((1,PROFILES),(2,REPEAT_PROFILES)):
            for profile in profiles:
                if hashes != prediction_code_hashes():
                    raise ValueError('Prediction code changed during evaluation; discard the unfinished batch')
                flags = dict(zip(('USE_BACKWARD_SLICE','BOUNDED_OUTPUT_CONTRACT','EVIDENCE_EXPANSION'),
                                 map(bool,PROFILES[profile])))
                for name,value in flags.items():
                    setattr(config,name,value)
                with ThreadPoolExecutor(max_workers=args.workers) as pool:
                    jobs = [pool.submit(run,sample,profile,repeat) for sample in samples]
                    for job in as_completed(jobs):
                        row=job.result();rows.append(row);append('results.jsonl',row)
                        print(f"QUALITY {len(rows)}/{manifest['planned_sample_profile_pairs']} {profile}/r{repeat} {row['sample_id']} tokens={row.get('tokens_used')} error={bool(row.get('error'))}",
                              file=sys.__stdout__,flush=True)
                log.flush()
    report=summarize(rows,manifest,api_rows)
    (args.output/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({'metrics':report['metrics'],'repeat_sensitivity':report['repeat_sensitivity'],
                      'actual_invocations':report['actual_invocations'],'auto_promoted':False},indent=2))


if __name__=='__main__':
    main()
