"""One authorized120-result graph-SRC smoke; freeze before any external call."""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import contextlib
import importlib
import io
import json
import os
from pathlib import Path
import random
import re
import shutil
import socket
import sys
import threading
from types import SimpleNamespace
from unittest.mock import patch
from evaluation.evaluate_sven_complete_src import checked_rows, extended_score, request_hash
from evaluation.evaluate_reconstructed_llm import digest, read_json, score
from evaluation.audit_type_coverage_baseline import memoized_search

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'development/graph_read_slice_candidate_20261009/src'
PROTOCOL = ROOT/'evaluation/GRAPH_READ_SLICE_LLM_PROTOCOL_20261009.md'
PROFILES = ['control', 'read_slice']


def source_only_pair(control, candidate, code):
    a, b = json.loads(json.dumps(control)), json.loads(json.dumps(candidate))
    for request in (a, b):
        text = request['messages'][1]['content']
        if not text.startswith('SRC:\n'): raise ValueError('Missing source section')
        src, rest = text[5:].split('\n\nDEP PATHS:', 1)
        request['messages'][1]['content'] = 'SRC:\n<source>\n\nDEP PATHS:'+rest
    if a != b: raise ValueError('Candidate changed non-SRC request fields')
    candidate_src = candidate['messages'][1]['content'][5:].split('\n\nDEP PATHS:', 1)[0]
    if len(candidate_src) > min(1100, max(600, len(code)//8)) and candidate != control:
        raise ValueError('Changed source exceeds original character budget')
    return control != candidate


def prepare():
    receipt = read_json(ROOT/'baselines/type_coverage_reconstructed_20261008/baseline.json')
    old = read_json(ROOT/'output/sven_complete_src_eval_20261008/manifest.json')
    smoke = read_json(ROOT/'output/reconstructed_llm60_eval_20261008/manifest.json')
    samples = smoke['samples']
    if len(samples) != 30 or len({s['idx'] for s in samples}) != 30: raise ValueError('Wrong fixed selection')
    data = read_json(old['dataset'])
    if digest(old['dataset']) != old['dataset_sha256']: raise ValueError('Dataset changed')
    hashes = {n: digest(SOURCE/n) for n in receipt['code_hashes']}
    changes = {n.replace('/', '\\') for n in hashes if hashes[n] != receipt['code_hashes'][n]}
    if changes != {'linearization\\backward_slice.py'}: raise ValueError('More than one source-policy module changed')
    for root in (Path(receipt['frozen_source']), ROOT/'development/type_coverage_reconstructed_20261008/src'):
        for name, expected in receipt['code_hashes'].items():
            if digest(root/name) != expected: raise ValueError('Default/frozen foundation changed')
    for s in samples:
        expected = next(x for x in old['samples'] if x['idx'] == s['idx'])
        if s != expected: raise ValueError('Fixed sample identity changed')
        if digest(s['source_path']) != s['wrapped_source_sha256'] or digest(Path(s['cache_path'])/'export/export.dot') != s['cpg_sha256']:
            raise ValueError('Source/CPG changed')
    tooling = [Path(__file__).relative_to(ROOT), Path('evaluation/test_graph_read_slice_candidate.py'),
               Path('evaluation/test_graph_read_slice_runner.py'), Path('evaluation/audit_graph_read_slice.py'),
               Path('evaluation/evaluate_sven_complete_src.py'), Path('evaluation/evaluate_reconstructed_llm.py'),
               Path('evaluation/audit_type_coverage_baseline.py'), PROTOCOL.relative_to(ROOT)]
    return dict(samples=samples, profiles=PROFILES, repeats=[1, 2], planned_results=120, code_root=str(SOURCE), code_hashes=hashes,
                tooling_hashes={str(n): digest(ROOT/n) for n in tooling}, dataset=old['dataset'], dataset_sha256=old['dataset_sha256'],
                fixed_selection_manifest_sha256=digest(ROOT/'output/reconstructed_llm60_eval_20261008/manifest.json'),
                settings=receipt['settings'], endpoint='https://api.deepseek.com/v1', requested_model='deepseek-chat',
                exact_sources=len({s['source_sha256'] for s in samples}), family_groups=len({s['group_id'] for s in samples}),
                scope='30 fixed previously exposed SVEN development rows, paired graph-read SRC smoke; not independent final test',
                bootstrap_seed=20261009, bootstrap_draws=2000, automatic_promotion=False), data


def modules(manifest, offline):
    if not offline:
        env = ROOT/'.env'
        if env.exists():
            for line in env.read_text(encoding='utf8').splitlines():
                if line.strip() and not line.lstrip().startswith('#') and '=' in line:
                    k, v = line.split('=', 1); os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    os.environ.update(manifest['settings'])
    os.environ.update(LLM_MODEL='deepseek-chat', OPENAI_BASE_URL=manifest['endpoint'])
    if offline: os.environ['OPENAI_API_KEY'] = 'offline-not-a-key'
    sys.dont_write_bytecode = True; sys.path.insert(0, str(SOURCE))
    config = importlib.import_module('config'); pipeline = importlib.import_module('graph.pipeline')
    api = importlib.import_module('reasoning.llm_api')
    for module in (config, pipeline, api):
        if not Path(module.__file__).resolve().is_relative_to(SOURCE): raise ValueError('Wrong isolated source')
    for name, expected in manifest['settings'].items():
        if hasattr(config, name):
            actual = getattr(config, name)
            converted = expected == '1' if isinstance(actual, bool) else int(expected) if isinstance(actual, int) else expected
            if actual != converted: raise ValueError('Runtime setting mismatch: '+name)
    if not offline and (not config.LLM_API_KEY or config.LLM_API_KEY == 'offline-not-a-key' or config.LLM_MODEL != 'deepseek-chat' or config.LLM_BASE_URL.rstrip('/') != manifest['endpoint']):
        raise ValueError('Credential/endpoint/model mismatch')
    return config, pipeline, api


def summary(rows, calls, manifest):
    indexed, own = checked_rows(rows, calls, manifest)
    metrics, by_cwe, accounting, repeat = {}, {}, {}, {}
    for p in PROFILES:
        repeat[p] = sum(indexed[s['idx'], p, 1]['prediction'] != indexed[s['idx'], p, 2]['prediction'] for s in manifest['samples'])
        for rep in (1, 2):
            key = f'{p}/r{rep}'
            batch = [indexed[s['idx'], p, rep] for s in manifest['samples']]
            observed = [c for c in calls if c['profile'] == p and c['repeat'] == rep]
            metrics[key] = extended_score(batch)
            by_cwe[key] = {c: extended_score([r for r in batch if r['cwe'] == c]) for c in sorted({s['cwe'] for s in manifest['samples']})}
            accounting[key] = dict(invocations=len(observed), failed_invocations=sum(bool(c.get('error')) for c in observed),
                                  unknown_usage=sum(not c.get('usage_known') for c in observed), models=dict(Counter(c.get('model', 'unavailable') for c in observed)),
                                  length_finishes=sum(c.get('finish_reason') == 'length' for c in observed),
                                  **{k: sum(c.get(k) or 0 for c in observed) for k in ('prompt_tokens', 'completion_tokens', 'total_tokens')})
    intervals = {}
    for name, subset in [('global', manifest['samples']), ('CWE-125', [s for s in manifest['samples'] if s['cwe'] == 'CWE-125'])]:
        groups = defaultdict(list)
        for s in subset: groups[s['group_id']].append(s['idx'])
        rng = random.Random(manifest['bootstrap_seed']); deltas = {k: [] for k in ('f1', 'accuracy')}
        for _ in range(manifest['bootstrap_draws']):
            ids = [i for group in rng.choices(list(groups.values()), k=len(groups)) for i in group]
            a, b = [score([indexed[i, p, 1] for i in ids]) for p in PROFILES]
            for k in deltas: deltas[k].append(b[k]-a[k])
        a = metrics['control/r1'] if name == 'global' else by_cwe['control/r1'][name]
        b = metrics['read_slice/r1'] if name == 'global' else by_cwe['read_slice/r1'][name]
        intervals[name] = {k: dict(delta=b[k]-a[k], ci95=[sorted(v)[50], sorted(v)[1950]]) for k, v in deltas.items()}
    constant = score([dict(s, prediction=1) for s in manifest['samples']])
    functional = all(not v['errors'] and not v['uncertain'] for v in metrics.values()) and all(not v['failed_invocations'] and not v['unknown_usage'] for v in accounting.values())
    gates = dict(cwe125_improves_both=all(by_cwe[f'read_slice/r{r}']['CWE-125'][k] > by_cwe[f'control/r{r}']['CWE-125'][k] for r in (1, 2) for k in ('f1', 'accuracy')),
                 global_nonnegative_both=all(metrics[f'read_slice/r{r}'][k] >= metrics[f'control/r{r}'][k] for r in (1, 2) for k in ('f1', 'accuracy')),
                 positive_mcc_constant_accuracy_both=all(metrics[f'read_slice/r{r}']['mcc'] > 0 and metrics[f'read_slice/r{r}']['accuracy'] > constant['accuracy'] for r in (1, 2)),
                 primary_cwe125_accuracy_interval_positive=intervals['CWE-125']['accuracy']['ci95'][0] > 0)
    return dict(scheduled_results=len(rows), metrics=metrics, by_cwe=by_cwe, api_accounting=accounting,
                actual_invocations=len(calls), total_reported_tokens=sum(c.get('total_tokens') or 0 for c in calls),
                repeated_prediction_disagreements=repeat, always_positive=constant, primary_family_intervals=intervals,
                functional_gate=functional, gates=gates, exploratory_support=functional and all(gates.values()), auto_promoted=False,
                scope=manifest['scope'], limitations=['Same previously exposed30-row selection, correlated/conflicting sources, not independent evidence.',
                'Only SRC policy changes; original graph decoder/parser/net semantics remain.', 'Source dependency/brace heuristics are not capacity or dominance proofs.',
                '150-output truncation retained; repeat variability/family uncertainty must be reported.', 'No automatic rerun/promotion/full254 expansion or submission claim.'])


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--preflight-only', action='store_true'); parser.add_argument('--preflight', type=Path)
    parser.add_argument('--authorized-real-120', action='store_true'); parser.add_argument('--workers', type=int, default=4)
    args = parser.parse_args()
    if args.output.exists() or not 1 <= args.workers <= 4: raise ValueError('Fresh directory/workers1..4 required')
    if not args.preflight_only and (not args.preflight or not args.authorized_real_120): raise ValueError('Frozen preflight and specific authority required')
    manifest, data = prepare()
    config, pipeline, api = modules(manifest, args.preflight_only)
    args.output.mkdir(parents=True)
    def save(name, value): (args.output/name).write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding='utf8')
    def blocked(*a, **k): raise ValueError('Unobserved client/process forbidden')
    requests = {}
    originals = {n: getattr(pipeline, n) for n in ('load_graph', 'summarize_graph', 'extract_all_candidate_paths', 'retrieve_topk')}
    local = threading.local()
    def cached(name, *a, **k):
        key = (name, tuple(a[0].nodes())) if name != 'load_graph' else name
        if key not in local.prepared: local.prepared[key] = originals[name](*a, **k)
        value = local.prepared[key]
        return value.copy() if name in ('load_graph', 'summarize_graph') else [list(p) for p in value]
    def patches():
        stack = contextlib.ExitStack()
        stack.enter_context(patch.object(api, 'create_client', blocked)); stack.enter_context(patch('subprocess.Popen', blocked))
        stack.enter_context(patch.object(pipeline, 'build_cpg', side_effect=lambda source, cache: str(Path(cache)/'export')))
        for name in originals:
            stack.enter_context(patch.object(pipeline, name, side_effect=lambda *a, _name=name, **k: cached(_name, *a, **k)))
        stack.enter_context(patch.object(re, 'search', memoized_search(re.search)))
        return stack
    re._MAXCACHE = 32768
    if hasattr(re, '_MAXCACHE2'): re._MAXCACHE2 = 16384
    if args.preflight_only:
        old_first = {}
        for line in (ROOT/'output/sven_complete_src_eval_20261008/api_receipts.jsonl').read_text(encoding='utf8').splitlines():
            c = json.loads(line)
            if c['profile'] == 'control': old_first.setdefault(c['idx'], c['request'])
        receipts = []
        with patches(), patch.object(socket.socket, 'connect', blocked), patch.object(socket, 'create_connection', blocked):
            for s in manifest['samples']:
                local.prepared = {}
                for profile in PROFILES:
                    config.USE_BACKWARD_SLICE = profile == 'read_slice'
                    captured = []
                    def mock(**request):
                        captured.append(request)
                        return SimpleNamespace(model='offline-mock', usage=SimpleNamespace(total_tokens=0, prompt_tokens=0, completion_tokens=0),
                            choices=[SimpleNamespace(finish_reason='stop', message=SimpleNamespace(content='HYPOTHESIS: no vulnerability detected\nACTION: {"action":"Stop"}'))])
                    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=mock)))
                    with contextlib.redirect_stdout(io.StringIO()):
                        result = pipeline.run_hgl_pipeline(s['source_path'], data[s['idx']]['input'], s['sample_id'], s['cache_path'], client, 4096, return_details=True)
                    if len(captured) != 1: raise ValueError('Preflight expected one fixed mock Stop response')
                    requests[s['idx'], profile] = captured[0]
                    receipts.append(dict(idx=s['idx'], profile=profile, source_policy=result['module_audit'].get('backward_slice', {})))
                if requests[s['idx'], 'control'] != old_first[s['idx']]: raise ValueError('Control input differs from verified foundation')
                source_only_pair(requests[s['idx'], 'control'], requests[s['idx'], 'read_slice'], data[s['idx']]['input'])
                print(f'OFFLINE graph SRC preflight {len(requests)//2}/30 api_calls=0', flush=True)
        manifest['first_request_sha256'] = {f'{p}/{i}': request_hash(v) for (i, p), v in requests.items()}
        manifest['source_input_changes'] = sum(requests[s['idx'], 'control'] != requests[s['idx'], 'read_slice'] for s in manifest['samples'])
        save('manifest.json', manifest); save('source_policy_receipts.json', receipts)
        (args.output/'first_requests.jsonl').write_text(''.join(json.dumps(dict(idx=i, profile=p, request=v), ensure_ascii=False)+'\n' for (i,p),v in requests.items()), encoding='utf8')
        print(f'PREFLIGHT PASS rows30 results120 changes{manifest["source_input_changes"]} api_calls0'); return
    frozen = read_json(args.preflight/'manifest.json')
    if any(frozen[k] != v for k,v in manifest.items()): raise ValueError('Frozen preflight drift')
    manifest = frozen
    requests = {(r['idx'], r['profile']): r['request'] for r in map(json.loads, (args.preflight/'first_requests.jsonl').read_text(encoding='utf8').splitlines())}
    if {f'{p}/{i}': request_hash(v) for (i,p),v in requests.items()} != manifest['first_request_sha256']: raise ValueError('Frozen request drift')
    save('manifest.json', manifest)
    for group, names, root in [('code_snapshot', manifest['code_hashes'], SOURCE), ('tooling_snapshot', manifest['tooling_hashes'], ROOT)]:
        for name, expected in names.items():
            dest = args.output/group/name; dest.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(root/name, dest)
            if digest(dest) != expected: raise ValueError('Snapshot hash changed')
    from openai import OpenAI
    import httpx
    client = OpenAI(api_key=config.LLM_API_KEY, base_url=config.LLM_BASE_URL, max_retries=0, timeout=90,
                    http_client=httpx.Client(trust_env=False, timeout=90))
    rows, calls, lock = [], [], threading.Lock()
    def append(name, value):
        with lock:
            with (args.output/name).open('a', encoding='utf8') as f: f.write(json.dumps(value, ensure_ascii=False)+'\n')
    def one(sample, profile, rep):
        base = {k: sample[k] for k in ('idx','sample_id','target','group_id','cwe','source_sha256')}
        base.update(profile=profile, repeat=rep); own = []; first_checked = False
        def observed(**request):
            nonlocal first_checked
            if not first_checked:
                if request != requests[sample['idx'], profile]: raise ValueError('Actual first request differs from freeze')
                first_checked = True
            if len(own) >= 6 or request.get('max_tokens') != 150 or request.get('model') != 'deepseek-chat' or request.get('temperature') != 0:
                raise ValueError('Outside authorized call bounds')
            record = dict(base, request=request)
            try:
                response = client.chat.completions.create(**request); usage = response.usage
                record.update(answer=response.choices[0].message.content, model=response.model, finish_reason=response.choices[0].finish_reason,
                              usage_known=usage is not None, **{k:getattr(usage,k,None) for k in ('prompt_tokens','completion_tokens','total_tokens')})
                return response
            except Exception as exc:
                record.update(error=str(exc).replace(config.LLM_API_KEY,'[REDACTED]'), usage_known=False)
                raise RuntimeError(record['error']) from None
            finally:
                own.append(record); append('api_receipts.jsonl',record)
                with lock: calls.append(record)
        try:
            if digest(sample['source_path']) != sample['wrapped_source_sha256'] or digest(Path(sample['cache_path'])/'export/export.dot') != sample['cpg_sha256']: raise ValueError('Input changed')
            observer = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=observed)))
            value = pipeline.run_hgl_pipeline(sample['source_path'],data[sample['idx']]['input'],sample['sample_id'],sample['cache_path'],observer,4096,return_details=True)
            if not first_checked or value['reasoning_steps'] > 2: raise ValueError('Extra/unobserved steps')
            value['tokens_used'] = sum(c.get('total_tokens') or 0 for c in own)
            return dict(base, **value, first_request_verified=first_checked)
        except Exception as exc:
            return dict(base,prediction=None,error=str(exc).replace(config.LLM_API_KEY,'[REDACTED]'),tokens_used=sum(c.get('total_tokens') or 0 for c in own),first_request_verified=first_checked)
    def paired(sample, profile):
        local.prepared = {}
        for rep in (1,2):
            row = one(sample,profile,rep); append('results.jsonl',row)
            with lock: rows.append(row); done = len(rows)
            print(f'LLM graph SRC {done}/120 {profile}/r{rep} idx={sample["idx"]} error={bool(row.get("error"))}',file=sys.__stdout__,flush=True)
    try:
        with patches(), (args.output/'execution.log').open('w',encoding='utf8') as log, contextlib.redirect_stdout(log):
            for profile in PROFILES:
                config.USE_BACKWARD_SLICE = profile == 'read_slice'
                with ThreadPoolExecutor(max_workers=args.workers) as pool:
                    for future in as_completed([pool.submit(paired,s,profile) for s in manifest['samples']]): future.result()
                log.flush()
    finally: client.close()
    fresh,_ = prepare()
    if any(fresh[k] != manifest[k] for k in fresh): raise ValueError('Freeze changed during run')
    report = summary(rows,calls,manifest); save('report.json',report)
    print(json.dumps(dict(metrics=report['metrics'],by_cwe=report['by_cwe'],gates=report['gates'],tokens=report['total_reported_tokens']),indent=2))


if __name__ == '__main__': main()
