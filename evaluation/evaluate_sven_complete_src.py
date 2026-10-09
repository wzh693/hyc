"""Frozen real SVEN comparison of one isolated complete-provided-SRC policy."""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import contextlib
import copy
from functools import lru_cache
import hashlib
import importlib
import json
import os
from pathlib import Path
import random
import re
import shutil
import sys
import threading
from types import SimpleNamespace
from unittest.mock import patch

from evaluation.evaluate_reconstructed_llm import digest, read_json, score

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'development/type_coverage_reconstructed_20261008/src'
PROTOCOL = ROOT/'evaluation/SVEN_COMPLETE_SRC_PROTOCOL_20261008.md'
CHANGED = {'config.py', 'linearization\\typed_paths.py'}


def request_hash(request):
    return hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()


def source_only_request(control, code):
    """Independent deterministic input recipe; actual pipeline must match it."""
    request = copy.deepcopy(control)
    if len(request['messages']) != 2 or request['messages'][1]['role'] != 'user':
        raise ValueError('Unexpected message structure')
    user = request['messages'][1]['content']
    if not user.startswith('SRC:\n') or '\n\nDEP PATHS:' not in user:
        raise ValueError('Missing source boundary')
    old, rest = user[5:].split('\n\nDEP PATHS:', 1)
    src = code if code and len(code) <= 6000 else (
        '/* Source exceeds complete-slice cap; sparse evidence follows. */\n'+old if code else old)
    request['messages'][1]['content'] = 'SRC:\n'+src+'\n\nDEP PATHS:'+rest
    return request


def compare_source_requests(control, candidate, code):
    if candidate != source_only_request(control, code):
        raise ValueError('Non-SRC input or source recipe changed')
    return control != candidate


def preparation(candidate_only=False):
    receipt = read_json(ROOT/'baselines/type_coverage_reconstructed_20261008/baseline.json')
    old = read_json(receipt['source_manifest'])
    data = read_json(old['dataset'])
    if len(data) != 254 or digest(old['dataset']) != old['dataset_sha256']:
        raise ValueError('Authorized dataset identity changed')
    hashes = {name: digest(SOURCE/name) for name in receipt['code_hashes']}
    differences = {name for name in hashes if hashes[name] != receipt['code_hashes'][name]}
    if {n.replace('/', '\\') for n in differences} != CHANGED:
        raise ValueError('More than one declared candidate/source drift')
    for name, expected in receipt['code_hashes'].items():
        if digest(Path(receipt['frozen_source'])/name) != expected:
            raise ValueError('Frozen foundation changed')
    first = {}
    for line in (ROOT/'output/sven_full_pipeline_eval_20261006/api_receipts.jsonl').read_text(encoding='utf8').splitlines():
        call = json.loads(line)
        if call['profile'] == 'control' and not call.get('error'):
            first.setdefault(call['idx'], call['request'])
    if set(first) != set(range(254)): raise ValueError('Missing verified control requests')
    samples = copy.deepcopy(old['samples'])
    if {s['idx'] for s in samples} != set(range(254)) or len(samples) != 254:
        raise ValueError('Incomplete frozen sample manifest')
    for sample in samples:
        item = data[sample['idx']]
        if sample['target'] != int(item['output'] == 'VULNERABLE') or sample['cwe'] != item['cwe']:
            raise ValueError('Changed label/CWE')
        if hashlib.sha256(item['input'].encode()).hexdigest() != sample['source_sha256']:
            raise ValueError('Changed supplied source')
        for name in ('source_path', 'cache_path'):
            path = Path(sample[name]); sample[name] = str(path if path.is_absolute() else ROOT/path)
        try:
            if digest(sample['source_path']) != sample['wrapped_source_sha256'] or digest(Path(sample['cache_path'])/'export/export.dot') != sample['cpg_sha256']:
                raise ValueError('Prepared source/graph changed')
        except Exception as exc:
            sample['preparation_error'] = str(exc)
    profiles = ['complete_src'] if candidate_only else ['control', 'complete_src']
    requests = {(s['idx'], p): first[s['idx']] if p == 'control' else source_only_request(first[s['idx']], data[s['idx']]['input'])
                for s in samples for p in profiles}
    for s in samples:
        compare_source_requests(first[s['idx']], source_only_request(first[s['idx']], data[s['idx']]['input']), data[s['idx']]['input'])
    tool_hashes = {str(Path(__file__).relative_to(ROOT)): digest(__file__),
                   'evaluation/evaluate_reconstructed_llm.py': digest(ROOT/'evaluation/evaluate_reconstructed_llm.py'),
                   'evaluation/audit_sven_complete_src.py': digest(ROOT/'evaluation/audit_sven_complete_src.py'),
                   'evaluation/test_sven_complete_src.py': digest(ROOT/'evaluation/test_sven_complete_src.py'),
                   str(PROTOCOL.relative_to(ROOT)): digest(PROTOCOL)}
    manifest = dict(samples=samples, profiles=profiles, repeats=[1, 2],
        code_root=str(SOURCE), code_hashes=hashes, foundation_hashes=receipt['code_hashes'],
        changed_source_files=sorted(differences), tooling_hashes=tool_hashes,
        settings=dict(receipt['settings'], COMPLETE_SOURCE_SLICE='0'),
        profile_settings={p: {'COMPLETE_SOURCE_SLICE': '1' if p == 'complete_src' else '0'} for p in profiles},
        dataset=str(old['dataset']), dataset_sha256=old['dataset_sha256'],
        planned_results=254*len(profiles)*2, max_steps=2, output_cap=150, graph_budget=4096,
        max_attempts_per_step=3, sdk_retries=0, timeout_seconds=90,
        endpoint='https://api.deepseek.com/v1', requested_model='deepseek-chat',
        first_request_sha256={f'{p}/{i}': request_hash(r) for (i, p), r in requests.items()},
        exact_sources=len({s['source_sha256'] for s in samples}),
        family_groups=len({s['group_id'] for s in samples}),
        source_cap_fallbacks=sum(len(item['input']) > 6000 for item in data),
        candidate_source_input_changes=sum(first[i] != source_only_request(first[i], data[i]['input']) for i in range(254)),
        bootstrap_seed=20261012, bootstrap_draws=2000,
        preflight_kind='Deterministic frozen request recipes; not a full254-row pipeline shadow.',
        scope='All254 local exposed SVEN sliced-classification rows; not held-out or all upstream SVEN.',
        candidate_only=candidate_only, automatic_promotion=False)
    return manifest, requests, data


def checked_rows(rows, calls, manifest):
    samples = {s['idx']: s for s in manifest['samples']}
    expected = {(i, p, r) for i in samples for p in manifest['profiles'] for r in manifest['repeats']}
    indexed = {(r['idx'], r['profile'], r['repeat']): r for r in rows}
    if len(indexed) != len(rows) or set(indexed) != expected:
        raise ValueError('Incomplete/duplicate/unexpected planned rows')
    own = defaultdict(list)
    for call in calls:
        key = call['idx'], call['profile'], call['repeat']
        if key not in expected: raise ValueError('Unscheduled API receipt')
        own[key].append(call)
    for key, row in indexed.items():
        sample = samples[key[0]]
        if any(row[k] != sample[k] for k in ('target', 'cwe', 'group_id', 'source_sha256', 'sample_id')):
            raise ValueError('Result identity mismatch')
        invocations = own[key]
        if len(invocations) > 6: raise ValueError('Invocation limit exceeded')
        if row['tokens_used'] != sum(c.get('total_tokens') or 0 for c in invocations):
            raise ValueError('Usage mismatch')
        for call in invocations:
            if any(call[k] != row[k] for k in ('target', 'cwe', 'group_id', 'source_sha256', 'sample_id')):
                raise ValueError('Call identity mismatch')
            if call['request']['model'] != 'deepseek-chat' or call['request']['max_tokens'] != 150 or call['request']['temperature'] != 0:
                raise ValueError('Unapproved API parameters')
        if invocations and request_hash(invocations[0]['request']) != manifest['first_request_sha256'][f'{key[1]}/{key[0]}']:
            raise ValueError('First input differs from freeze')
        if not row.get('error'):
            successful = [c for c in invocations if not c.get('error')]
            trace = row.get('arbitrate', {}).get('reasoning_trace', [])
            if not successful or len(successful) != len(trace) or len(trace) > 2:
                raise ValueError('Missing/extra actual responses')
            if any(c['answer'] != t['answer'] or c['request']['messages'] != [
                    {'role': 'system', 'content': t['system_prompt']}, {'role': 'user', 'content': t['user_prompt']}]
                   for c, t in zip(successful, trace)):
                raise ValueError('Actual answers/requests differ from trace')
    return indexed, own


def extended_score(rows):
    result = score(rows)
    tp, tn, fp, fn = (result[k] for k in ('tp', 'tn', 'fp', 'fn'))
    result['balanced_accuracy'] = ((tp/(tp+fn) if tp+fn else 0)+(tn/(tn+fp) if tn+fp else 0))/2
    result['tokens_per_scheduled'] = result['total_tokens']/len(rows) if rows else 0
    return result


def summarize(rows, calls, manifest, draws=None):
    indexed, own = checked_rows(rows, calls, manifest)
    samples, profiles = manifest['samples'], manifest['profiles']
    batches = {f'{p}/r{rep}': [indexed[s['idx'], p, rep] for s in samples] for p in profiles for rep in (1, 2)}
    metrics = {key: extended_score(batch) for key, batch in batches.items()}
    by_cwe = {key: {c: extended_score([r for r in batch if r['cwe'] == c]) for c in sorted({s['cwe'] for s in samples})}
              for key, batch in batches.items()}
    accounting = {}
    for p in profiles:
        for rep in (1, 2):
            observed = [c for c in calls if c['profile'] == p and c['repeat'] == rep]
            good = [c for c in observed if not c.get('error')]
            accounting[f'{p}/r{rep}'] = dict(invocations=len(observed), successful_invocations=len(good),
                failed_invocations=len(observed)-len(good), unknown_usage_invocations=sum(not c.get('usage_known') for c in observed),
                actual_models=dict(Counter(c.get('model', 'unavailable') for c in observed)),
                length_calls=sum(c.get('finish_reason') == 'length' for c in good),
                **{k: sum(c.get(k) or 0 for c in observed) for k in ('prompt_tokens', 'completion_tokens', 'total_tokens')})
    constant = {name: extended_score([dict(s, prediction=p) for s in samples])
                for name, p in (('always_positive', 1), ('always_negative', 0))}
    repeat = {p: dict(prediction_disagreements=sum(indexed[s['idx'], p, 1]['prediction'] != indexed[s['idx'], p, 2]['prediction'] for s in samples),
                      verified_first_requests=sum(bool(own[s['idx'], p, r]) for s in samples for r in (1, 2))) for p in profiles}
    intervals, gates = {}, {}
    if 'control' in profiles:
        draws = manifest['bootstrap_draws'] if draws is None else draws
        for name, subset in (('global', samples), ('CWE-125', [s for s in samples if s['cwe'] == 'CWE-125'])):
            groups = defaultdict(list)
            for s in subset: groups[s['group_id']].append(s['idx'])
            rng = random.Random(manifest['bootstrap_seed'])
            deltas = {'f1': [], 'accuracy': []}
            for _ in range(draws):
                ids = [i for group in rng.choices(list(groups.values()), k=len(groups)) for i in group]
                a = score([indexed[i, 'control', 1] for i in ids]); b = score([indexed[i, 'complete_src', 1] for i in ids])
                for k in deltas: deltas[k].append(b[k]-a[k])
            actual_a = metrics['control/r1'] if name == 'global' else by_cwe['control/r1'][name]
            actual_b = metrics['complete_src/r1'] if name == 'global' else by_cwe['complete_src/r1'][name]
            intervals[name] = {k: dict(delta=actual_b[k]-actual_a[k], ci95=[sorted(v)[int(draws*.025)], sorted(v)[min(draws-1, int(draws*.975))]]) for k, v in deltas.items()}
        gates = dict(
            cwe125_improves_both=all(by_cwe[f'complete_src/r{r}']['CWE-125'][k] > by_cwe[f'control/r{r}']['CWE-125'][k] for r in (1, 2) for k in ('f1', 'accuracy')),
            global_nonnegative_both=all(metrics[f'complete_src/r{r}'][k] >= metrics[f'control/r{r}'][k] for r in (1, 2) for k in ('f1', 'accuracy')),
            constant_accuracy_positive_mcc_both=all(metrics[f'complete_src/r{r}']['accuracy'] > constant['always_positive']['accuracy'] and metrics[f'complete_src/r{r}']['mcc'] > 0 for r in (1, 2)),
            primary_cwe125_accuracy_interval=intervals['CWE-125']['accuracy']['ci95'][0] > 0)
    functional = all(not m['errors'] and not m['uncertain'] for m in metrics.values()) and all(not a['failed_invocations'] and not a['unknown_usage_invocations'] for a in accounting.values())
    return dict(scheduled_results=len(rows), metrics=metrics, by_cwe=by_cwe, api_accounting=accounting,
        actual_invocations=len(calls), total_reported_tokens=sum(c.get('total_tokens') or 0 for c in calls),
        constant_baselines=constant, repeat_sensitivity=repeat, primary_family_intervals=intervals,
        gates=gates, functional_gate=functional, exploratory_support=functional and bool(gates) and all(gates.values()),
        auto_promoted=False, scope=manifest['scope'],
        limitations=['Complete provided slices are not necessarily complete functions/helper contracts.',
                    'Additional source evidence increases input costs; cap150 truncation remains.',
                    'Exposed correlated/conflicting-label data retained; repeats are not new samples.',
                    'No independent final test, no historical61.15% recovery or causal generalization claim.',
                    'Family bootstrap is descriptive for these groups, not future provider variability.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--preflight-only', action='store_true')
    parser.add_argument('--preflight', type=Path)
    parser.add_argument('--authorized-real-sven', action='store_true')
    parser.add_argument('--candidate-only', action='store_true')
    parser.add_argument('--workers', type=int, default=4)
    args = parser.parse_args()
    if args.output.exists() or not 1 <= args.workers <= 4: raise ValueError('Fresh output and workers1..4 required')
    if not args.preflight_only and (not args.preflight or not args.authorized_real_sven): raise ValueError('New explicit authority and frozen preflight required')
    manifest, requests, data = preparation(args.candidate_only)
    args.output.mkdir(parents=True)
    def save(name, value): (args.output/name).write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding='utf8')
    save('manifest.json', manifest)
    if args.preflight_only:
        with (args.output/'first_requests.jsonl').open('w', encoding='utf8') as f:
            for (idx, profile), request in requests.items(): f.write(json.dumps(dict(idx=idx, profile=profile, request=request), ensure_ascii=False)+'\n')
        print(f'PREFLIGHT PASS rows254 planned{manifest["planned_results"]} source_changes={manifest["candidate_source_input_changes"]} fallbacks={manifest["source_cap_fallbacks"]} api_calls0')
        return
    if read_json(args.preflight/'manifest.json') != manifest: raise ValueError('Frozen preflight drift')
    frozen_requests = {(r['idx'], r['profile']): r['request'] for r in map(json.loads, (args.preflight/'first_requests.jsonl').read_text(encoding='utf8').splitlines())}
    if frozen_requests != requests: raise ValueError('Frozen first requests drift')
    env_file = ROOT/'.env'
    if env_file.exists():
        for line in env_file.read_text(encoding='utf8').splitlines():
            if line.strip() and not line.lstrip().startswith('#') and '=' in line:
                k, v = line.split('=', 1); os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    os.environ.update(manifest['settings'])
    os.environ.update(LLM_MODEL='deepseek-chat', OPENAI_BASE_URL=manifest['endpoint'])
    sys.dont_write_bytecode = True; sys.path.insert(0, str(SOURCE))
    config = importlib.import_module('config'); pipeline = importlib.import_module('graph.pipeline')
    api = importlib.import_module('reasoning.llm_api'); loop = importlib.import_module('reasoning.reasoning_loop')
    importlib.import_module('learning.scorer')
    for module in (config, pipeline, api, loop):
        if not Path(module.__file__).resolve().is_relative_to(SOURCE): raise ValueError('Wrong source root')
    for name, value in manifest['settings'].items():
        if hasattr(config, name):
            actual = getattr(config, name)
            expected = value == '1' if isinstance(actual, bool) else int(value) if isinstance(actual, int) else value
            if actual != expected: raise ValueError('Runtime setting mismatch: '+name)
    if not config.LLM_API_KEY or config.LLM_MODEL != 'deepseek-chat' or config.LLM_BASE_URL.rstrip('/') != manifest['endpoint']: raise ValueError('Credential/endpoint/model mismatch')
    for name, expected in manifest['code_hashes'].items():
        destination = args.output/'code_snapshot'/name; destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(SOURCE/name, destination)
        if digest(destination) != expected: raise ValueError('Snapshot changed')
    for name in manifest['tooling_hashes']:
        destination = args.output/'tooling_snapshot'/name; destination.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(ROOT/name, destination)
    from openai import OpenAI
    import httpx
    client = OpenAI(api_key=config.LLM_API_KEY, base_url=config.LLM_BASE_URL, max_retries=0, timeout=90,
                    http_client=httpx.Client(trust_env=False, timeout=90))
    rows, calls = [], []; lock = threading.Lock(); local = threading.local()
    def append(name, value):
        with lock:
            with (args.output/name).open('a', encoding='utf8') as f: f.write(json.dumps(value, ensure_ascii=False)+'\n')
    originals = {n: getattr(pipeline, n) for n in ('load_graph', 'summarize_graph', 'extract_all_candidate_paths', 'retrieve_topk')}
    def cached(name, *values, **kwargs):
        key = (name, tuple(values[0].nodes()) if name != 'load_graph' else None)
        if key not in local.prepared: local.prepared[key] = originals[name](*values, **kwargs)
        value = local.prepared[key]
        if name in ('load_graph', 'summarize_graph'): return value.copy()
        return [list(p) for p in value]
    def blocked(*a, **kw): raise ValueError('Only authorized observed client/prepared CPG permitted')
    def one(sample, profile, repeat):
        base = {k: sample[k] for k in ('idx', 'sample_id', 'target', 'group_id', 'cwe', 'source_sha256')}
        base.update(profile=profile, repeat=repeat); own = []; first_checked = False
        def observed(**request):
            nonlocal first_checked
            if not first_checked:
                if request != requests[sample['idx'], profile]: raise ValueError('Actual first request differs from frozen recipe')
                first_checked = True
            if len(own) >= 6 or request.get('model') != 'deepseek-chat' or request.get('max_tokens') != 150 or request.get('temperature') != 0: raise ValueError('Request outside approval')
            record = dict(base, request=request)
            try:
                response = client.chat.completions.create(**request); usage = response.usage
                record.update(answer=response.choices[0].message.content, model=response.model,
                    finish_reason=response.choices[0].finish_reason, usage_known=usage is not None,
                    **{k: getattr(usage, k, None) for k in ('prompt_tokens', 'completion_tokens', 'total_tokens')})
                return response
            except Exception as exc:
                record.update(error=str(exc).replace(config.LLM_API_KEY, '[REDACTED]'), usage_known=False)
                raise RuntimeError(record['error']) from None
            finally:
                own.append(record); append('api_receipts.jsonl', record)
                with lock: calls.append(record)
        observer = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=observed)))
        try:
            if sample.get('preparation_error'): raise ValueError(sample['preparation_error'])
            if digest(sample['source_path']) != sample['wrapped_source_sha256'] or digest(Path(sample['cache_path'])/'export/export.dot') != sample['cpg_sha256']: raise ValueError('Prepared input changed')
            result = pipeline.run_hgl_pipeline(sample['source_path'], data[sample['idx']]['input'], sample['sample_id'], sample['cache_path'], observer, 4096, return_details=True)
            if not first_checked or result.get('reasoning_steps', 0) > 2: raise ValueError('Unobserved/extra step')
            result['tokens_used'] = sum(c.get('total_tokens') or 0 for c in own)
            return dict(base, **result, first_request_verified=first_checked)
        except Exception as exc:
            return dict(base, prediction=None, error=str(exc).replace(config.LLM_API_KEY, '[REDACTED]'), first_request_verified=first_checked,
                        tokens_used=sum(c.get('total_tokens') or 0 for c in own))
    def paired(sample, profile):
        local.prepared = {}
        for repeat in (1, 2):
            row = one(sample, profile, repeat); append('results.jsonl', row)
            with lock: rows.append(row); done = len(rows)
            print(f'SVEN SRC {done}/{manifest["planned_results"]} {profile}/r{repeat} idx={sample["idx"]} error={bool(row.get("error"))}', file=sys.__stdout__, flush=True)
        local.prepared.clear()
    cached_search = lru_cache(maxsize=65536)(re.search)
    re._MAXCACHE = 32768
    if hasattr(re, '_MAXCACHE2'): re._MAXCACHE2 = 16384
    try:
        with patch.object(api, 'create_client', blocked), \
                patch.object(pipeline, 'build_cpg', side_effect=lambda source, cache: str(Path(cache)/'export')), \
                patch.object(pipeline, 'load_graph', side_effect=lambda *a, **k: cached('load_graph', *a, **k)), \
                patch.object(pipeline, 'summarize_graph', side_effect=lambda *a, **k: cached('summarize_graph', *a, **k)), \
                patch.object(pipeline, 'extract_all_candidate_paths', side_effect=lambda *a, **k: cached('extract_all_candidate_paths', *a, **k)), \
                patch.object(pipeline, 'retrieve_topk', side_effect=lambda *a, **k: cached('retrieve_topk', *a, **k)), \
                patch.object(re, 'search', cached_search), patch('subprocess.Popen', blocked), \
                (args.output/'execution.log').open('w', encoding='utf8') as log, contextlib.redirect_stdout(log):
            # Profile flag is constant throughout each pool; no cross-thread flag races.
            for profile in manifest['profiles']:
                config.COMPLETE_SOURCE_SLICE = profile == 'complete_src'
                with ThreadPoolExecutor(max_workers=args.workers) as pool:
                    for future in as_completed([pool.submit(paired, s, profile) for s in manifest['samples']]): future.result()
                log.flush()
    finally:
        client.close()
    if manifest['code_hashes'] != {n: digest(SOURCE/n) for n in manifest['code_hashes']} or any(digest(ROOT/n) != h for n, h in manifest['tooling_hashes'].items()) or digest(manifest['dataset']) != manifest['dataset_sha256']: raise ValueError('Freeze changed during execution')
    report = summarize(rows, calls, manifest); report['frozen_code_matches'] = True; save('report.json', report)
    print(json.dumps(dict(metrics=report['metrics'], by_cwe=report['by_cwe'], gates=report['gates'], tokens=report['total_reported_tokens']), indent=2))


if __name__ == '__main__': main()
