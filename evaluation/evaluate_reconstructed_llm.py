"""Authorized 30-row/two-repeat real-model smoke of the isolated foundation."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import contextlib
from functools import lru_cache
import hashlib
import importlib
import io
import json
import math
import os
from pathlib import Path
import random
import re
import shutil
import sys
import threading
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def select_indices(data, seed=20261009):
    rng = random.Random(seed)
    indices = []
    for cwe in sorted({r['cwe'] for r in data}):
        for label in ('BENIGN', 'VULNERABLE'):
            eligible = [i for i, r in enumerate(data) if r['cwe'] == cwe and r['output'] == label]
            if len(eligible) < 5: raise ValueError('Insufficient stratum')
            indices.extend(rng.sample(eligible, 5))
    if len(indices) != 30 or len(set(indices)) != 30:
        raise ValueError('Expected exactly 30 distinct fixed rows')
    return sorted(indices)


def score(rows):
    tp = tn = fp = fn = 0
    for r in rows:
        y, p = r['target'], r.get('prediction')
        if p not in (0, 1):
            fn += y == 1; fp += y == 0
        elif y == 1:
            tp += p == 1; fn += p == 0
        else:
            tn += p == 0; fp += p == 1
    denominator = 2*tp+fp+fn
    mcc_den = (tp+fp)*(tp+fn)*(tn+fp)*(tn+fn)
    return dict(n=len(rows), tp=tp, tn=tn, fp=fp, fn=fn,
        f1=2*tp/denominator if denominator else 0,
        accuracy=(tp+tn)/len(rows) if rows else 0,
        precision=tp/(tp+fp) if tp+fp else 0, recall=tp/(tp+fn) if tp+fn else 0,
        mcc=(tp*tn-fp*fn)/math.sqrt(mcc_den) if mcc_den else 0,
        errors=sum(bool(r.get('error')) for r in rows),
        uncertain=sum(r.get('prediction') not in (0, 1) and not r.get('error') for r in rows),
        total_tokens=sum(r.get('tokens_used') or 0 for r in rows))


def summarize(rows, calls, manifest):
    expected = {(s['idx'], rep) for s in manifest['samples'] for rep in (1, 2)}
    indexed = {(r['idx'], r['repeat']): r for r in rows}
    if len(indexed) != len(rows) or set(indexed) != expected:
        raise ValueError('Incomplete/duplicate scheduled rows')
    for key, row in indexed.items():
        own = [c for c in calls if (c['idx'], c['repeat']) == key]
        if len(own) > 6 or (not own and not row.get('error')): raise ValueError('Invocation bound/receipts mismatch')
        if row['tokens_used'] != sum(c.get('total_tokens') or 0 for c in own):
            raise ValueError('Token accounting mismatch')
        if not row.get('error'):
            good = [c for c in own if not c.get('error')]
            trace = row.get('arbitrate', {}).get('reasoning_trace', [])
            if len(good) != len(trace) or any(c['answer'] != t['answer'] for c, t in zip(good, trace)):
                raise ValueError('Saved trace differs from actual API responses')
        if any(c['request']['model'] != 'deepseek-chat' or c['request']['max_tokens'] != 150 for c in own):
            raise ValueError('Unauthorized request change')
    batches = {str(rep): [indexed[s['idx'], rep] for s in manifest['samples']] for rep in (1, 2)}
    metrics = {rep: score(batch) for rep, batch in batches.items()}
    by_cwe = {rep: {c: score([r for r in batch if r['cwe'] == c])
                   for c in sorted({s['cwe'] for s in manifest['samples']})} for rep, batch in batches.items()}
    constant = score([dict(s, prediction=1) for s in manifest['samples']])
    good_calls = [c for c in calls if not c.get('error')]
    accounting = dict(invocations=len(calls), successful_invocations=len(good_calls),
        failed_invocations=len(calls)-len(good_calls),
        unknown_usage_invocations=sum(not c.get('usage_known') for c in calls),
        actual_models=dict(Counter(c.get('model', 'unavailable') for c in calls)),
        length_calls=sum(c.get('finish_reason') == 'length' for c in good_calls),
        **{k: sum(c.get(k) or 0 for c in calls) for k in ('prompt_tokens', 'completion_tokens', 'total_tokens')})
    functional = all(m['errors'] == 0 and m['uncertain'] == 0 for m in metrics.values()) and accounting['failed_invocations'] == 0 and accounting['unknown_usage_invocations'] == 0
    quality = all(m['accuracy'] > constant['accuracy'] and m['mcc'] > 0 for m in metrics.values())
    return dict(metrics=metrics, by_cwe=by_cwe, api_accounting=accounting,
        scheduled_results=len(expected), first_requests_verified=sum(bool(r.get('first_request_verified')) for r in rows),
        repeat_prediction_disagreements=sum(indexed[s['idx'], 1]['prediction'] != indexed[s['idx'], 2]['prediction'] for s in manifest['samples']),
        always_positive=constant, functional_gate=functional, quality_sanity_gate=quality,
        github_upload_eligible=functional and quality,
        scope='30 exposed SVEN development rows, two stochastic repeats; NOT independent validation.',
        limitations=['No matched fresh control; no causal gain over a previous version can be claimed.',
                     'Repeats are the same 30 rows, not 60 independent samples.',
                     '150-token length truncation and legacy semantics remain recorded, not repaired in this run.',
                     'Historical 61.15% is not inherited; no locked test sent or evaluated.',
                     'Regex/preprocessing caches are for test execution only; not cold-cache production timing.'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--authorized-real', action='store_true')
    p.add_argument('--preflight-only', action='store_true')
    p.add_argument('--preflight', type=Path)
    p.add_argument('--workers', type=int, default=4)
    args = p.parse_args()
    if args.output.exists() or not 1 <= args.workers <= 4:
        raise ValueError('Fresh output path and workers1..4 required')
    if not args.preflight_only and (not args.authorized_real or not args.preflight):
        raise ValueError('Explicit real-test authority and frozen preflight required')
    baseline = ROOT/'baselines/type_coverage_reconstructed_20261008'
    receipt = read_json(baseline/'baseline.json')
    source_root = ROOT/'development/type_coverage_reconstructed_20261008/src'
    source_hashes = {name: digest(source_root/name) for name in receipt['code_hashes']}
    if source_hashes != receipt['code_hashes']:
        raise ValueError('Development source differs from restored foundation')
    replay = read_json(baseline/'offline_audit_v3/report.json')
    if not replay['snapshot_reproduction_passed'] or not replay['offline_safety_passed']:
        raise ValueError('Missing full offline restoration proof')
    old_manifest = read_json(receipt['source_manifest'])
    dataset = Path(old_manifest['dataset'])
    if digest(dataset) != old_manifest['dataset_sha256']: raise ValueError('SVEN changed')
    data = read_json(dataset)
    indices = select_indices(data)
    samples = [dict(s) for s in old_manifest['samples'] if s['idx'] in indices]
    for s in samples:
        for key in ('source_path', 'cache_path'):
            value = Path(s[key]); s[key] = str(value if value.is_absolute() else ROOT/value)
        if digest(s['source_path']) != s['wrapped_source_sha256'] or digest(Path(s['cache_path'])/'export/export.dot') != s['cpg_sha256']:
            raise ValueError('Frozen source/graph changed')
        if s['target'] != int(data[s['idx']]['output'] == 'VULNERABLE'):
            raise ValueError('Target changed')
    first = {}
    for line in (ROOT/'output/sven_full_pipeline_eval_20261006/api_receipts.jsonl').read_text(encoding='utf8').splitlines():
        c = json.loads(line)
        if c['profile'] == 'control' and not c.get('error') and c['idx'] in indices:
            first.setdefault(c['idx'], c['request'])
    if set(first) != set(indices): raise ValueError('Missing frozen first request')
    manifest = dict(samples=samples, settings=receipt['settings'], code_root=str(source_root),
        code_hashes=source_hashes, runner_sha256=digest(__file__), dataset_sha256=digest(dataset),
        seed=20261009, planned_results=60, repeats=[1, 2], max_steps=2, output_cap=150,
        requested_model='deepseek-chat', endpoint='https://api.deepseek.com/v1',
        max_attempts_per_step=3, sdk_retries=0, timeout_seconds=90,
        first_request_sha256={str(i): hashlib.sha256(json.dumps(first[i], sort_keys=True).encode()).hexdigest() for i in indices},
        exact_sources=len({s['source_sha256'] for s in samples}), family_groups=len({s['group_id'] for s in samples}),
        protocol='Five rows per label per CWE; all failures retained, no replacement or favorable resume.',
        functional_gate='All 60 results explicit, no pipeline/API errors, all usage known, receipts and code/input hashes verified.',
        quality_sanity_gate='Accuracy greater than always-positive and MCC>0 in BOTH repeats; exploratory only.',
        scope='Previously exposed SVEN development smoke; no held-out or publication claim.')
    args.output.mkdir(parents=True)
    (args.output/'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf8')
    if args.preflight_only:
        print(f'PREFLIGHT PASS rows30 planned60 exact_sources={manifest["exact_sources"]} families={manifest["family_groups"]} api_calls0')
        return
    if read_json(args.preflight/'manifest.json') != manifest:
        raise ValueError('Frozen preflight differs from run')
    # Load credentials without copying/printing them. Explicit test settings win.
    env_path = ROOT/'.env'
    if env_path.exists():
        for line in env_path.read_text(encoding='utf8').splitlines():
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1); os.environ.setdefault(key.strip(), value.strip())
    os.environ.update(receipt['settings'])
    os.environ.update(LLM_MODEL='deepseek-chat', OPENAI_BASE_URL='https://api.deepseek.com/v1')
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(source_root))
    config = importlib.import_module('config')
    pipeline = importlib.import_module('graph.pipeline')
    loop = importlib.import_module('reasoning.reasoning_loop')
    api = importlib.import_module('reasoning.llm_api')
    importlib.import_module('learning.scorer')
    for module in (config, pipeline, loop, api):
        if not Path(module.__file__).resolve().is_relative_to(source_root): raise ValueError('Wrong code root')
    if not config.LLM_API_KEY or config.LLM_MODEL != manifest['requested_model'] or config.LLM_BASE_URL.rstrip('/') != manifest['endpoint']:
        raise ValueError('Credentials/model/endpoint do not match authorization')
    for name, expected in receipt['settings'].items():
        if hasattr(config, name):
            value = getattr(config, name)
            converted = expected == '1' if isinstance(value, bool) else int(expected) if isinstance(value, int) else expected
            if value != converted: raise ValueError('Runtime setting mismatch: '+name)
    for name, expected in source_hashes.items():
        dst = args.output/'code_snapshot'/name; dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_root/name, dst)
        if digest(dst) != expected: raise ValueError('Code snapshot mismatch')
    shutil.copy2(__file__, args.output/'runner_snapshot.py')
    from openai import OpenAI
    import httpx
    client = OpenAI(api_key=config.LLM_API_KEY, base_url=config.LLM_BASE_URL, max_retries=0,
                    timeout=90, http_client=httpx.Client(trust_env=False, timeout=90))
    lock = threading.Lock(); local = threading.local(); rows = []; calls = []
    def append(name, row):
        with lock:
            with (args.output/name).open('a', encoding='utf8') as f: f.write(json.dumps(row, ensure_ascii=False)+'\n')
    originals = {n: getattr(pipeline, n) for n in ('load_graph', 'summarize_graph', 'extract_all_candidate_paths', 'retrieve_topk')}
    def cached(name, *values, **kwargs):
        if name == 'load_graph': key = name
        else: key = (name, tuple(values[0].nodes()))
        if key not in local.prepared: local.prepared[key] = originals[name](*values, **kwargs)
        value = local.prepared[key]
        if name in ('load_graph', 'summarize_graph'): return value.copy()
        return [list(path) for path in value]
    def blocked_client(*a, **kw): raise ValueError('Only the observed authorized client may be used')
    def one(s, rep):
        base = {k: s[k] for k in ('idx', 'sample_id', 'target', 'group_id', 'cwe', 'source_sha256')}
        base['repeat'] = rep; own = []; first_checked = False
        def observed(**request):
            nonlocal first_checked
            if not first_checked:
                if request != first[s['idx']]: raise ValueError('Actual first request differs from verified snapshot')
                first_checked = True
            if request.get('model') != 'deepseek-chat' or request.get('max_tokens') != 150 or len(own) >= 6:
                raise ValueError('Request outside approved bounds')
            record = dict(base, request=request)
            try:
                response = client.chat.completions.create(**request); usage = response.usage
                record.update(answer=response.choices[0].message.content, model=response.model,
                    finish_reason=response.choices[0].finish_reason, usage_known=usage is not None,
                    **{k: getattr(usage, k, None) for k in ('prompt_tokens', 'completion_tokens', 'total_tokens')})
                return response
            except Exception as exc:
                # Redact API credential if an upstream exception happens to contain it.
                record.update(error=str(exc).replace(config.LLM_API_KEY, '[REDACTED]'), usage_known=False)
                raise RuntimeError(record['error']) from None
            finally:
                own.append(record); append('api_receipts.jsonl', record)
                with lock: calls.append(record)
        observer = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=observed)))
        try:
            if digest(s['source_path']) != s['wrapped_source_sha256'] or digest(Path(s['cache_path'])/'export/export.dot') != s['cpg_sha256']:
                raise ValueError('Prepared input changed')
            result = pipeline.run_hgl_pipeline(s['source_path'], data[s['idx']]['input'], s['sample_id'], s['cache_path'], observer, 4096, return_details=True)
            if not first_checked or (result.get('reasoning_steps') or 0) > 2: raise ValueError('Unobserved/extra step')
            result['tokens_used'] = sum(c.get('total_tokens') or 0 for c in own)
            result['first_request_verified'] = first_checked
            return dict(base, **result)
        except Exception as exc:
            return dict(base, prediction=None, error=str(exc).replace(config.LLM_API_KEY, '[REDACTED]'),
                        first_request_verified=first_checked,
                        tokens_used=sum(c.get('total_tokens') or 0 for c in own))
    def paired(s):
        local.prepared = {}; batch = []
        for rep in (1, 2):
            row = one(s, rep); append('results.jsonl', row)
            with lock: rows.append(row)
            print(f'LLM {len(rows)}/60 idx={s["idx"]} repeat={rep} error={bool(row.get("error"))}', file=sys.__stdout__, flush=True)
            batch.append(row)
        local.prepared.clear()
        return batch
    original_search = re.search
    cache_search = lru_cache(maxsize=65536)(original_search)
    def search(pattern, string, flags=0):
        if isinstance(pattern, (str, bytes, re.Pattern)) and isinstance(string, (str, bytes)):
            return cache_search(pattern, string, flags)
        return original_search(pattern, string, flags)
    with patch.object(api, 'create_client', blocked_client), \
            patch.object(pipeline, 'build_cpg', side_effect=lambda source, cache: str(Path(cache)/'export')), \
            patch.object(pipeline, 'load_graph', side_effect=lambda *a, **k: cached('load_graph', *a, **k)), \
            patch.object(pipeline, 'summarize_graph', side_effect=lambda *a, **k: cached('summarize_graph', *a, **k)), \
            patch.object(pipeline, 'extract_all_candidate_paths', side_effect=lambda *a, **k: cached('extract_all_candidate_paths', *a, **k)), \
            patch.object(pipeline, 'retrieve_topk', side_effect=lambda *a, **k: cached('retrieve_topk', *a, **k)), \
            patch.object(re, 'search', search), (args.output/'execution.log').open('w', encoding='utf8') as log, contextlib.redirect_stdout(log):
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            for future in as_completed([pool.submit(paired, s) for s in samples]): future.result()
    client.close()
    if source_hashes != {name: digest(source_root/name) for name in source_hashes} or digest(__file__) != manifest['runner_sha256']:
        raise ValueError('Frozen code changed during test')
    report = summarize(rows, calls, manifest)
    report['frozen_code_matches'] = True
    (args.output/'report.json').write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf8')
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == '__main__': main()
