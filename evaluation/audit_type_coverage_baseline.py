"""Offline-only reconstruction audit. Saved answers are NOT new LLM results."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import contextlib
from functools import lru_cache
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def verify(root, hashes):
    root = Path(root).resolve()
    for name, expected in hashes.items():
        path = (root/name).resolve()
        if not path.is_relative_to(root) or digest(path) != expected:
            raise ValueError('Code hash mismatch: ' + name)


def saved_rows(path, n):
    rows = [json.loads(line) for line in Path(path).read_text(encoding='utf8').splitlines() if line.strip()]
    result = {r['idx']: r for r in rows}
    if len(rows) != n or set(result) != set(range(n)):
        raise ValueError('Historical rows must be complete and unique')
    return result


def metrics(rows):
    tp = tn = fp = fn = uncertain = 0
    for row in rows:
        y, pred = row['target'], row.get('prediction')
        if y not in (0, 1):
            raise ValueError('Nonbinary target')
        if pred not in (0, 1):
            uncertain += 1
            fn += y == 1
            fp += y == 0
        elif y == 1:
            tp += pred == 1
            fn += pred == 0
        else:
            tn += pred == 0
            fp += pred == 1
    denom = 2*tp + fp + fn
    return dict(n=len(rows), tp=tp, tn=tn, fp=fp, fn=fn, uncertain=uncertain,
                f1=2*tp/denom if denom else 0, accuracy=(tp+tn)/len(rows) if rows else 0)


def validate_trace(row):
    trace = row.get('arbitrate', {}).get('reasoning_trace', [])
    if not trace or any(not all(k in t for k in ('answer', 'user_prompt', 'system_prompt')) for t in trace):
        raise ValueError('Missing saved model trace')
    return trace


def memoized_search(original):
    """Same regex queries have the same immutable result; not a scoring change."""
    cached = lru_cache(maxsize=65536)(original)
    def search(pattern, string, flags=0):
        if isinstance(pattern, (str, bytes, re.Pattern)) and isinstance(string, (str, bytes)):
            return cached(pattern, string, flags)
        return original(pattern, string, flags)
    search.cache_info = cached.cache_info
    return search


def summarize_replays(results):
    summaries = {}
    for label in ('type_coverage_history', 'snapshot_control_history'):
        batch = [r for r in results if r['history'] == label]
        summaries[label] = dict(n=len(batch), errors=sum(bool(r.get('error')) for r in batch),
            same_predictions=sum(r['prediction'] == r['historical_prediction'] for r in batch),
            same_first_user_prompt=sum(bool(r.get('user_prompt_equal')) for r in batch),
            same_first_system_prompt=sum(bool(r.get('system_prompt_equal')) for r in batch),
            same_step_count=sum(bool(r.get('same_step_count')) for r in batch),
            output_cap_valid=sum(bool(r.get('output_cap_valid')) for r in batch),
            saved_answer_replay_metrics_NOT_new_llm_score=metrics(batch))
    return summaries


def run_shards(args):
    """Independent processes avoid global monkeypatch/config races."""
    args.output.mkdir(parents=True)
    def run(index):
        command = [sys.executable, '-B', str(Path(__file__).resolve()), '--baseline', str(args.baseline.resolve()),
                   '--output', str(args.output.resolve()/f'shard_{index:02d}'), '--workers', '1',
                   '--shard-index', str(index), '--shard-count', str(args.workers)]
        if args.code_root: command += ['--code-root', str(args.code_root.resolve())]
        result = subprocess.run(command, check=False, capture_output=True, text=True, encoding='utf8', errors='replace')
        (args.output/f'shard_{index:02d}.log').write_text(result.stdout+'\n'+result.stderr, encoding='utf8')
        print(f'OFFLINE shard {index+1}/{args.workers} complete exit={result.returncode}', flush=True)
        return index, result.returncode
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        statuses = list(pool.map(run, range(args.workers)))
    shard_reports = [read_json(args.output/f'shard_{i:02d}/report.json') for i, _ in statuses]
    rows = [r for i, _ in statuses for r in read_json(args.output/f'shard_{i:02d}/rows.json')]
    identities = {(r['idx'], r['history']) for r in rows}
    manifest = read_json(args.baseline/'baseline.json')
    source_manifest = read_json(manifest['source_manifest'])
    count = len(source_manifest['samples'])
    expected = {(i, label) for i in range(count) for label in ('type_coverage_history', 'snapshot_control_history')}
    if len(identities) != len(rows) or identities != expected:
        raise ValueError('Incomplete/duplicate shard results; do not drop failed rows')
    report = dict(shard_reports[0])
    report.pop('shard', None)
    report['audit_only_regex_search_cache_scope'] = 'First shard only; each shard report has its own cache statistics'
    report.update(workers=args.workers, summaries=summarize_replays(rows),
                  snapshot_reproduction_passed=all(r['snapshot_reproduction_passed'] for r in shard_reports),
                  offline_safety_passed=all(r['offline_safety_passed'] for r in shard_reports),
                  shard_exit_codes={str(i): value for i, value in statuses})
    for key in ('actual_api_calls', 'blocked_network_attempts', 'fake_model_responses'):
        report[key] = sum(r[key] for r in shard_reports)
    verify(Path(manifest['frozen_source']), manifest['code_hashes'])
    verify(Path(__file__).resolve().parents[1], manifest['preserved_repaired_code_hashes'])
    (args.output/'report.json').write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf8')
    (args.output/'rows.json').write_text(json.dumps(sorted(rows, key=lambda r: (r['idx'], r['history'])), indent=2), encoding='utf8')
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if any(value != 0 for _, value in statuses): raise SystemExit('Offline replay audit failed; inspect preserved shards')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--code-root', type=Path, help='Default frozen source; candidate copies may be supplied')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--workers', type=int, default=6)
    parser.add_argument('--shard-index', type=int, default=0)
    parser.add_argument('--shard-count', type=int, default=1)
    args = parser.parse_args()
    if not 1 <= args.workers <= 8 or not 0 <= args.shard_index < args.shard_count:
        parser.error('workers must be 1..8; invalid shard identity')
    if args.output.exists():
        raise ValueError('Use a new output directory; never overwrite a frozen audit')
    if args.workers > 1:
        run_shards(args)
        return
    # Performance-only interpreter cache setting: patterns, flags and source code
    # are unchanged. Legacy path ranking otherwise thrashes Python's 512-entry cache.
    re._MAXCACHE = 32768
    if hasattr(re, '_MAXCACHE2'):
        re._MAXCACHE2 = 16384
    print('OFFLINE verifying provenance; no real model client', flush=True)
    project = Path(__file__).resolve().parents[1]
    baseline = args.baseline.resolve()
    receipt = read_json(baseline/'baseline.json')
    code_root = args.code_root.resolve() if args.code_root else Path(receipt['frozen_source'])
    if args.output.exists():
        raise ValueError('Use a new output directory; never overwrite a frozen audit')
    verify(Path(receipt['frozen_source']), receipt['code_hashes'])
    verify(baseline/'preserved_repaired_src', receipt['preserved_repaired_code_hashes'])
    verify(project, receipt['preserved_repaired_code_hashes'])
    for key in ('source_manifest', 'preserved_repaired_manifest'):
        if digest(receipt[key]) != receipt[key+'_sha256']:
            raise ValueError('Provenance manifest changed')
    reference = receipt['historical_reference']
    if digest(reference['report']) != reference['sha256']:
        raise ValueError('Historical report changed')
    historical_manifest = read_json(receipt['source_manifest'])
    dataset = Path(historical_manifest['dataset'])
    if digest(dataset) != historical_manifest['dataset_sha256']:
        raise ValueError('Historical data changed')
    data = read_json(dataset)
    n = len(data)
    type_rows = saved_rows(project/'sven_eval/output_type_coverage_full/sven_results.jsonl', n)
    old_rows_all = [json.loads(s) for s in (project/'output/sven_full_pipeline_eval_20261006/results.jsonl').read_text(encoding='utf8').splitlines() if s.strip()]
    old_control = {r['idx']: r for r in old_rows_all if r['profile'] == 'control'}
    if len(old_rows_all) != 2*n or len(old_control) != n:
        raise ValueError('Incomplete 10/06 saved run')
    os.environ.update(receipt['settings'])
    os.environ.update(OPENAI_API_KEY='offline-not-a-key', OPENAI_BASE_URL='https://api.deepseek.com/v1',
                      LLM_MODEL='deepseek-chat', PYTHONDONTWRITEBYTECODE='1')
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(code_root))
    print('OFFLINE importing isolated prediction modules', flush=True)
    config = importlib.import_module('config')
    pipeline = importlib.import_module('graph.pipeline')
    loop = importlib.import_module('reasoning.reasoning_loop')
    api = importlib.import_module('reasoning.llm_api')
    for module in (config, pipeline, loop, api):
        if not Path(module.__file__).resolve().is_relative_to(code_root):
            raise ValueError('Imported production checkout instead of isolated source')
    effective = {}
    for name, expected in receipt['settings'].items():
        if hasattr(config, name):
            actual = getattr(config, name)
            check = (expected == '1') if isinstance(actual, bool) else int(expected) if isinstance(actual, int) else expected
            if actual != check:
                raise ValueError('Effective setting mismatch: ' + name)
            effective[name] = actual
    inputs = {}
    for sample in historical_manifest['samples']:
        idx = sample['idx']
        if hashlib.sha256(data[idx]['input'].encode()).hexdigest() != sample['source_sha256']:
            raise ValueError('Source identity mismatch')
        source, cache = Path(sample['source_path']), Path(sample['cache_path'])
        if not source.is_absolute(): source = project/source
        if not cache.is_absolute(): cache = project/cache
        if digest(source) != sample['wrapped_source_sha256'] or digest(cache/'export/export.dot') != sample['cpg_sha256']:
            raise ValueError('Historical source/CPG changed')
        inputs[idx] = (source, cache, sample['sample_id'])
    counters = dict(blocked_network_attempts=0, fake_model_responses=0)
    print(f'OFFLINE inputs verified: {n} sources; starting saved-answer replay', flush=True)
    def blocked(*unused_args, **unused_kwargs):
        counters['blocked_network_attempts'] += 1
        raise RuntimeError('Network/client/process access forbidden in this offline audit')
    results = []
    # The child process has no real client; sockets and Joern subprocesses are blocked too.
    cached_search = memoized_search(re.search)
    with patch.object(re, 'search', cached_search), patch.object(api, 'create_client', blocked), patch.object(socket.socket, 'connect', blocked), \
            patch.object(socket, 'create_connection', blocked), patch('subprocess.Popen', blocked), \
            patch.object(loop, 'query_llm_with_retry', api.query_llm):
        for idx in range(n):
            if idx % args.shard_count != args.shard_index:
                continue
            if idx % 5 == 0:
                print(f'OFFLINE begin source {idx}/{n}', flush=True)
            source, cache, sid = inputs[idx]
            for label, saved in (('type_coverage_history', type_rows[idx]), ('snapshot_control_history', old_control[idx])):
                trace = validate_trace(saved)
                captured = []
                def fake_create(**kwargs):
                    position = len(captured)
                    captured.append(kwargs)
                    if position >= len(trace):
                        raise ValueError('Reconstruction requested an extra model step')
                    counters['fake_model_responses'] += 1
                    entry = trace[position]
                    usage = SimpleNamespace(total_tokens=0, prompt_tokens=0, completion_tokens=0)
                    return SimpleNamespace(model='offline-saved-answer', usage=usage,
                        choices=[SimpleNamespace(finish_reason=entry.get('finish_reason'),
                                                 message=SimpleNamespace(content=entry['answer']))])
                client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=fake_create)))
                try:
                    with patch.object(pipeline, 'build_cpg', return_value=str(cache/'export')), contextlib.redirect_stdout(io.StringIO()):
                        value = pipeline.run_hgl_pipeline(str(source), data[idx]['input'], sid, str(cache), client,
                                                         4096, ablation='', return_details=True)
                    first = captured[0]['messages']
                    system = next(m['content'] for m in first if m['role'] == 'system')
                    user = next(m['content'] for m in first if m['role'] == 'user')
                    row = dict(idx=idx, history=label, target=int(data[idx]['output'] == 'VULNERABLE'),
                        prediction=value['prediction'], historical_prediction=saved['prediction'],
                        system_prompt_equal=system == trace[0]['system_prompt'],
                        user_prompt_equal=user == trace[0]['user_prompt'],
                        same_step_count=len(captured) == len(trace),
                        output_cap_valid=all(c['max_tokens'] == 150 for c in captured),
                        actual_new_api_tokens=0,
                        first_request_sha256=hashlib.sha256(json.dumps(captured[0], sort_keys=True).encode()).hexdigest())
                except Exception as exc:
                    row = dict(idx=idx, history=label, target=int(data[idx]['output'] == 'VULNERABLE'),
                               prediction=None, historical_prediction=saved['prediction'], error=str(exc))
                results.append(row)
            if (idx+1) % 25 == 0 or idx+1 == n:
                print(f'OFFLINE {idx+1}/{n} sources api_calls=0', flush=True)
    selected_n = len(range(args.shard_index, n, args.shard_count))
    report = dict(baseline=receipt['name'], code_root=str(code_root), effective_settings=effective,
                  shard=dict(index=args.shard_index, count=args.shard_count),
                  audit_only_regex_compile_cache_entries=re._MAXCACHE,
                  audit_only_regex_search_cache=cached_search.cache_info()._asdict(),
                  reconstruction_is_exact_historical_version=False,
                  new_llm_score=None, actual_api_calls=0, **counters, summaries=summarize_replays(results))
    verify(project, receipt['preserved_repaired_code_hashes'])
    verify(Path(receipt['frozen_source']), receipt['code_hashes'])
    # Extra/missing steps or errors invalidate replay; old/type prompt mismatches are diagnostic, not erased.
    old = report['summaries']['snapshot_control_history']
    report['snapshot_reproduction_passed'] = all(old[k] == selected_n for k in (
        'same_predictions', 'same_first_user_prompt', 'same_first_system_prompt', 'same_step_count', 'output_cap_valid')) and old['errors'] == 0
    report['offline_safety_passed'] = counters['blocked_network_attempts'] == 0
    report['current_repaired_checkout_preserved'] = True
    report['limitations'] = ['61.15% belongs to archived responses, not this reconstructed version.',
        'Audit-only identical regex query memoization preserves patterns/results; not production timing evidence.',
        'The 10/06 snapshot is not proven bit-identical to the older type-coverage implementation.',
        'Saved-answer replay cannot estimate fresh provider variability or new detection quality.',
        'SVEN is development-exposed; locked Devign test was not read or executed.',
        'Legacy prediction semantics are isolated here; current repairs are not overwritten.']
    args.output.mkdir(parents=True)
    (args.output/'report.json').write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf8')
    (args.output/'rows.json').write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding='utf8')
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if not report['snapshot_reproduction_passed'] or not report['offline_safety_passed']:
        raise SystemExit('Offline snapshot reproduction failed; inspect report, no new API score available')


if __name__ == '__main__':
    main()
