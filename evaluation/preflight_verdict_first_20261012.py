"""Full254 verdict-first/foundation paired offline mocks; zero paid calls.

候选 = verdict_first_candidate_20261012(输出契约判定先行:SYSTEM prompt
Format 段两行契约 + 解析行匹配 VERDICT|HYPOTHESIS 双标签)。检索/图压缩
与 foundation 完全一致,预期差异仅出现在首个请求的 SYSTEM 段(user 消息
逐字节一致)。mock 回答按各臂自身契约格式给出。
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import contextlib
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

ROOT = Path(__file__).resolve().parents[1]
SOURCES = dict(control=ROOT/'development/type_coverage_reconstructed_20261008/src',
               candidate=ROOT/'development/verdict_first_candidate_20261012/src')


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def system_only_request_diff(a, b):
    """两请求是否仅 system 消息内容不同(其余逐字节一致)。"""
    if a == b:
        return False
    for key in ('model', 'max_tokens', 'temperature'):
        if a.get(key) != b.get(key):
            return False
    ma, mb = a.get('messages', []), b.get('messages', [])
    if len(ma) != 2 or len(mb) != 2:
        return False
    for x, y in zip(ma, mb):
        if x.get('role') != y.get('role'):
            return False
        if x.get('role') == 'system':
            continue  # SYSTEM 段差异是本候选的唯一预期变化
        if x.get('content', '') != y.get('content', ''):
            return False
    return True


def worker(output, arm, indices):
    from evaluation.test_graph_guided_foundation import verify_foundation
    base = verify_foundation()
    os.environ.update(base['settings'])
    os.environ.update(OPENAI_API_KEY='offline-not-a-key', RECORD_REASONING_TRACE='1')
    sys.path.insert(0, str(SOURCES[arm]))
    pipeline = importlib.import_module('graph.pipeline')
    api = importlib.import_module('reasoning.llm_api')
    if not Path(pipeline.__file__).resolve().is_relative_to(SOURCES[arm]):
        raise ValueError('Wrong source root')
    ref = read(ROOT/'output/sven_complete_src_eval_20261008/manifest.json')
    data = read(ref['dataset'])
    if len(data) != 254 or sha(ref['dataset']) != ref['dataset_sha256']:
        raise ValueError('Dataset drift/scope')
    samples = {s['idx']: s for s in ref['samples']}
    from evaluation.audit_type_coverage_baseline import memoized_search
    rows, external = [], [0]
    # mock 回答按各臂自身契约格式:控制臂旧四行格式,候选臂新两行格式;
    # 两臂解析到同一行为学结果(Uncertain -> step1 Stop -> 单请求)
    native = (('VERDICT: Uncertain\nACTION: {"action":"Stop","reason":"missing bounds"}')
              if arm == 'candidate' else
              ('HYPOTHESIS: Uncertain\nACTION: {"action":"Stop","reason":"missing bounds"}\nREASONING: Missing bounds'))
    def blocked(*a, **k):
        external[0] += 1
        raise RuntimeError('Offline external operation prohibited')
    output.mkdir(parents=True)
    re._MAXCACHE = 32768
    with patch.object(re, 'search', memoized_search(re.search)), \
            patch.object(socket.socket, 'connect', blocked), patch.object(socket, 'create_connection', blocked), \
            patch.object(api, 'create_client', blocked), patch('subprocess.Popen', blocked):
        for idx in indices:
            sample, code = samples[idx], data[idx]['input']
            row = dict(idx=idx, arm=arm, error=None, actual_mock_requests=0)
            requests, captured = [], {}
            try:
                dot = Path(sample['cache_path'])/'export/export.dot'
                if (sha(dot) != sample['cpg_sha256'] or sha(sample['source_path']) != sample['wrapped_source_sha256'] or
                        hashlib.sha256(code.encode()).hexdigest() != sample['source_sha256']):
                    raise ValueError('Source/graph drift')
                original_load, original_loop = pipeline.load_graph, pipeline.reasoning_loop
                def load(*a, **k):
                    graph = original_load(*a, **k)
                    captured['original'] = graph
                    return graph
                def loop(graph, paths, *a, **k):
                    captured.update(graph=graph, topk=paths, offset=k['source_line_offset'])
                    return original_loop(graph, paths, *a, **k)
                def mock(**request):
                    requests.append(request)
                    return SimpleNamespace(model='offline-mock', usage=SimpleNamespace(total_tokens=0, prompt_tokens=0, completion_tokens=0),
                        choices=[SimpleNamespace(finish_reason='stop', message=SimpleNamespace(content=native))])
                client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=mock)))
                with patch.object(pipeline, 'build_cpg', return_value=str(dot.parent)), \
                        patch.object(pipeline, 'load_graph', load), patch.object(pipeline, 'reasoning_loop', loop), \
                        contextlib.redirect_stdout(io.StringIO()):
                    result = pipeline.run_hgl_pipeline(sample['source_path'], code, sample['sample_id'],
                        sample['cache_path'], client, 4096, return_details=True)
                if len(requests) != 1 or requests[0]['max_tokens'] != 150:
                    raise ValueError('Unexpected request count/cap')
                graph = captured['graph']
                row.update(request=requests[0], topk=captured['topk'], module_audit=result['module_audit'],
                    prediction=result['prediction'], graph_sha256=digest(dict(
                        nodes=sorted([(str(n), a) for n, a in graph.nodes(data=True)]),
                        edges=sorted([(str(a), str(b), str(k), d) for a, b, k, d in graph.edges(keys=True, data=True)], key=lambda e: e[:3]))))
                # 注：候选保留 foundation 训练分支，pipeline.py 与 control
                # 逐字节一致，运行期导入 learning.scorer（不触发 torch）是
                # 两臂对称的 foundation 行为，由 selection_drift/
                # unexpected_request_diff 不变量覆盖。
            except Exception as exc:
                row['error'] = repr(exc)
            row['actual_mock_requests'] = len(requests)
            rows.append(row)
            with (output/'rows.jsonl').open('a', encoding='utf8') as handle:
                handle.write(json.dumps(row, ensure_ascii=False)+'\n')
    (output/'status.json').write_text(json.dumps(dict(errors=sum(bool(r['error']) for r in rows),
        external_attempts=external[0], rows=len(rows))), encoding='utf8')
    if external[0] or any(r['error'] for r in rows):
        raise SystemExit('Offline shard failed; all rows retained')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--arm', choices=SOURCES)
    parser.add_argument('--indices')
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('Fresh output required')
    if os.environ.get('PYTHONHASHSEED') != '0':
        raise ValueError('Start with PYTHONHASHSEED=0')
    if args.arm:
        return worker(args.output, args.arm, list(map(int, args.indices.split(','))))
    from evaluation.test_graph_guided_foundation import verify_foundation
    verify_foundation()
    bindings = {str(p.relative_to(ROOT)): sha(p) for root in SOURCES.values() for p in root.rglob('*.py')}
    bindings[str(Path(__file__).relative_to(ROOT))] = sha(__file__)
    args.output.mkdir(parents=True)
    manifest = dict(rows=254, planned_requests=508, source_tool_hashes=bindings,
        reference_commit='fd3240d6921cf26005ad8ec6cf4372157e294978', PYTHONHASHSEED='0',
        candidate='verdict-first two-line output contract (SYSTEM Format + parser dual-label)', paid_calls=0, quality_evaluation=False)
    (args.output/'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf8')
    jobs = [(arm, shard, list(range(254))[shard::6]) for arm in SOURCES for shard in range(6)]
    def launch(job):
        arm, shard, indices = job
        result = subprocess.run([sys.executable, '-B', '-m', 'evaluation.preflight_verdict_first_20261012',
            '--output', str(args.output/f'{arm}_{shard}'), '--arm', arm, '--indices', ','.join(map(str, indices))],
            cwd=ROOT, capture_output=True, text=True, encoding='utf8', errors='replace')
        (args.output/f'{arm}_{shard}.log').write_text(result.stdout+'\n'+result.stderr, encoding='utf8')
        print(f'{arm}/{shard} exit={result.returncode}', flush=True)
        return result.returncode
    with ThreadPoolExecutor(max_workers=6) as pool:
        statuses = list(pool.map(launch, jobs))
    rows = [json.loads(line) for arm, shard, _ in jobs
            for line in (args.output/f'{arm}_{shard}/rows.jsonl').read_text(encoding='utf8').splitlines()]
    indexed = {(r['idx'], r['arm']): r for r in rows}
    errors = [dict(idx=r['idx'], arm=r['arm'], error=r['error']) for r in rows if r['error']]
    selection_drift = [i for i in range(254) if not any(indexed[i, a]['error'] for a in SOURCES) and
        any(indexed[i, 'control'][key] != indexed[i, 'candidate'][key] for key in ('topk', 'graph_sha256'))]
    user_message_drift = [i for i in range(254) if not any(indexed[i, a]['error'] for a in SOURCES)
        and indexed[i, 'control']['request']['messages'][1]['content'] != indexed[i, 'candidate']['request']['messages'][1]['content']]
    unexpected_diff = [i for i in range(254) if not any(indexed[i, a]['error'] for a in SOURCES)
        and indexed[i, 'control']['request'] != indexed[i, 'candidate']['request']
        and not system_only_request_diff(indexed[i, 'control']['request'], indexed[i, 'candidate']['request'])]
    changed = [i for i in range(254) if not any(indexed[i, a]['error'] for a in SOURCES)
        and indexed[i, 'control']['request'] != indexed[i, 'candidate']['request']]
    report = dict(rows=254, retained_results=len(rows), actual_mock_requests=sum(r['actual_mock_requests'] for r in rows),
        errors=errors, selection_drift=selection_drift, user_message_drift=user_message_drift,
        unexpected_request_diff=unexpected_diff,
        system_contract_changes=len(changed), changed_indices=sorted(changed), shard_exit_codes=statuses,
        paid_calls=0, quality_evaluation=False)
    report['pass'] = (not any(statuses) and not errors and not selection_drift and not unexpected_diff
        and not user_message_drift and report['system_contract_changes'] == 254
        and len(rows) == 508 and len(indexed) == 508 and report['actual_mock_requests'] == 508
        and all(sha(ROOT/n) == h for n, h in bindings.items()))
    (args.output/'report.json').write_text(json.dumps(report, indent=2), encoding='utf8')
    verify_foundation()
    print(json.dumps(report, indent=2), flush=True)
    if not report['pass']:
        raise SystemExit('Full offline gate failed')


if __name__ == '__main__':
    main()
