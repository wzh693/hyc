"""Full254 asymmetric-bounds/foundation paired offline mocks; zero paid calls.

候选 = asymmetric_bounds_candidate_20261012(非对称证据负担契约:判定先行
两行 + 良性/不确定须 BOUNDS 逐字守卫引用,引用无效进受控次步完整源码挑战)。
检索/图压缩与 foundation 完全一致,预期差异仅出现在首个请求的 SYSTEM 段
(user 消息逐字节一致)。mock 回答按各臂自身契约格式给出;候选臂按 idx%3
场景覆盖三条终态路径(引用即停/次步仍良/次步改判类型),引用行由候选自身
验证器自检,保证场景真实生效。
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
               candidate=ROOT/'development/asymmetric_bounds_candidate_20261012/src')


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


def scenario_answers(arm, idx, code, validator=None):
    """各臂 mock 回答与预期请求数(候选臂 idx%3 覆盖三条终态路径)。

    候选场景(引用行经候选自身 _benign_bounds_valid 自检,检不出可用守卫行
    则降级为无引用场景,保证 mock 与运行时解析器判定一致):
      idx%3==0 且有守卫行 -> 良性+有效引用,1 请求(benign_bounds_proven)
      idx%3==2            -> 良性无引用 -> 次步改判类型,2 请求,预测 1
      其余                -> 良性无引用 -> 次步仍良性,2 请求(challenge_final)
    """
    if arm == 'control':
        return ['HYPOTHESIS: Uncertain\nACTION: {"action":"Stop","reason":"missing bounds"}'
                '\nREASONING: Missing bounds'], 1
    benign = 'VERDICT: no vulnerability detected\nACTION: {"action":"Stop","reason":"checked"}'
    quote = find_guard_quote(code, validator)
    if idx % 3 == 0 and quote:
        return [benign + '\nBOUNDS: ' + quote], 1
    if idx % 3 == 2:
        return [benign, 'VERDICT: integer overflow\nACTION: {"action":"Stop","reason":"recheck"}'], 2
    return [benign, benign], 2


def find_guard_quote(code, validator=None):
    """取第一条通过候选验证器自检的守卫行(逐字引用,可验证)。"""
    for line in (code or '').splitlines():
        stripped = line.strip()
        if len(stripped) < 8:
            continue
        probe = 'BOUNDS: ' + stripped
        if validator is None or validator(probe, code):
            if re.search(r'[<>]=?|[!=]=|&&|\|\||!\s*\(?\s*[A-Za-z_]|'
                         r'\b(?:if|while|for|sizeof|strlen|NULL)\b', stripped, re.I):
                return stripped
    return ''


def worker(output, arm, indices):
    from evaluation.test_graph_guided_foundation import verify_foundation
    base = verify_foundation()
    os.environ.update(base['settings'])
    os.environ.update(OPENAI_API_KEY='offline-not-a-key', RECORD_REASONING_TRACE='1')
    sys.path.insert(0, str(SOURCES[arm]))
    pipeline = importlib.import_module('graph.pipeline')
    api = importlib.import_module('reasoning.llm_api')
    validator = None
    if arm == 'candidate':
        validator = importlib.import_module('reasoning.reasoning_loop')._benign_bounds_valid
    if not Path(pipeline.__file__).resolve().is_relative_to(SOURCES[arm]):
        raise ValueError('Wrong source root')
    ref = read(ROOT/'output/sven_complete_src_eval_20261008/manifest.json')
    data = read(ref['dataset'])
    if len(data) != 254 or sha(ref['dataset']) != ref['dataset_sha256']:
        raise ValueError('Dataset drift/scope')
    samples = {s['idx']: s for s in ref['samples']}
    from evaluation.audit_type_coverage_baseline import memoized_search
    rows, external = [], [0]

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
            answers, expected = scenario_answers(arm, idx, code, validator)
            row = dict(idx=idx, arm=arm, error=None, actual_mock_requests=0,
                       scenario=idx % 3, expected_requests=expected)
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
                    if len(requests) > len(answers):
                        raise ValueError('Unexpected extra request beyond scenario')
                    return SimpleNamespace(model='offline-mock', usage=SimpleNamespace(total_tokens=0, prompt_tokens=0, completion_tokens=0),
                        choices=[SimpleNamespace(finish_reason='stop', message=SimpleNamespace(content=answers[len(requests)-1]))])
                client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=mock)))
                with patch.object(pipeline, 'build_cpg', return_value=str(dot.parent)), \
                        patch.object(pipeline, 'load_graph', load), patch.object(pipeline, 'reasoning_loop', loop), \
                        contextlib.redirect_stdout(io.StringIO()):
                    result = pipeline.run_hgl_pipeline(sample['source_path'], code, sample['sample_id'],
                        sample['cache_path'], client, 4096, return_details=True)
                if len(requests) != expected or any(r['max_tokens'] != 150 for r in requests):
                    raise ValueError('Unexpected request count/cap')
                if len(requests) >= 2 and 'FULL SRC:' not in requests[1]['messages'][1]['content']:
                    raise ValueError('Challenge step missing full source')
                if arm == 'candidate' and idx % 3 == 2 and result['prediction'] != 1:
                    raise ValueError('Challenge type-recovery scenario mispredicted')
                graph = captured['graph']
                row.update(request=requests[0], topk=captured['topk'], module_audit=result['module_audit'],
                    prediction=result['prediction'], graph_sha256=digest(dict(
                        nodes=sorted([(str(n), a) for n, a in graph.nodes(data=True)]),
                        edges=sorted([(str(a), str(b), str(k), d) for a, b, k, d in graph.edges(keys=True, data=True)], key=lambda e: e[:3]))))
            except Exception as exc:
                row['error'] = repr(exc)
            row['actual_mock_requests'] = len(requests)
            rows.append(row)
            with (output/'rows.jsonl').open('a', encoding='utf8') as handle:
                handle.write(json.dumps(row, ensure_ascii=False)+'\n')
    (output/'status.json').write_text(json.dumps(dict(errors=sum(bool(r['error']) for r in rows),
        external_attempts=external[0], rows=len(rows),
        requests=sum(r['actual_mock_requests'] for r in rows))), encoding='utf8')
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
        candidate='asymmetric evidence-burden contract (verdict-first + BOUNDS guard citation + controlled full-source challenge step)',
        paid_calls=0, quality_evaluation=False)
    (args.output/'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf8')
    jobs = [(arm, shard, list(range(254))[shard::6]) for arm in SOURCES for shard in range(6)]

    def launch(job):
        arm, shard, indices = job
        result = subprocess.run([sys.executable, '-B', '-m', 'evaluation.preflight_asymmetric_bounds_20261012',
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
        and indexed[i, 'control']['request']['messages'][1]['content'] != indexed[i, 'candidate']['request']['messages'][1]['content']
        ]
    unexpected_diff = [i for i in range(254) if not any(indexed[i, a]['error'] for a in SOURCES)
        and indexed[i, 'control']['request'] != indexed[i, 'candidate']['request']
        and not system_only_request_diff(indexed[i, 'control']['request'], indexed[i, 'candidate']['request'])]
    changed = [i for i in range(254) if not any(indexed[i, a]['error'] for a in SOURCES)
        and indexed[i, 'control']['request'] != indexed[i, 'candidate']['request']]
    candidate_rows = [r for r in rows if r['arm'] == 'candidate' and not r['error']]
    challenge_rows = sum(r['expected_requests'] == 2 for r in candidate_rows)
    request_mismatch = [dict(idx=r['idx'], arm=r['arm'], expected=r['expected_requests'],
        actual=r['actual_mock_requests']) for r in rows if not r['error'] and r['actual_mock_requests'] != r['expected_requests']]
    expected_total = sum(r['expected_requests'] for r in rows if not r['error'])
    report = dict(rows=254, retained_results=len(rows), actual_mock_requests=sum(r['actual_mock_requests'] for r in rows),
        expected_mock_requests=expected_total, request_mismatch=request_mismatch,
        challenge_rows=challenge_rows, bounds_proven_rows=sum(r['expected_requests'] == 1 for r in candidate_rows),
        errors=errors, selection_drift=selection_drift, user_message_drift=user_message_drift,
        unexpected_request_diff=unexpected_diff,
        system_contract_changes=len(changed), changed_indices=sorted(changed), shard_exit_codes=statuses,
        paid_calls=0, quality_evaluation=False)
    report['pass'] = (not any(statuses) and not errors and not selection_drift and not unexpected_diff
        and not user_message_drift and not request_mismatch
        and report['system_contract_changes'] == 254
        and len(rows) == 508 and len(indexed) == 508
        and report['actual_mock_requests'] == expected_total
        and all(sha(ROOT/n) == h for n, h in bindings.items()))
    (args.output/'report.json').write_text(json.dumps(report, indent=2), encoding='utf8')
    verify_foundation()
    print(json.dumps(report, indent=2), flush=True)
    if not report['pass']:
        raise SystemExit('Full offline gate failed')


if __name__ == '__main__':
    main()
