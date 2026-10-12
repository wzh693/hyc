"""One explicitly authorized full254 paired LLM batch; frozen retrieval cache.

候选 = verdict_first_candidate_20261012(输出契约判定先行:SYSTEM Format 两行
契约 + 解析器 VERDICT|HYPOTHESIS 双标签 + 前步摘要重写);对照 = 冻结
foundation。双臂×双重复×254=1016。差异仅 system 消息,user 消息逐字节一致。
"""
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
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from evaluation.preflight_graph_display import graph_hash, digest as value_hash
from evaluation.evaluate_reconstructed_llm import digest, read_json, score
from evaluation.evaluate_sven_complete_src import checked_rows, extended_score, request_hash
from evaluation.audit_type_coverage_baseline import memoized_search

ROOT = Path(__file__).resolve().parents[1]
SHADOW = ROOT/'output/verdict_first_preflight_20261012'
PROTOCOL = ROOT/'evaluation/VERDICT_FIRST_LLM_PROTOCOL_20261012.md'
PROFILES = ['control', 'verdict']


def prepare():
    if os.environ.get('PYTHONHASHSEED') != '0': raise ValueError('Startup hash seed0 required')
    from evaluation.test_graph_guided_foundation import verify_foundation
    foundation = verify_foundation(); frozen = read_json(SHADOW/'manifest.json')
    if not read_json(SHADOW/'report.json')['pass']: raise ValueError('Full254 verdict-first preflight required')
    for name, expected in frozen['source_tool_hashes'].items():
        if digest(ROOT/name) != expected: raise ValueError('Frozen dependency drift: '+name)
    ref = read_json(ROOT/'output/sven_complete_src_eval_20261008/manifest.json')
    data = read_json(ref['dataset']); samples = ref['samples']
    if len(data) != 254 or len(samples) != 254 or {s['idx'] for s in samples} != set(range(254)) or digest(ref['dataset']) != ref['dataset_sha256']:
        raise ValueError('Dataset identity/scope drift')
    stage_rows = [json.loads(line) for folder in SHADOW.iterdir() if folder.is_dir()
                for line in (folder/'rows.jsonl').read_text(encoding='utf8').splitlines()]
    stages = {(r['idx'], 'verdict' if r['arm'] == 'candidate' else 'control'): r for r in stage_rows}
    if len(stage_rows) != 508 or len(stages) != 508 or set(stages) != {(i, p) for i in range(254) for p in PROFILES}:
        raise ValueError('Not a complete paired retrieval cache')
    if any(s['target'] != int(data[s['idx']]['output'] == 'VULNERABLE') or s['cwe'] != data[s['idx']]['cwe'] for s in samples):
        raise ValueError('Labels changed')
    requests = {key: r['request'] for key, r in stages.items()}
    roots = dict(control=ROOT/'development/type_coverage_reconstructed_20261008/src',
                verdict=ROOT/'development/verdict_first_candidate_20261012/src')
    hashes = {p: {f.relative_to(root).as_posix(): digest(f) for f in root.rglob('*.py')} for p, root in roots.items()}
    tools = ['evaluation/run_verdict_first_llm_20261012.py',
             str(PROTOCOL.relative_to(ROOT)),
             'evaluation/preflight_verdict_first_20261012.py',
             'evaluation/test_verdict_first_20261012.py',
             'evaluation/preflight_graph_display.py',
             'evaluation/evaluate_sven_complete_src.py',
             'evaluation/evaluate_reconstructed_llm.py',
             'evaluation/audit_type_coverage_baseline.py',
             'evaluation/test_graph_guided_foundation.py']
    order = list(range(254)); random.Random(20261012).shuffle(order)
    manifest = dict(samples=samples, profiles=PROFILES, repeats=[1, 2], planned_results=1016,
        source_roots={p: str(root) for p, root in roots.items()}, source_hashes=hashes,
        tooling_hashes={n: digest(ROOT/n) for n in tools}, settings=foundation['settings'],
        dataset=ref['dataset'], dataset_sha256=ref['dataset_sha256'],
        stage_artifact_sha256={str(f.relative_to(SHADOW)): digest(f) for f in SHADOW.rglob('*.json*')}, stage_root=str(SHADOW),
        first_request_sha256={f'{p}/{i}': request_hash(r) for (i, p), r in requests.items()},
        sample_order=order, pair_order_rule='Isolated arm processes,2threads each; per sample repeat1 then2; arm completion order not guaranteed',
        candidate_input_changes=sum(requests[i, 'control'] != requests[i, 'verdict'] for i in range(254)),
        endpoint='https://api.deepseek.com/v1', requested_model='deepseek-chat',
        output_cap=150, max_steps=2, max_attempts_per_step=3, sdk_retries=0, timeout_seconds=90,
        workers=4, graph_budget=4096, bootstrap_seed=20261012, bootstrap_draws=2000,
        exact_sources=len({s['source_sha256'] for s in samples}), family_groups=len({s['group_id'] for s in samples}),
        automatic_promotion=False, scope='All254 local exposed SVEN rows; not independent final or all upstream SVEN.',
        retrieval_cache='Frozen TopK validated against exact graph content and membership in regenerated candidates.',
        candidate='verdict-first two-line output contract (SYSTEM Format rewrite + parser dual-label + prior summary rewrite)',
        PYTHONHASHSEED='0', authorization='Human approved verdict-first full254x2x2 single batch 2026-10-12 (this conversation)')
    return manifest, requests, stages, data


def pair_order(idx, repeat): return PROFILES if (idx+repeat) % 2 == 0 else list(reversed(PROFILES))


def usage_record(usage):
    fields = {k: getattr(usage, k, None) for k in ('prompt_tokens', 'completion_tokens', 'total_tokens')}
    known = all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in fields.values())
    known = known and fields['prompt_tokens']+fields['completion_tokens'] == fields['total_tokens']
    return dict(usage_known=known, **fields)


def checked_selection(graph, candidates, stage):
    if graph_hash(graph) != stage['graph_sha256']:
        raise ValueError('Frozen retrieval cache does not match actual graph/candidates')
    if any(p not in candidates for p in stage['topk']):
        raise ValueError('Cached path not from candidate set')
    return [list(p) for p in stage['topk']]


def summarize(rows, calls, manifest, draws=None):
    indexed, own = checked_rows(rows, calls, manifest)
    samples = manifest['samples']; batches = {f'{p}/r{rep}': [indexed[s['idx'], p, rep] for s in samples] for p in PROFILES for rep in (1, 2)}
    metrics = {k: extended_score(v) for k, v in batches.items()}
    by_cwe = {k: {c: extended_score([r for r in batch if r['cwe'] == c]) for c in sorted({s['cwe'] for s in samples})} for k, batch in batches.items()}
    accounting = {}
    for p in PROFILES:
        for rep in (1, 2):
            observed = [c for c in calls if c['profile'] == p and c['repeat'] == rep]
            accounting[f'{p}/r{rep}'] = dict(invocations=len(observed), successful_invocations=sum(not c.get('error') for c in observed),
                failed_invocations=sum(bool(c.get('error')) for c in observed), unknown_usage=sum(not c.get('usage_known') for c in observed),
                actual_models=dict(Counter(c.get('model', 'unavailable') for c in observed)), length_calls=sum(c.get('finish_reason') == 'length' for c in observed),
                **{k: sum(c.get(k) or 0 for c in observed) for k in ('prompt_tokens', 'completion_tokens', 'total_tokens')})
    constant = {name: extended_score([dict(s, prediction=p) for s in samples]) for name, p in [('always_positive', 1), ('always_negative', 0)]}
    intervals = {}; draws = manifest['bootstrap_draws'] if draws is None else draws
    groups = defaultdict(list)
    for s in samples: groups[s['group_id']].append(s['idx'])
    rng = random.Random(manifest['bootstrap_seed']); values = {k: [] for k in ('f1', 'accuracy', 'fp')}
    for _ in range(draws):
        ids = [i for group in rng.choices(list(groups.values()), k=len(groups)) for i in group]
        a, b = [score([indexed[i, p, 1] for i in ids]) for p in PROFILES]
        for k in values: values[k].append(b[k]-a[k])
    a = metrics['control/r1']; b = metrics['verdict/r1']
    intervals['global'] = {k: dict(delta=b[k]-a[k], ci95=[sorted(v)[int(draws*.025)], sorted(v)[min(draws-1, int(draws*.975))]]) for k, v in values.items()}
    gates = dict(
        global_nonnegative_both=all(metrics[f'verdict/r{r}'][k] >= metrics[f'control/r{r}'][k] for r in (1, 2) for k in ('f1', 'accuracy')),
        fp_not_worse_both=all(metrics[f'verdict/r{r}']['fp'] <= metrics[f'control/r{r}']['fp'] for r in (1, 2)),
        global_intervals_positive=intervals['global']['f1']['ci95'][0] > 0 and intervals['global']['accuracy']['ci95'][0] > 0,
        beats_constant_both=all(metrics[f'verdict/r{r}'][k] > constant['always_positive'][k] and metrics[f'verdict/r{r}']['mcc'] > 0 for r in (1, 2) for k in ('f1', 'accuracy')))
    models = {c.get('model') for c in calls if not c.get('error')}
    functional = all(not m['errors'] and not m['uncertain'] for m in metrics.values()) and all(not a['failed_invocations'] and not a['unknown_usage'] for a in accounting.values()) and len(models) == 1 and None not in models
    effective = {}
    for label, changed in [('changed_first_input', True), ('unchanged_first_input', False)]:
        ids = [s['idx'] for s in samples if (manifest['first_request_sha256'][f'control/{s["idx"]}'] != manifest['first_request_sha256'][f'verdict/{s["idx"]}']) == changed]
        effective[label] = dict(rows=len(ids), repeats={})
        for rep in (1, 2):
            a = [indexed[i, 'control', rep] for i in ids]; b = [indexed[i, 'verdict', rep] for i in ids]
            effective[label]['repeats'][str(rep)] = dict(prediction_differences=sum(x['prediction'] != y['prediction'] for x, y in zip(a, b)),
                gained_correct=sum(x['prediction'] != x['target'] and y['prediction'] == y['target'] for x, y in zip(a, b)),
                lost_correct=sum(x['prediction'] == x['target'] and y['prediction'] != y['target'] for x, y in zip(a, b)))
    return dict(scheduled_results=len(rows), metrics=metrics, by_cwe=by_cwe, api_accounting=accounting,
        actual_invocations=len(calls), total_reported_tokens=sum(c.get('total_tokens') or 0 for c in calls),
        constant_baselines=constant, repeat_prediction_disagreements={p: sum(indexed[s['idx'], p, 1]['prediction'] != indexed[s['idx'], p, 2]['prediction'] for s in samples) for p in PROFILES},
        global_intervals=intervals, input_change_decomposition=effective, functional_gate=functional, gates=gates,
        exploratory_support=functional and all(gates.values()), auto_promoted=False, scope=manifest['scope'],
        limitations=['Development-exposed, correlated/conflicting rows retained; repeats are not new independent samples.',
                     'r1 family intervals are descriptive, not independent causal/generalization proof.',
                     'Frozen deterministic retrieval cache, not a retrieval speed benchmark.',
                     'Verdict-first contract changes the SYSTEM message only; user messages are byte-identical and the 150-output cap is retained; the verdict line is designed to survive truncation.',
                     'No automatic activation, reruns, locked Devign, GitHub upload or paper-readiness claim.'])


class Runtime:
    def __init__(self, manifest, stages, offline, arm='control'):
        if not offline:
            env = ROOT/'.env'
            if env.exists():
                for line in env.read_text(encoding='utf8').splitlines():
                    if line.strip() and not line.lstrip().startswith('#') and '=' in line:
                        k, v = line.split('=', 1); os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
        os.environ.update(manifest['settings']); os.environ.update(LLM_MODEL='deepseek-chat', OPENAI_BASE_URL=manifest['endpoint'])
        if offline: os.environ['OPENAI_API_KEY'] = 'offline-not-a-key'
        sys.dont_write_bytecode = True
        self.source = Path(manifest['source_roots'][arm])
        sys.path.insert(0, str(self.source))
        self.config = importlib.import_module('config'); self.pipeline = importlib.import_module('graph.pipeline'); self.api = importlib.import_module('reasoning.llm_api')
        for module in (self.config, self.pipeline, self.api):
            if not Path(module.__file__).resolve().is_relative_to(self.source): raise ValueError('Wrong isolated source imported')
        for name, value in manifest['settings'].items():
            if hasattr(self.config, name):
                actual = getattr(self.config, name); expected = value == '1' if isinstance(actual, bool) else int(value) if isinstance(actual, int) else value
                if actual != expected: raise ValueError('Runtime setting mismatch: '+name)
        if not offline and (not self.config.LLM_API_KEY or self.config.LLM_API_KEY == 'offline-not-a-key' or self.config.LLM_MODEL != 'deepseek-chat' or self.config.LLM_BASE_URL.rstrip('/') != manifest['endpoint']):
            raise ValueError('Credential/endpoint/model mismatch')
        self.local = threading.local(); self.stages = stages; self.blocked_attempts = 0
        self.originals = {n: getattr(self.pipeline, n) for n in ('load_graph', 'summarize_graph', 'extract_all_candidate_paths')}

    def blocked(self, *a, **k): self.blocked_attempts += 1; raise RuntimeError('Unobserved client/process forbidden')

    def cache(self, name, *a, **k):
        key = (name, tuple(a[0].nodes()) if name != 'load_graph' else None)
        if key not in self.local.prepared: self.local.prepared[key] = self.originals[name](*a, **k)
        value = self.local.prepared[key]
        return value.copy() if name in ('load_graph', 'summarize_graph') else [list(p) for p in value]

    def retrieve(self, graph, candidates, *a, **k):
        if a or k.get('learned_scores') is not None or k.get('vuln_type', 'Generic') != 'Generic': raise ValueError('Unsupported retrieval-cache arguments')
        return checked_selection(graph, candidates, self.stages[self.local.idx, self.local.profile])

    def patches(self, offline):
        stack = contextlib.ExitStack()
        stack.enter_context(patch.object(self.api, 'create_client', self.blocked)); stack.enter_context(patch('subprocess.Popen', self.blocked))
        stack.enter_context(patch.object(self.pipeline, 'build_cpg', side_effect=lambda source, cache: str(Path(cache)/'export')))
        for name in self.originals:
            stack.enter_context(patch.object(self.pipeline, name, side_effect=lambda *a, _name=name, **k: self.cache(_name, *a, **k)))
        stack.enter_context(patch.object(self.pipeline, 'retrieve_topk', side_effect=self.retrieve))
        stack.enter_context(patch.object(re, 'search', memoized_search(re.search)))
        if offline:
            stack.enter_context(patch.object(socket.socket, 'connect', self.blocked)); stack.enter_context(patch.object(socket, 'create_connection', self.blocked))
        re._MAXCACHE = 32768
        if hasattr(re, '_MAXCACHE2'): re._MAXCACHE2 = 16384
        return stack


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path); parser.add_argument('--preflight-only', action='store_true')
    parser.add_argument('--preflight', type=Path); parser.add_argument('--authorized-real-1016', action='store_true')
    parser.add_argument('--internal-arm', choices=PROFILES)
    args = parser.parse_args()
    if args.output.exists(): raise ValueError('Fresh output required; no resume/rerun')
    if not args.preflight_only and (not args.preflight or not args.authorized_real_1016): raise ValueError('Frozen runtime preflight and this batch authorization required')
    manifest, requests, stages, data = prepare()
    if not args.internal_arm:
        return orchestrate(args, manifest)
    if not args.preflight_only:
        frozen = read_json(args.preflight/'manifest.json')
        if frozen != manifest: raise ValueError('Runtime freeze changed')
        proof = read_json(args.preflight/'runtime_verification.json')
        if not proof['passed'] or proof['rows'] != 1016 or any(digest(args.preflight/n) != h for n, h in proof['hashes'].items()):
            raise ValueError('Runtime preflight not complete/intact')
    runtime = Runtime(manifest, stages, args.preflight_only, args.internal_arm or 'control')
    args.output.mkdir(parents=True)
    def save(name, value): (args.output/name).write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding='utf-8')
    save('manifest.json', manifest)
    lock = threading.Lock(); rows = []; calls = []; mock_records = []
    def append(name, value):
        with lock:
            with (args.output/name).open('a', encoding='utf8') as f: f.write(json.dumps(value, ensure_ascii=False)+'\n')
    if args.preflight_only: client = None
    else:
        for group, hashes, source in [('code_snapshot', manifest['source_hashes']['verdict'], Path(manifest['source_roots']['verdict'])),
                                   ('control_snapshot', manifest['source_hashes']['control'], Path(manifest['source_roots']['control'])),
                                   ('tooling_snapshot', manifest['tooling_hashes'], ROOT)]:
            for name, expected in hashes.items():
                dest = args.output/group/name; dest.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(source/name, dest)
                if digest(dest) != expected: raise ValueError('Snapshot hash mismatch')
        client = DirectClient(runtime.config.LLM_API_KEY, manifest['endpoint'])
    def one(sample, profile, rep):
        base = {k: sample[k] for k in ('idx', 'sample_id', 'target', 'group_id', 'cwe', 'source_sha256')}; base.update(profile=profile, repeat=rep)
        runtime.local.profile = profile; own = []; first = False; attempts = Counter(); step_requests = {}
        # mock 回答按臂自身契约:verdict 臂两行 VERDICT 格式,control 臂旧四行
        # HYPOTHESIS 格式;两臂解析到同一行为学结果(Uncertain->step1 Stop->单请求)
        native = ('VERDICT: Uncertain\nACTION: {"action":"Stop","reason":"missing bounds"}' if profile == 'verdict' else
                  'HYPOTHESIS: Uncertain\nACTION: {"action":"Stop","reason":"missing bounds"}\nREASONING: Missing bounds')
        def observed(**request):
            nonlocal first
            step = 1+sum(not c.get('error') for c in own); attempt = attempts[step]+1
            if step > 2 or attempt > 3 or len(own) >= 6: raise ValueError('Authorized step/attempt bound exceeded')
            if request.get('model') != 'deepseek-chat' or request.get('max_tokens') != 150 or request.get('temperature') != 0: raise ValueError('Unauthorized call parameters')
            if step == 1:
                if request != requests[sample['idx'], profile]: raise ValueError('Actual first request differs from full freeze')
                first = True
            if step in step_requests and step_requests[step] != request: raise ValueError('Retry request mutated')
            step_requests[step] = request; attempts[step] += 1
            if args.preflight_only:
                record = dict(base, request=request); mock_records.append(record); append('requests.jsonl', record)
                return SimpleNamespace(model='offline-mock', usage=SimpleNamespace(total_tokens=0, prompt_tokens=0, completion_tokens=0),
                    choices=[SimpleNamespace(finish_reason='stop', message=SimpleNamespace(content=native))])
            record = dict(base, request=request, step=step, attempt=attempt, started_at=datetime.now(timezone.utc).isoformat()); started = time.monotonic()
            try:
                response = client.chat.completions.create(**request); usage = response.usage
                record.update(answer=response.choices[0].message.content, model=response.model, finish_reason=response.choices[0].finish_reason,
                    **usage_record(usage))
                return response
            except Exception as exc:
                record.update(error=str(exc).replace(runtime.config.LLM_API_KEY, '[REDACTED]'), usage_known=False)
                raise RuntimeError(record['error']) from None
            finally:
                record['elapsed_seconds'] = time.monotonic()-started; own.append(record); append('api_receipts.jsonl', record)
                with lock: calls.append(record)
        observer = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=observed)))
        try:
            if digest(sample['source_path']) != sample['wrapped_source_sha256'] or digest(Path(sample['cache_path'])/'export/export.dot') != sample['cpg_sha256']: raise ValueError('Input changed')
            value = runtime.pipeline.run_hgl_pipeline(sample['source_path'], data[sample['idx']]['input'], sample['sample_id'], sample['cache_path'], observer, 4096, return_details=True)
            if not first or value['reasoning_steps'] > 2: raise ValueError('Unobserved/extra step')
            value['tokens_used'] = sum(c.get('total_tokens') or 0 for c in own)
            return dict(base, **value, first_request_verified=first)
        except Exception as exc:
            return dict(base, prediction=None, error=str(exc).replace(runtime.config.LLM_API_KEY, '[REDACTED]'), tokens_used=sum(c.get('total_tokens') or 0 for c in own), first_request_verified=first)
    def paired(sample):
        runtime.local.idx = sample['idx']; runtime.local.prepared = {}
        for rep in (1, 2):
            for profile in pair_order(sample['idx'], rep):
                if profile != args.internal_arm: continue
                row = one(sample, profile, rep); append('results.jsonl', row)
                with lock: rows.append(row); done = len(rows)
                if not args.preflight_only or done % 40 == 0:
                    print(f'{"OFFLINE" if args.preflight_only else "LLM"} verdict {done}/1016 {profile}/r{rep} idx={sample["idx"]} error={bool(row.get("error"))}', file=sys.__stdout__, flush=True)
        runtime.local.prepared.clear()
    samples = {s['idx']: s for s in manifest['samples']}
    try:
        with runtime.patches(args.preflight_only), (args.output/'execution.log').open('w', encoding='utf-8') as log, contextlib.redirect_stdout(log):
            with ThreadPoolExecutor(max_workers=2) as pool:
                for future in as_completed([pool.submit(paired, samples[i]) for i in manifest['sample_order']]): future.result()
    finally:
        if client is not None: client.close()
    after, _, _, _ = prepare()
    if after != manifest or runtime.blocked_attempts: raise ValueError('Freeze drift/forbidden external attempt; all records preserved')
    if args.preflight_only:
        expected = {(i, args.internal_arm, r) for i in range(254) for r in (1, 2)}
        if len(rows) != 508 or len(mock_records) != 508 or {(r['idx'], r['profile'], r['repeat']) for r in mock_records} != expected or any(r.get('error') for r in rows):
            raise ValueError('Incomplete full runtime preflight; keep failures')
        save('runtime_verification.json', dict(passed=True, rows=508, source_rows=254, new_api_calls=0,
            request_records_sha256=digest(args.output/'requests.jsonl'), results_sha256=digest(args.output/'results.jsonl'),
            manifest_sha256=digest(args.output/'manifest.json'), blocked_external_attempts=runtime.blocked_attempts))
        print('FULL RUNTIME PREFLIGHT PASS254 rows/1016 mock requests/no API'); return
    if len(rows) != 508: raise ValueError('Full arm denominator required')
    save('worker_complete.json', dict(rows=len(rows), calls=len(calls), errors=sum(bool(r.get('error')) for r in rows)))


class DirectClient:
    """No SDK retries/proxies/redirects; observer accounts every request."""
    def __init__(self, key, endpoint):
        import httpx
        self.key = key; self.endpoint = endpoint
        self.http = httpx.Client(trust_env=False, timeout=90, follow_redirects=False)
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))
    def create(self, **request):
        response = self.http.post(self.endpoint+'/chat/completions', json=request,
            headers={'Authorization': 'Bearer '+self.key})
        response.raise_for_status(); data = response.json(); choice = data['choices'][0]
        usage = dict(prompt_tokens=None, completion_tokens=None, total_tokens=0)
        usage.update(data.get('usage') or {})
        return SimpleNamespace(model=data.get('model'), usage=SimpleNamespace(**usage),
            choices=[SimpleNamespace(finish_reason=choice.get('finish_reason'), message=SimpleNamespace(content=choice['message'].get('content') or ''))])
    def close(self): self.http.close()


def orchestrate(args, manifest):
    if not args.preflight_only:
        proof = read_json(args.preflight/'runtime_verification.json')
        if not proof['passed'] or proof['rows'] != 1016 or read_json(args.preflight/'manifest.json') != manifest:
            raise ValueError('Full runtime freeze required')
        for name, expected in proof['hashes'].items():
            if digest(args.preflight/name) != expected: raise ValueError('Runtime preflight drift')
    args.output.mkdir(parents=True)
    (args.output/'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf8')
    for group, hashes, source in [('code_snapshot', manifest['source_hashes']['verdict'], Path(manifest['source_roots']['verdict'])),
        ('control_snapshot', manifest['source_hashes']['control'], Path(manifest['source_roots']['control'])),
        ('tooling_snapshot', manifest['tooling_hashes'], ROOT)]:
        for name, expected in hashes.items():
            dest = args.output/group/name; dest.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(source/name, dest)
            if digest(dest) != expected: raise ValueError('Snapshot mismatch')
    def launch(arm):
        command = [sys.executable, '-B', '-m', 'evaluation.run_verdict_first_llm_20261012',
            '--output', str((args.output/arm).resolve()), '--internal-arm', arm]
        if args.preflight_only: command += ['--preflight-only']
        else: command += ['--preflight', str(args.preflight.resolve()), '--authorized-real-1016']
        with (args.output/(arm+'.log')).open('x', encoding='utf8') as log:
            result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        print(arm+' exit='+str(result.returncode), flush=True)
        return result.returncode
    with ThreadPoolExecutor(max_workers=2) as pool: statuses = list(pool.map(launch, PROFILES))
    names = ['results.jsonl', 'requests.jsonl' if args.preflight_only else 'api_receipts.jsonl']; records = {}
    for name in names:
        records[name] = [json.loads(line) for arm in PROFILES if (args.output/arm/name).exists()
                       for line in (args.output/arm/name).read_text(encoding='utf8').splitlines()]
        (args.output/name).write_text(''.join(json.dumps(r, ensure_ascii=False)+'\n' for r in records[name]), encoding='utf8')
    if any(statuses): raise ValueError('Worker failed; preserve all output; no restart')
    rows = records['results.jsonl']
    if len(rows) != 1016 or len({(r['idx'], r['profile'], r['repeat']) for r in rows}) != 1016:
        raise ValueError('Full denominator missing')
    if prepare()[0] != manifest: raise ValueError('Source/tool drift')
    if args.preflight_only:
        if len(records['requests.jsonl']) != 1016 or any(r.get('error') for r in rows): raise ValueError('Runtime preflight failed')
        proof = dict(passed=True, rows=1016, new_api_calls=0, hashes={n: digest(args.output/n) for n in (*names, 'manifest.json')})
        (args.output/'runtime_verification.json').write_text(json.dumps(proof, indent=2), encoding='utf8')
        print('FULL1016 RUNTIME MOCK PASS', flush=True)
    else:
        report = summarize(rows, records['api_receipts.jsonl'], manifest)
        (args.output/'report.json').write_text(json.dumps(report, indent=2), encoding='utf8')
        print(json.dumps(report['metrics'], indent=2), flush=True)


if __name__ == '__main__':
    main()
