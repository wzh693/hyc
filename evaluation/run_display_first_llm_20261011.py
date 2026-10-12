"""One authorized frozen full254x2x2 DeepSeek batch; mock first, no reruns."""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import contextlib
from dataclasses import asdict
import hashlib
import io
import json
import os
from pathlib import Path
import random
import socket
import threading
import time
from unittest.mock import patch

import torch
from development.converged_graph_v2_candidate_20261010 import architecture as base
from development.converged_display_first_candidate_20261011 import architecture as candidate
from development.converged_graph_v2_candidate_20261010.run_offline import ROOT, read, sha
from evaluation.evaluate_sven_complete_src import extended_score, request_hash
from evaluation.test_graph_guided_foundation import verify_foundation
from graph.load_graph import load_graph
from linearization.source_mapping import source_line_offset

PROFILES = ('control', 'display')
IDENTITY = ('idx', 'sample_id', 'target', 'cwe', 'group_id', 'source_sha256')


def prepare():
    if os.environ.get('PYTHONHASHSEED') != '0':
        raise ValueError('PYTHONHASHSEED=0 required before Python startup')
    stage = ROOT/'output/converged_display_first_preflight_seed0_20261011'
    freeze, stage_report = read(stage/'manifest.json'), read(stage/'report.json')
    if not stage_report['pass']:
        raise ValueError('Offline full paired preflight required')
    bindings = dict(freeze['source_tool_hashes'])
    for name, expected in bindings.items():
        if sha(ROOT/name) != expected:
            raise ValueError('Frozen dependency drift: '+name)
    for path in (Path(__file__), ROOT/'evaluation/DISPLAY_FIRST_LLM_PROTOCOL_20261011.md',
                 ROOT/'evaluation/audit_display_first_llm_20261011.py',
                 ROOT/'evaluation/test_display_first_llm_20261011.py',
                 ROOT/'evaluation/supervise_display_first_llm_20261011.py'):
        bindings[str(path.relative_to(ROOT))] = sha(path)
    ref = read(ROOT/'output/sven_complete_src_eval_20261008/manifest.json')
    data = read(ref['dataset'])
    samples = ref['samples']
    if len(data) != 254 or len(samples) != 254 or {s['idx'] for s in samples} != set(range(254)):
        raise ValueError('Full254 required')
    if sha(ref['dataset']) != freeze['dataset_sha256']:
        raise ValueError('Dataset drift')
    expected_requests = {}
    for profile, name in (('control', 'control'), ('display', 'candidate')):
        path = stage/(name+'_rows.jsonl')
        bindings[str(path.relative_to(ROOT))] = sha(path)
        rows = [json.loads(line) for line in path.read_text(encoding='utf8').splitlines()]
        if len(rows) != 254 or {r['idx'] for r in rows} != set(range(254)) or any(r['error'] for r in rows):
            raise ValueError('Incomplete input preflight')
        for row in rows:
            expected_requests[row['idx'], profile] = dict(row['result']['trace'][0]['request'],
                                                        model='deepseek-chat', temperature=0)
    for sample in samples:
        item = data[sample['idx']]
        if (sample['target'] != int(item['output'] == 'VULNERABLE') or sample['cwe'] != item['cwe'] or
                hashlib.sha256(item['input'].encode()).hexdigest() != sample['source_sha256']):
            raise ValueError('Label/source identity mismatch')
    order = list(range(254))
    random.Random(20261011).shuffle(order)
    manifest = dict(samples=samples, profiles=list(PROFILES), repeats=[1, 2], planned_results=1016,
        source_tool_hashes=bindings, dataset=ref['dataset'], dataset_sha256=freeze['dataset_sha256'],
        settings=asdict(base.Settings()), model_sha256=freeze['model_sha256'],
        endpoint='https://api.deepseek.com/v1', requested_model='deepseek-chat',
        max_steps=3, max_attempts_per_step=3, output_cap=150, timeout_seconds=90,
        workers=4, sdk_retries=0, sample_order=order, bootstrap_seed=20261011, bootstrap_draws=2000,
        first_request_sha256={f'{p}/{i}': request_hash(r) for (i,p),r in expected_requests.items()},
        scope='Full254 exposed local SVEN; development comparison, not independent publication test',
        automatic_promotion=False, security_net='shadow', python_hash_seed=0)
    return manifest, expected_requests, data


def load_inputs(manifest, data):
    verify_foundation()
    torch.set_num_threads(2)
    model_dir = ROOT/'output/converged_expanded_gat_training_20261010'
    scorer = base.SharedGATScorer(model_dir/'gat_mil.pt', model_dir/'split.json')
    inputs = {}
    for sample in manifest['samples']:
        code = data[sample['idx']]['input']
        try:
            dot = Path(sample['cache_path'])/'export/export.dot'
            if sha(dot) != sample['cpg_sha256'] or sha(sample['source_path']) != sample['wrapped_source_sha256']:
                raise ValueError('Graph/source drift')
            with contextlib.redirect_stdout(io.StringIO()):
                graph = load_graph(str(dot))
            offset = source_line_offset(code, Path(sample['source_path']).read_text(encoding='utf8'))
            inputs[sample['idx']] = (graph, code, offset, scorer(graph, code))
        except Exception as exc:
            inputs[sample['idx']] = repr(exc)
    return inputs


def response_usage(value):
    result = {k: value.get(k) for k in ('prompt_tokens', 'completion_tokens', 'total_tokens')}
    known = all(type(v) is int and v >= 0 for v in result.values())
    result['usage_known'] = known and result['prompt_tokens']+result['completion_tokens'] == result['total_tokens']
    return result


def bounded_call(request, transport, record, sleep=time.sleep):
    for attempt in range(1, 4):
        started = time.monotonic()
        receipt = dict(request=request, attempt=attempt)
        try:
            raw = transport(request)
            value = dict(text=raw['choices'][0]['message'].get('content') or '',
                model=raw.get('model'), finish_reason=raw['choices'][0].get('finish_reason'))
            receipt.update(response=value, **response_usage(raw.get('usage') or {}))
            return value
        except Exception as exc:
            receipt.update(error=str(exc), usage_known=False)
            if attempt == 3:
                raise RuntimeError('Step failed after 3 recorded attempts') from None
        finally:
            receipt['elapsed_seconds'] = time.monotonic()-started
            record(receipt)
        sleep(attempt)


def summarize(rows, calls, manifest):
    indexed = {(r['idx'], r['profile'], r['repeat']):r for r in rows}
    expected = {(i,p,r) for i in range(254) for p in PROFILES for r in (1,2)}
    if len(rows) != 1016 or set(indexed) != expected:
        raise ValueError('Incomplete/duplicate result denominator')
    metrics, cwes = {}, {}
    for p in PROFILES:
        for rep in (1,2):
            batch = [indexed[i,p,rep] for i in range(254)]
            metrics[f'{p}/r{rep}'] = extended_score(batch)
            cwes[f'{p}/r{rep}'] = {c: extended_score([r for r in batch if r['cwe'] == c]) for c in sorted({r['cwe'] for r in batch})}
    intervals = {}
    for name, subset, key in [('global', manifest['samples'], 'f1'),
            ('CWE-125', [s for s in manifest['samples'] if s['cwe'] == 'CWE-125'], 'accuracy')]:
        groups = defaultdict(list)
        for sample in subset:
            groups[sample['group_id']].append(sample['idx'])
        rng, values = random.Random(20261011), []
        for _ in range(2000):
            ids = [i for group in rng.choices(list(groups.values()), k=len(groups)) for i in group]
            values.append(extended_score([indexed[i,'display',1] for i in ids])[key]-
                          extended_score([indexed[i,'control',1] for i in ids])[key])
        values.sort()
        intervals[name] = dict(metric=key, ci95=[values[50], values[1950]])
    positive = extended_score([dict(s, prediction=1) for s in manifest['samples']])
    gates = dict(global_nonnegative_both=all(metrics[f'display/r{r}'][k] >= metrics[f'control/r{r}'][k] for r in (1,2) for k in ('f1','accuracy')),
        cwe125_improves_both=all(cwes[f'display/r{r}']['CWE-125'][k] > cwes[f'control/r{r}']['CWE-125'][k] for r in (1,2) for k in ('f1','accuracy')),
        primary_family_intervals_positive=all(v['ci95'][0] > 0 for v in intervals.values()),
        other_types_within_002=all(cwes[f'display/r{r}'][c]['balanced_accuracy'] >= cwes[f'control/r{r}'][c]['balanced_accuracy']-.02 for r in (1,2) for c in ('CWE-190','CWE-416')),
        beats_constant_both=all(metrics[f'display/r{r}']['accuracy'] > positive['accuracy'] and metrics[f'display/r{r}']['f1'] > positive['f1'] and metrics[f'display/r{r}']['mcc'] > 0 for r in (1,2)))
    models = Counter(c.get('response',{}).get('model') for c in calls if not c.get('error'))
    return dict(scheduled_results=len(rows), metrics=metrics, by_cwe=cwes, gates=gates,
        functional_gate=all(not v['errors'] and not v['uncertain'] for v in metrics.values()) and
            all(not c.get('error') and c.get('usage_known') for c in calls) and len(models)==1 and None not in models,
        actual_invocations=len(calls), actual_models=dict(models),
        failed_invocations=sum(bool(c.get('error')) for c in calls),
        unknown_usage=sum(not c.get('usage_known') for c in calls),
        length_calls=sum(c.get('response',{}).get('finish_reason')=='length' for c in calls),
        total_reported_tokens=sum(c.get('total_tokens') or 0 for c in calls),
        primary_family_intervals=intervals, always_positive=positive,
        repeat_disagreements={p:sum(indexed[i,p,1]['prediction'] != indexed[i,p,2]['prediction'] for i in range(254)) for p in PROFILES},
        scope=manifest['scope'], auto_promoted=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--preflight-only', action='store_true')
    parser.add_argument('--preflight', type=Path)
    parser.add_argument('--authorized-real-1016', action='store_true')
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('Fresh output required; no resume or rerun')
    if not args.preflight_only and (not args.preflight or not args.authorized_real_1016):
        raise ValueError('Explicit authorization and full runtime preflight required')
    manifest, requests, data = prepare()
    if not args.preflight_only:
        prior = read(args.preflight/'verification.json')
        if not prior['pass'] or read(args.preflight/'manifest.json') != manifest:
            raise ValueError('Preflight identity mismatch')
        for name, expected in prior['hashes'].items():
            if sha(args.preflight/name) != expected:
                raise ValueError('Runtime preflight artifacts changed')
    inputs = load_inputs(manifest, data)
    args.output.mkdir(parents=True)
    def save(name, value):
        (args.output/name).write_text(json.dumps(value, indent=2), encoding='utf8')
    save('manifest.json', manifest)
    # Preserve all bound implementations and receipts, never credentials.
    import shutil
    for name, expected in manifest['source_tool_hashes'].items():
        destination = args.output/'snapshot'/name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT/name, destination)
        if sha(destination) != expected:
            raise ValueError('Snapshot mismatch')
    secret, client = '', None
    if not args.preflight_only:
        env = ROOT/'.env'
        if env.exists():
            for line in env.read_text(encoding='utf8').splitlines():
                if line.strip() and not line.lstrip().startswith('#') and '=' in line:
                    key, value = line.split('=',1)
                    if key.strip() == 'OPENAI_API_KEY':
                        secret = value.strip().strip('"').strip("'")
        secret = os.environ.get('OPENAI_API_KEY') or secret
        if not secret or secret == 'offline-not-a-key':
            raise ValueError('Configured credential absent; no API called')
        import httpx
        client = httpx.Client(trust_env=False, timeout=90, follow_redirects=False)
    lock, rows, calls, blocked_count = threading.Lock(), [], [], [0]
    def append(name, value):
        with lock:
            with (args.output/name).open('a', encoding='utf8') as stream:
                stream.write(json.dumps(value, ensure_ascii=False)+'\n')
    def blocked(*arg, **kw):
        blocked_count[0] += 1
        raise RuntimeError('Offline connection forbidden')
    def one(sample, profile, rep):
        identity = {key:sample[key] for key in IDENTITY}
        identity.update(profile=profile, repeat=rep)
        own, trace, step = [], [], [0]
        def invoke(**raw):
            step[0] += 1
            if step[0] > 3:
                raise ValueError('Step budget exceeded')
            request = dict(raw, model='deepseek-chat', temperature=0)
            if request['max_tokens'] != 150:
                raise ValueError('Output budget drift')
            if step[0] == 1 and request != requests[sample['idx'],profile]:
                raise ValueError('First request differs from freeze')
            def record(receipt):
                if receipt.get('error') and secret:
                    receipt['error'] = receipt['error'].replace(secret, '[REDACTED]')
                receipt.update(identity, step=step[0])
                own.append(receipt)
                append('api_receipts.jsonl', receipt)
                with lock:
                    calls.append(receipt)
            def transport(payload):
                if args.preflight_only:
                    return dict(model='offline-mock', choices=[dict(message={'content':'{"verdict":"Uncertain","action":"Stop"}'}, finish_reason='stop')],
                        usage=dict(prompt_tokens=0, completion_tokens=0, total_tokens=0))
                response = client.post(manifest['endpoint']+'/chat/completions', json=payload,
                    headers={'Authorization':'Bearer '+secret})
                response.raise_for_status()
                return response.json()
            return bounded_call(request, transport, record)
        try:
            value = inputs[sample['idx']]
            if isinstance(value, str):
                raise ValueError(value)
            graph, code, offset, scores = value
            run = base.run if profile == 'control' else candidate.run
            result = run(graph, code, offset, lambda g,s:scores, invoke)
            trace = result['trace']
            row = dict(identity, prediction=result['final_pred'], result=result, error=None)
        except Exception as exc:
            row = dict(identity, prediction=None, error=str(exc).replace(secret,'[REDACTED]') if secret else str(exc))
        row['tokens_used'] = sum(c.get('total_tokens') or 0 for c in own)
        append('results.jsonl', row)
        with lock:
            rows.append(row)
            done = len(rows)
        if done % 20 == 0 or done == 1016:
            print(f'{"MOCK" if args.preflight_only else "LLM"} {done}/1016', flush=True)
    def paired(idx):
        sample = next(s for s in manifest['samples'] if s['idx'] == idx)
        for rep in (1,2):
            order = PROFILES if (idx+rep)%2 == 0 else tuple(reversed(PROFILES))
            for profile in order:
                one(sample, profile, rep)
    try:
        with contextlib.ExitStack() as stack:
            if args.preflight_only:
                stack.enter_context(patch.object(socket.socket, 'connect', blocked))
                stack.enter_context(patch.object(socket, 'create_connection', blocked))
            with ThreadPoolExecutor(max_workers=4) as pool:
                for future in as_completed([pool.submit(paired, idx) for idx in manifest['sample_order']]):
                    future.result()
    finally:
        if client is not None:
            client.close()
    if prepare()[0] != manifest or blocked_count[0]:
        raise ValueError('Freeze drift or forbidden connection; preserve all records')
    if args.preflight_only:
        expected = {(i,p,r) for i in range(254) for p in PROFILES for r in (1,2)}
        passed = (len(rows)==1016 and len(calls)==1016 and
            {(r['idx'],r['profile'],r['repeat']) for r in rows}==expected and not any(r['error'] for r in rows))
        save('verification.json', dict(pass_=passed, rows=len(rows), mock_requests=len(calls),
            paid_api_calls=0, hashes={name:sha(args.output/name) for name in ('manifest.json','results.jsonl','api_receipts.jsonl')}))
        # JSON key pass is used by the real-run guard.
        receipt = read(args.output/'verification.json')
        receipt['pass'] = receipt.pop('pass_')
        save('verification.json', receipt)
        if not passed:
            raise ValueError('Full runtime preflight failed')
    else:
        save('report.json', summarize(rows, calls, manifest))
    print('BATCH COMPLETE; no automatic rerun or promotion', flush=True)


if __name__ == '__main__':
    main()
