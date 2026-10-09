"""Fresh full-SVEN end-to-end benchmark replay, never a held-out confirmation."""
import argparse
from collections import Counter, defaultdict
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
PROFILES = {'control': (False, False, False),
            'slice_expansion': (True, False, True)}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_groups(data):
    """Conservative union of same source OR same source-family filename."""
    parents = list(range(len(data)))
    def root(i):
        while parents[i] != i:
            parents[i] = parents[parents[i]]
            i = parents[i]
        return i
    seen = {}
    for i, sample in enumerate(data):
        for key in (('code', sample['input']), ('family', sample['file_name'])):
            if key in seen:
                parents[root(i)] = root(seen[key])
            else:
                seen[key] = i
    return [f'sven_family_{root(i):04d}' for i in range(len(data))]


def summarize(rows, calls, samples, bootstrap=2000):
    from evaluation.evaluate_wiring_quality import score
    indexed = {}
    for row in rows:
        key = row['idx'], row['profile']
        if key in indexed:
            raise ValueError('Duplicate sample/profile result')
        indexed[key] = row
    expected = {(s['idx'], p) for s in samples for p in PROFILES}
    if set(indexed) != expected:
        raise ValueError('Missing/unexpected dataset results')
    metrics = {p: score([indexed[s['idx'], p] for s in samples]) for p in PROFILES}
    groups = defaultdict(list)
    sources = defaultdict(list)
    for s in samples:
        groups[s['group_id']].append(s['idx'])
        sources[s['source_sha256']].append(s['idx'])
    rng = random.Random(20261006)
    deltas = {'f1': [], 'accuracy': []}
    for _ in range(bootstrap):
        ids = [i for group in rng.choices(list(groups.values()), k=len(groups)) for i in group]
        a = score([indexed[i, 'control'] for i in ids])
        b = score([indexed[i, 'slice_expansion'] for i in ids])
        for metric in deltas:
            deltas[metric].append(b[metric] - a[metric])
    cis = {}
    for metric, values in deltas.items():
        values.sort()
        cis[metric] = [values[int(bootstrap*.025)], values[min(bootstrap-1, int(bootstrap*.975))]]
    consistent = [ids for ids in sources.values()
                  if len({indexed[i, 'control']['target'] for i in ids}) == 1]
    representatives = [min(ids) for ids in consistent]
    accounting, modules, by_cwe = {}, {}, {}
    for p in PROFILES:
        batch = [indexed[s['idx'], p] for s in samples]
        observed = [c for c in calls if c['profile'] == p]
        accounting[p] = {
            'actual_invocations': len(observed),
            'failed_invocations': sum(bool(c.get('error')) for c in observed),
            'calls_without_usage': sum(not c.get('usage_available', False) for c in observed),
            'truncated_calls': sum(c.get('finish_reason') == 'length' for c in observed),
            'actual_models': dict(Counter(c.get('model', 'unavailable') for c in observed)),
            **{name: sum(c.get(name, 0) or 0 for c in observed)
               for name in ('prompt_tokens', 'completion_tokens', 'total_tokens')},
        }
        accounting[p]['mean_actual_tokens'] = accounting[p]['total_tokens']/len(samples)
        audits = [r.get('module_audit', {}) for r in batch]
        slices = [a.get('backward_slice', {}) for a in audits]
        events = [e for a in audits for e in a.get('expansion', {}).get('events', [])]
        modules[p] = {
            'audited_samples': sum(bool(a) for a in audits),
            'compression_executed': sum(bool(a.get('compression')) for a in audits),
            'topk_executed': sum(bool(a.get('topk')) for a in audits),
            'learned_scoring': sum(bool(a.get('learned_scoring')) for a in audits),
            'graph_net_executed': sum(bool(a.get('graph_security_net')) for a in audits),
            'source_net_executed': sum(bool(a.get('source_security_net')) for a in audits),
            'source_net_flips': sum(bool(r.get('arbitrate', {}).get('security_net', {}).get('flipped')) for r in batch),
            'expansion_events': len(events),
            'two_step_samples': sum((r.get('reasoning_steps') or 0) > 1 for r in batch),
            'slice_receipts': slices,
            'slice_fallbacks': sum(bool(a.get('fallback')) for a in slices),
            'slices_with_budget_omissions': sum(a.get('omitted_lines', 0) > 0 for a in slices),
            'events_with_new_paths': sum(e.get('new_paths', 0) > 0 for e in events),
            'stop_reasons': dict(Counter(str(a.get('stop_reason', 'unavailable')) for a in audits)),
        }
        by_cwe[p] = {cwe: score([r for r in batch if r['cwe'] == cwe])
                     for cwe in sorted({s['cwe'] for s in samples})}
    return {
        'metrics': metrics, 'api_accounting': accounting, 'modules': modules, 'by_cwe': by_cwe,
        'trivial_baselines': {name: score([dict(s, prediction=pred) for s in samples])
                             for name, pred in (('always_positive', 1), ('always_negative', 0))},
        'source_groups': {'exact_sources': len(sources), 'family_union_groups': len(groups),
            'conflicting_exact_sources': len(sources)-len(consistent),
            'consistent_exact_lowest_index_supplement': {
                p: score([indexed[i, p] for i in representatives]) for p in PROFILES},
            'paired_family_bootstrap_delta_ci95': cis, 'seed': 20261006, 'draws': bootstrap},
        'prediction_disagreements': sum(indexed[s['idx'], 'control'].get('prediction') !=
                                      indexed[s['idx'], 'slice_expansion'].get('prediction') for s in samples),
        'scope': 'Previously exposed full SVEN development benchmark replay, not independent confirmation.',
        'auto_promoted': False,
        'limitations': ['One fresh run per profile; provider variability not isolated.',
            'Rows are correlated and identical source can have conflicting labels.',
            'CPG uses validated source-fingerprinted cache; this is not a cold-cache timing benchmark.',
            'Failure/uncertain results retained and penalized; missing API usage is unknown cost.',
            'No learned/GAT or graph net activation; no retraining or final-test tuning.'],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--preflight-only', action='store_true')
    parser.add_argument('--prepared-root', type=Path)
    args = parser.parse_args()
    if not 1 <= args.workers <= 8:
        parser.error('workers must be 1..8')
    if args.output.exists():
        raise ValueError('Use a new empty output path; no replacement or favorable resume')
    from evaluation.build_clean_development_pilot import SETTINGS
    settings = dict(SETTINGS, RECORD_REASONING_TRACE='1', USE_BACKWARD_SLICE='0',
                    BOUNDED_OUTPUT_CONTRACT='0', EVIDENCE_EXPANSION='0')
    os.environ.update(settings)
    import config
    from evaluation.evaluate_wiring_quality import effective_configuration, prediction_code_hashes
    effective = effective_configuration(config, settings)
    from graph.build_cpg import _source_fingerprint, _dot_has_func_method
    from graph.pipeline import run_hgl_pipeline
    from sven_eval.data.wrap_slice import wrap_slice
    from linearization.source_mapping import source_line_offset
    dataset = ROOT/'sven_eval/data/sven_test.json'
    data = json.loads(dataset.read_text(encoding='utf-8'))
    groups = source_groups(data)
    samples = []
    for idx, item in enumerate(data):
        sid = f"{idx:04d}_{Path(item['file_name']).stem}"
        source = ROOT/'sven_eval/src_c'/f"{idx:04d}_{item['file_name']}"
        cache = ROOT/'sven_eval/cpg_cache'/sid
        if args.prepared_root:
            cache = args.prepared_root/sid
            source = cache/'source.c'
        sample = {'idx': idx, 'sample_id': sid, 'group_id': groups[idx],
            'target': int(item['output'] == 'VULNERABLE'), 'cwe': item['cwe'],
            'file_name': item['file_name'], 'source_path': str(source), 'cache_path': str(cache),
            'source_sha256': hashlib.sha256(item['input'].encode()).hexdigest()}
        try:
            wrapped = source.read_text(encoding='utf-8')
            expected_wrapper, ok, reason = wrap_slice(item['input'], item['file_name'])
            if not ok or wrapped != expected_wrapper:
                raise ValueError('Source differs from deterministic SVEN wrapper')
            offset = source_line_offset(item['input'], wrapped)
            if offset > len(wrapped.splitlines()):
                raise ValueError('Cannot verify line-preserving wrapper source mapping')
            sample.update(source_line_offset=offset, wrapper_reason=reason)
            dot = cache/'export/export.dot'
            meta = json.loads((cache/'.hgl_cpg_cache.json').read_text(encoding='utf-8'))
            if meta.get('source_fingerprint') != _source_fingerprint(wrapped, str(source)):
                raise ValueError('CPG cache source/tool fingerprint mismatch')
            if not _dot_has_func_method(str(dot)):
                raise ValueError('CPG contains no defined function body')
            sample.update(wrapped_source_sha256=digest(source), cpg_sha256=digest(dot))
        except Exception as exc:
            sample['preparation_error'] = str(exc)
        samples.append(sample)
    invalid = [s for s in samples if s.get('preparation_error')]
    # No model call allowed with silently stale/missing graph inputs.
    hashes = prediction_code_hashes()
    hashes[str(Path(__file__).relative_to(ROOT))] = digest(__file__)
    hashes['sven_eval/data/wrap_slice.py'] = digest(ROOT/'sven_eval/data/wrap_slice.py')
    manifest = {'dataset': str(dataset), 'dataset_sha256': digest(dataset), 'samples': samples,
        'profiles': PROFILES, 'settings': settings, 'effective_settings': effective,
        'code_hashes': hashes, 'planned_pairs': len(samples)*len(PROFILES),
        'requested_model': config.LLM_MODEL, 'token_budget': 4096, 'output_token_ceiling': 150,
        'retry_policy': 'SDK retries disabled, 90s timeout, wrapper up to 3 observed attempts.',
        'scope': 'Full previously exposed SVEN benchmark replay; no independent generalization claim.',
        'protocol': 'SVEN_FULL_PIPELINE_PROTOCOL_20261006.md', 'preparation_errors': len(invalid)}
    args.output.mkdir(parents=True)
    (args.output/'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(f"PREFLIGHT samples={len(samples)} valid={len(samples)-len(invalid)} invalid={len(invalid)}", flush=True)
    if invalid:
        print(json.dumps([{'idx': s['idx'], 'error': s['preparation_error']} for s in invalid[:10]], indent=2))
        raise ValueError('Repair graph/source preparation before any API calls; no sample replacement')
    if args.preflight_only:
        print('PREFLIGHT PASS api_calls=0')
        return
    from reasoning.llm_api import create_client
    client = create_client().with_options(max_retries=0, timeout=90)
    lock = threading.Lock()
    rows, calls = [], []
    def append(name, row):
        with lock:
            with (args.output/name).open('a', encoding='utf-8') as file:
                file.write(json.dumps(row, ensure_ascii=False)+'\n')
    def run(s, profile):
        base = {key: s[key] for key in ('idx', 'sample_id', 'group_id', 'target', 'cwe', 'source_sha256')}
        base.update(profile=profile, repeat=1)
        def observed(**kwargs):
            call = dict(base, request=kwargs)
            try:
                response = client.chat.completions.create(**kwargs)
                usage = response.usage
                call.update(model=response.model, answer=response.choices[0].message.content,
                    finish_reason=response.choices[0].finish_reason, usage_available=usage is not None,
                    **{key: getattr(usage, key, None) for key in
                       ('prompt_tokens', 'completion_tokens', 'total_tokens')})
                return response
            except Exception as exc:
                call['error'] = str(exc)
                raise
            finally:
                append('api_receipts.jsonl', call)
                with lock:
                    calls.append(call)
        observer = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=observed)))
        try:
            if digest(s['source_path']) != s['wrapped_source_sha256'] or digest(Path(s['cache_path'])/'export/export.dot') != s['cpg_sha256']:
                raise ValueError('Input changed after preflight')
            result = run_hgl_pipeline(s['source_path'], data[s['idx']]['input'], s['sample_id'],
                s['cache_path'], observer, 4096, ablation='', return_details=True)
            audit = result.get('module_audit', {})
            if audit.get('learned_scoring') or audit.get('graph_security_net'):
                raise ValueError('Rejected module unexpectedly activated')
            return dict(base, **result)
        except Exception as exc:
            return dict(base, prediction=None, error=str(exc))
    def current_hashes():
        result = prediction_code_hashes()
        result[str(Path(__file__).relative_to(ROOT))] = digest(__file__)
        result['sven_eval/data/wrap_slice.py'] = digest(ROOT/'sven_eval/data/wrap_slice.py')
        return result
    with (args.output/'execution.log').open('w', encoding='utf-8') as log, contextlib.redirect_stdout(log):
        for profile, flags in PROFILES.items():
            if current_hashes() != hashes:
                raise ValueError('Prediction code changed during run')
            for name, value in zip(('USE_BACKWARD_SLICE', 'BOUNDED_OUTPUT_CONTRACT', 'EVIDENCE_EXPANSION'), flags):
                setattr(config, name, value)
            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                for future in as_completed([pool.submit(run, s, profile) for s in samples]):
                    row = future.result()
                    rows.append(row)
                    append('results.jsonl', row)
                    print(f"SVEN {len(rows)}/{manifest['planned_pairs']} {profile} idx={row['idx']} error={bool(row.get('error'))}", file=sys.__stdout__, flush=True)
            log.flush()
    if current_hashes() != hashes or digest(dataset) != manifest['dataset_sha256']:
        raise ValueError('Frozen inputs/code changed')
    report = summarize(rows, calls, samples)
    report['prediction_code_matches_manifest'] = True
    (args.output/'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({'metrics': report['metrics'], 'api_accounting': report['api_accounting'],
                      'source_groups': report['source_groups'], 'auto_promoted': False}, indent=2))


if __name__ == '__main__':
    main()
