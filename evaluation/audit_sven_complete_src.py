"""Zero-call integrity and independently recomputed confusion-count audit."""
import argparse
import hashlib
import json
from pathlib import Path
from evaluation.evaluate_sven_complete_src import ROOT, digest, read_json, source_only_request, summarize, request_hash


def audit(run, archived_source=False):
    manifest = read_json(run/'manifest.json')
    if archived_source:
        # A completed experiment binds its snapshots, not future editable code.
        prior = read_json(run/'audit.json')
        for name, expected_hash in prior['artifact_sha256'].items():
            if digest(run/name) != expected_hash: raise ValueError('Audited artifact changed')
        addendum = read_json(run/'audit_addendum.json')
        if digest(run/'api_receipts.jsonl') != addendum['api_receipts_sha256']:
            raise ValueError('Audited API receipts changed')
    data = read_json(manifest['dataset'])
    rows = list(map(json.loads, (run/'results.jsonl').read_text(encoding='utf8').splitlines()))
    calls_path = run/'api_receipts.jsonl'
    calls = list(map(json.loads, calls_path.read_text(encoding='utf8').splitlines())) if calls_path.exists() else []
    if len(data) != 254 or manifest['planned_results'] != 254*len(manifest['profiles'])*2 or manifest['profiles'] not in (['control', 'complete_src'], ['complete_src']):
        raise ValueError('Batch scope changed')
    if digest(manifest['dataset']) != manifest['dataset_sha256']: raise ValueError('Dataset changed')
    receipt = read_json(ROOT/'baselines/type_coverage_reconstructed_20261008/baseline.json')
    for name, expected in manifest['code_hashes'].items():
        if (not archived_source and digest(Path(manifest['code_root'])/name) != expected) or digest(run/'code_snapshot'/name) != expected:
            raise ValueError('Prediction code changed')
    for name, expected in receipt['code_hashes'].items():
        if digest(Path(receipt['frozen_source'])/name) != expected: raise ValueError('Frozen foundation changed')
    for name, expected in receipt['preserved_repaired_code_hashes'].items():
        if digest(ROOT/name) != expected: raise ValueError('Root repaired prediction code changed')
    for name, expected in manifest['tooling_hashes'].items():
        # Only unchanged pure scoring/request helpers are reused in archive mode.
        current_required = not archived_source or Path(name).name in ('evaluate_sven_complete_src.py', 'evaluate_reconstructed_llm.py')
        if (current_required and digest(ROOT/name) != expected) or digest(run/'tooling_snapshot'/name) != expected:
            raise ValueError('Runner/protocol changed')
    first, pairs = {}, 0
    for call in calls: first.setdefault((call['idx'], call['profile'], call['repeat']), call['request'])
    for sample in manifest['samples']:
        item = data[sample['idx']]
        if sample['target'] != int(item['output'] == 'VULNERABLE') or sample['cwe'] != item['cwe'] or hashlib.sha256(item['input'].encode()).hexdigest() != sample['source_sha256']:
            raise ValueError('Prepared identity differs from dataset')
        if not sample.get('preparation_error') and (digest(sample['source_path']) != sample['wrapped_source_sha256'] or digest(Path(sample['cache_path'])/'export/export.dot') != sample['cpg_sha256']):
            raise ValueError('Source/graph changed')
        for p in manifest['profiles']:
            for r in (1, 2):
                actual = first.get((sample['idx'], p, r))
                if actual and request_hash(actual) != manifest['first_request_sha256'][f'{p}/{sample["idx"]}']:
                    raise ValueError('Frozen/actual first request mismatch')
        for r in (1, 2):
            a = first.get((sample['idx'], 'control', r)); b = first.get((sample['idx'], 'complete_src', r))
            if a and b:
                if b != source_only_request(a, item['input']): raise ValueError('Paired first request changes more than SRC')
                pairs += 1
    expected = summarize(rows, calls, manifest)
    report = read_json(run/'report.json'); report.pop('frozen_code_matches')
    if report != expected: raise ValueError('Receipt-based recomputation mismatch')
    # Separate arithmetic implementation, rather than trusting the scorer twice.
    for p in manifest['profiles']:
        for r in (1, 2):
            batch = [x for x in rows if x['profile'] == p and x['repeat'] == r]
            scopes = [(expected['metrics'][f'{p}/r{r}'], batch)]
            scopes += [(m, [x for x in batch if x['cwe'] == c]) for c, m in expected['by_cwe'][f'{p}/r{r}'].items()]
            for metric, values in scopes:
                tp = sum(x['target'] == 1 and x['prediction'] == 1 for x in values)
                tn = sum(x['target'] == 0 and x['prediction'] == 0 for x in values)
                fn = sum(x['target'] == 1 and x['prediction'] != 1 for x in values)
                fp = sum(x['target'] == 0 and x['prediction'] != 0 for x in values)
                if [metric[k] for k in ('tp', 'tn', 'fp', 'fn')] != [tp, tn, fp, fn]: raise ValueError('Independent confusion mismatch')
                if metric['accuracy'] != (tp+tn)/len(values) or metric['f1'] != (2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0): raise ValueError('Independent score mismatch')
    return dict(passed=True, scheduled_results=len(rows), actual_invocations=len(calls), first_requests_verified=len(first),
        source_only_first_pairs_verified=pairs, source_files_verified=len(manifest['code_hashes']), new_api_calls=0,
        root_repaired_source_preserved=True, frozen_foundation_preserved=True, functional_gate=expected['functional_gate'],
        exploratory_support=expected['exploratory_support'],
        source_verification_mode='archived_snapshot' if archived_source else 'live_checkout_and_snapshot',
        artifact_sha256={n: digest(run/n) for n in ('manifest.json', 'results.jsonl', 'report.json')})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--archived-source', action='store_true', help='Read-only re-audit of preserved experiment snapshots after baseline selection')
    args = parser.parse_args()
    result = audit(args.run, archived_source=args.archived_source)
    if args.archived_source:
        print(json.dumps(result, indent=2))
        raise SystemExit(0)
    if (args.run/'audit.json').exists(): raise ValueError('Do not overwrite audit')
    (args.run/'audit.json').write_text(json.dumps(result, indent=2), encoding='utf8')
    print(json.dumps(result, indent=2))
