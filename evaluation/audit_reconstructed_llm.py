"""Independent offline verification of the authorized real smoke receipts."""
import argparse
import hashlib
import json
from pathlib import Path

from evaluation.evaluate_reconstructed_llm import digest, read_json, summarize


def audit(run):
    manifest = read_json(run/'manifest.json')
    rows = [json.loads(s) for s in (run/'results.jsonl').read_text(encoding='utf8').splitlines() if s.strip()]
    calls = [json.loads(s) for s in (run/'api_receipts.jsonl').read_text(encoding='utf8').splitlines() if s.strip()]
    samples = {s['idx']: s for s in manifest['samples']}
    if len(samples) != 30 or manifest['planned_results'] != 60: raise ValueError('Authorized size changed')
    for row in rows:
        sample = samples[row['idx']]
        if any(row[k] != sample[k] for k in ('target', 'cwe', 'group_id', 'source_sha256', 'sample_id')):
            raise ValueError('Result identity changed')
    first = {}
    for call in calls:
        first.setdefault((call['idx'], call['repeat']), call)
    for key, call in first.items():
        fingerprint = hashlib.sha256(json.dumps(call['request'], sort_keys=True).encode()).hexdigest()
        if fingerprint != manifest['first_request_sha256'][str(key[0])]:
            raise ValueError('Actual first request changed')
    if len(first) != 60: raise ValueError('Missing real first request')
    for name, expected in manifest['code_hashes'].items():
        if digest(Path(manifest['code_root'])/name) != expected or digest(run/'code_snapshot'/name) != expected:
            raise ValueError('Prediction source changed')
    if digest(run/'runner_snapshot.py') != manifest['runner_sha256']:
        raise ValueError('Runner snapshot changed')
    for sample in samples.values():
        if digest(sample['source_path']) != sample['wrapped_source_sha256'] or digest(Path(sample['cache_path'])/'export/export.dot') != sample['cpg_sha256']:
            raise ValueError('Graph/source hash changed')
    expected = summarize(rows, calls, manifest)
    actual = read_json(run/'report.json')
    actual.pop('frozen_code_matches')
    if actual != expected: raise ValueError('Metrics/receipt report differs from recomputation')
    return dict(passed=True, scheduled_results=len(rows), actual_invocations=len(calls),
                verified_code_files=len(manifest['code_hashes']),
                actual_first_requests_verified=len(first), new_api_calls=0,
                github_upload_eligible=expected['github_upload_eligible'],
                artifact_sha256={name: digest(run/name) for name in ('manifest.json','results.jsonl','api_receipts.jsonl','report.json')})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.run)
    destination = args.run/'audit.json'
    if destination.exists(): raise ValueError('Do not overwrite an audit')
    destination.write_text(json.dumps(result, indent=2), encoding='utf8')
    print(json.dumps(result, indent=2))
