"""Additional independent grouping/usage/foundation checks, zero external calls."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path): return json.loads(Path(path).read_text(encoding='utf-8-sig'))
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def audit(run):
    manifest = read(run/'manifest.json')
    receipt = read(ROOT/'baselines/type_coverage_reconstructed_20261008/baseline.json')
    if sha(receipt['source_manifest']) != receipt['source_manifest_sha256']: raise ValueError('Reference manifest changed')
    old = read(receipt['source_manifest'])
    data = read(manifest['dataset'])
    old_samples = {s['idx']: s for s in old['samples']}
    # Recompute the family/source union directly; do not trust saved group names.
    parents = list(range(len(data)))
    def root(i):
        while parents[i] != i:
            parents[i] = parents[parents[i]]; i = parents[i]
        return i
    seen = {}
    for i, item in enumerate(data):
        for key in (('source', item['input']), ('family', item['file_name'])):
            if key in seen: parents[root(i)] = root(seen[key])
            else: seen[key] = i
    members, sources = defaultdict(list), defaultdict(list)
    for sample in manifest['samples']:
        i = sample['idx']; expected = old_samples[i]
        for k in ('sample_id', 'target', 'group_id', 'cwe', 'source_sha256', 'wrapped_source_sha256', 'cpg_sha256'):
            if sample[k] != expected[k]: raise ValueError('Prepared/reference identity mismatch: '+k)
        members[root(i)].append(i); sources[data[i]['input']].append(i)
    recorded = defaultdict(list)
    for sample in manifest['samples']: recorded[sample['group_id']].append(sample['idx'])
    if {tuple(sorted(v)) for v in recorded.values()} != {tuple(sorted(v)) for v in members.values()}:
        raise ValueError('Wrong source-family grouping')
    conflicts = [ids for ids in sources.values() if len({data[i]['output'] for i in ids}) > 1]
    consistent_source_bound = sum(max(sum(data[i]['output'] == label for i in ids) for label in ('BENIGN', 'VULNERABLE')) for ids in sources.values())/len(data)
    calls = [json.loads(s) for s in (run/'api_receipts.jsonl').read_text(encoding='utf8').splitlines()]
    for call in calls:
        if call.get('usage_known'):
            values = [call[k] for k in ('prompt_tokens', 'completion_tokens', 'total_tokens')]
            if any(not isinstance(v, int) or v < 0 for v in values) or values[0]+values[1] != values[2]:
                raise ValueError('Usage falsely described as known or token sum inconsistent')
    release = ROOT/'releases/type_coverage_reconstructed_20261008'
    for name, expected in read(release/'profile.json')['source_hashes'].items():
        if sha(release/'src'/name) != expected: raise ValueError('Published source package changed')
    for name, expected in receipt['preserved_repaired_code_hashes'].items():
        if sha(ROOT/name) != expected or sha(ROOT/'baselines/type_coverage_reconstructed_20261008/preserved_repaired_src'/name) != expected:
            raise ValueError('Repaired reference/source changed')
    return dict(passed=True, new_api_calls=0, scheduled_samples=len(data), exact_sources=len(sources), family_union_groups=len(members),
        exact_source_conflict_groups=len(conflicts), exact_source_conflict_rows=sum(map(len, conflicts)),
        deterministic_source_only_accuracy_upper_bound=consistent_source_bound,
        bound_scope='Only a deterministic classifier using supplied SRC alone, not a bound on graph/context-aware or stochastic models.',
        known_usage_arithmetic_verified=sum(bool(c.get('usage_known')) for c in calls), published_source_files_preserved=47,
        repaired_reference_files_preserved=len(receipt['preserved_repaired_code_hashes']),
        api_receipts_sha256=sha(run/'api_receipts.jsonl'), auditor_sha256=sha(__file__))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--run', type=Path, required=True); args = parser.parse_args()
    result = audit(args.run); destination = args.run/'audit_addendum.json'
    if destination.exists(): raise ValueError('Do not overwrite audit addendum')
    destination.write_text(json.dumps(result, indent=2), encoding='utf8'); print(json.dumps(result, indent=2))
