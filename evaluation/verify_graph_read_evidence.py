"""Independent saved-request/denominator/count verification; no prediction imports."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGES = ('original', 'compressed', 'path_graph', 'candidate_paths', 'topk', 'displayed_path_nodes', 'src_exact', 'dep_exact')


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify(run):
    report = read(run/'report.json')
    rows = [json.loads(s) for s in (run/'rows.jsonl').read_text(encoding='utf8').splitlines()]
    if len(rows) != 254 or {r['idx'] for r in rows} != set(range(254)):
        raise ValueError('Not the full unique scheduled denominator')
    if report['scope'] != 'all exposed SVEN rows' or set(report['scheduled_indices']) != set(range(254)):
        raise ValueError('Scope disagrees with rows')
    if report['rows_sha256'] != sha(run/'rows.jsonl') or report['audit_tool_sha256'] != sha(ROOT/'evaluation/audit_graph_read_evidence.py'):
        raise ValueError('Rows or current audit tool changed')
    historical = ROOT/'output/sven_complete_src_eval_20261008'
    manifest = read(historical/'manifest.json')
    if report['source_manifest_sha256'] != sha(historical/'manifest.json'):
        raise ValueError('Referenced manifest changed')
    for name, digest in read(historical/'audit.json')['artifact_sha256'].items():
        if sha(historical/name) != digest: raise ValueError('Historical experiment changed')
    if sha(historical/'api_receipts.jsonl') != read(historical/'audit_addendum.json')['api_receipts_sha256']:
        raise ValueError('Saved receipts changed')
    samples = {r['idx']: r for r in manifest['samples']}
    first = {}
    for line in (historical/'api_receipts.jsonl').read_text(encoding='utf8').splitlines():
        call = json.loads(line)
        if call['profile'] == 'control': first.setdefault((call['idx'], call['repeat']), call['request'])
    requests_verified = 0
    for row in rows:
        if row.get('error'): raise ValueError('Audit error retained; not a complete passing audit')
        for key in ('source_sha256', 'group_id', 'cwe'):
            if row[key] != samples[row['idx']][key]: raise ValueError('Row identity drift')
        for repeat in (1, 2):
            text = first[row['idx'], repeat]['messages'][1]['content']
            start = text.index('SRC:\n')+5; end = text.index('\n\nDEP PATHS:\n', start)
            dep_start = end+len('\n\nDEP PATHS:\n'); dep_end = text.index('\n\nSTATE:', dep_start)
            if text[start:end] != row['src'] or text[dep_start:dep_end] != row['dep']:
                raise ValueError('Generated SRC/DEP does not match actual saved control')
            requests_verified += 1
    for scope, expected in report['summaries'].items():
        selected = rows if scope == 'all' else [r for r in rows if r['cwe'] == scope]
        if expected['scheduled_rows'] != len(selected) or expected['failed_rows'] != 0:
            raise ValueError('Wrong summary denominator')
        for category in ('reads', 'updates', 'guards'):
            values = [v for row in selected for v in row[category]]
            for stage in STAGES:
                if any(type(v['survival'][stage]) is not bool for v in values): raise ValueError('Nonboolean stage evidence')
                if expected[category+'_stage_presence'][stage] != len([v for v in values if v['survival'][stage]]):
                    raise ValueError('Stage-count arithmetic mismatch')
        for unit in ('source_sha256', 'group_id'):
            grouped = defaultdict(list)
            for row in selected: grouped[row[unit]].append(row)
            for stage in ('src_exact', 'dep_exact', 'topk'):
                means = []
                for members in grouped.values():
                    fractions = [len([v for v in r['reads'] if v['survival'][stage]])/len(r['reads']) for r in members if r['reads']]
                    if fractions: means.append(sum(fractions)/len(fractions))
                observed = expected[unit+'_macro'][stage]
                if (observed['eligible_units'], observed['total_units']) != (len(means), len(grouped)):
                    raise ValueError('Wrong macro denominator')
                value = sum(means)/len(means) if means else None
                if observed['mean_read_candidate_presence'] != value: raise ValueError('Wrong macro arithmetic')
    if len({r['source_sha256'] for r in rows}) != 74 or len({r['group_id'] for r in rows}) != 36:
        raise ValueError('Unique-source/family denominator changed')
    receipt = read(ROOT/'baselines/type_coverage_reconstructed_20261008/baseline.json')
    for root, hashes in [(ROOT/'development/type_coverage_reconstructed_20261008/src', receipt['code_hashes']),
                         (Path(receipt['frozen_source']), receipt['code_hashes']), (ROOT, receipt['preserved_repaired_code_hashes']),
                         (ROOT/'baselines/type_coverage_reconstructed_20261008/preserved_repaired_src', receipt['preserved_repaired_code_hashes'])]:
        for name, digest in hashes.items():
            if sha(root/name) != digest: raise ValueError('Prediction source/reference changed')
    release = ROOT/'releases/type_coverage_reconstructed_20261008'
    for name, digest in read(release/'profile.json')['source_hashes'].items():
        if sha(release/'src'/name) != digest: raise ValueError('Published source changed')
    if report['new_api_calls'] != 0 or report['blocked_external_attempts'] != 0 or any(report['shard_exit_codes']):
        raise ValueError('Offline safety or shard failure')
    return dict(passed=True, scheduled_rows=254, actual_control_request_sections_verified=requests_verified,
                exact_sources=74, family_groups=36, source_files_verified=47, repaired_reference_files_verified=52,
                published_source_files_verified=47, new_api_calls=0,
                report_sha256=sha(run/'report.json'), rows_sha256=sha(run/'rows.jsonl'), verifier_sha256=sha(__file__),
                limitation='Independently verifies identities/counts/request sections, not truth of lexical candidates, graph dominance or detection quality.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--run', required=True, type=Path); args = parser.parse_args()
    result = verify(args.run)
    destination = args.run/'verification.json'
    if destination.exists(): raise ValueError('Do not overwrite verification')
    destination.write_text(json.dumps(result, indent=2), encoding='utf8')
    print(json.dumps(result, indent=2))
