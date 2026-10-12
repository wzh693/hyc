"""Metadata-only local dataset admission audit. No source corpus or locked rows loaded."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path

from evaluation.build_clean_protocol import inventory_exposure
from development.converged_graph_v2_candidate_20261010.train_minimal_gat import ROOT, read, sha


def sink_summary(sinks, function_keys):
    grouped = defaultdict(list)
    reasons = Counter()
    for row in sinks:
        label = row.get('label')
        if label not in (0, 1):
            raise ValueError('Invalid sink label')
        key = (row['patch_id'], row['version'])
        grouped[key].append(label)
        reasons[row.get('sink_reason', '')] += 1
    keys = set(grouped) | set(function_keys)
    versions = {}
    for version in sorted({key[1] for key in keys}):
        subset = [key for key in keys if key[1] == version]
        versions[version] = dict(metadata_sample_keys=len(subset),
            keys_with_sinks=sum(key in grouped for key in subset),
            loader_derived_positive=sum(1 in grouped.get(key, []) for key in subset),
            loader_derived_negative=sum(1 not in grouped.get(key, []) for key in subset))
    return dict(sink_rows=sum(reasons.values()), versions=versions,
                sink_reasons=dict(reasons),
                metadata_keys_without_sink=sum(key not in grouped for key in keys),
                patches=len({key[0] for key in keys}))


def read_lines(path):
    with path.open(encoding='utf-8-sig') as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('Refuse overwrite')
    development_path = ROOT/'evaluation/protocol_clone_v2_20261005/development.json'
    development = read(development_path)
    protocol = read(ROOT/'evaluation/protocol_clone_v2_20261005/audit.json')
    split = read(ROOT/'output/converged_minimal_gat_training_20261010/split.json')
    exposed, hashes, artifacts = inventory_exposure(ROOT, protocol['n_raw'], read_sources=False)
    excluded_groups = {row['group_id'] for row in development
                       if row['idx'] in exposed or row['source_sha256'] in hashes}
    # Explicitly preserve every training/selection/calibration group, even if a
    # future exposure-inventory implementation misses a new result directory.
    excluded_groups.update(split['group_membership'].values())
    eligible = [row for row in development if row['group_id'] not in excluded_groups]
    cross_dir = ROOT.parents[1]/'vuln-dataset-main'
    sources = {str(development_path.relative_to(ROOT)): sha(development_path)}
    cross = dict(present=cross_dir.is_dir(), admission='blocked_pending_label_and_provenance_audit')
    if cross_dir.is_dir():
        functions = list(read_lines(cross_dir/'functions.jsonl'))
        keys = {(row['patch_id'], row['version']) for row in functions}
        cross.update(sink_summary(read_lines(cross_dir/'sinks.jsonl'), keys))
        cross['manifest'] = read(cross_dir/'manifest.json')
        cross['file_sizes'] = {p.name: p.stat().st_size for p in cross_dir.iterdir() if p.is_file()}
        cross['metadata_sha256'] = {name: sha(cross_dir/name)
            for name in ('functions.jsonl', 'sinks.jsonl', 'manifest.json')}
        cross['limits'] = ('Metadata keys are NOT verified full graph/sample counts. '
            'No independent function labels or clone checks; fixed/vulnerable versions must stay grouped. '
            'The existing loader derives function labels from any positive sink, '
            'and reconstructs source by node-ID order; do not treat as verified original source.')
    report = dict(development_total_rows=len(development),
        development_total_groups=len({r['group_id'] for r in development}),
        remaining_not_recorded_exposed_rows=len(eligible),
        remaining_not_recorded_exposed_groups=len({r['group_id'] for r in eligible}),
        eligible_manifest=eligible, excluded_development_groups=len(excluded_groups),
        prior_group_count=len(set(split['group_membership'].values())),
        exposure_artifacts=artifacts, source_hashes=sources, cross_function=cross,
        devign_raw_file_present=(ROOT.parents[1]/'devign/function.json').is_file(),
        sven_role='development replay only; not GAT training or independent test',
        external_candidates=[dict(name=name, local_status='not_found_in_inspected_locations',
            url=url, imported=False) for name, url in (
            ('PrimeVul', 'https://github.com/DLVulDet/PrimeVul'),
            ('DiverseVul', 'https://github.com/wagner-group/diversevul'),
            ('BigVul', 'https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset'))],
        paid_api_calls=0, raw_function_corpus_loaded=False, locked_or_validation_manifest_loaded=False,
        limitations='Unrecorded exposure remains unknown. Metadata inventory is not a training dataset '
        'or cross-dataset clone-isolation certificate. No new CPGs or external datasets downloaded.')
    args.output.mkdir(parents=True)
    (args.output/'report.json').write_text(json.dumps(report, indent=2), encoding='utf8')
    print(json.dumps({k: v for k, v in report.items() if k not in
                      ('eligible_manifest', 'exposure_artifacts')}, indent=2))


if __name__ == '__main__':
    main()
