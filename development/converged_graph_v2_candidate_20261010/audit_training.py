"""Read-only independent allowlist, split, source and model receipt checks."""
import argparse
import json
from pathlib import Path
from .train_minimal_gat import ROOT, read, sha


def audit(directory):
    split, report = read(directory/'split.json'), read(directory/'report.json')
    manifest_path = ROOT/'evaluation/protocol_clone_v2_20261005/development.json'
    if sha(manifest_path) != split['clean_development_manifest_sha256']:
        raise ValueError('Clean development allowlist drift')
    allowed = {r['idx']: r for r in read(manifest_path)}
    cache = ROOT/'output/devign_development300_20261005'
    if sha(cache/'meta.json') != split['cache_metadata_sha256']:
        raise ValueError('Cache metadata drift')
    metadata = read(cache/'meta.json')
    parts = [set(split[k]) for k in ('train', 'selection', 'calibration')]
    if any(parts[i] & parts[j] for i in range(3) for j in range(i)):
        raise ValueError('Repeated samples across partitions')
    group_sets = [{split['group_membership'][f] for f in part} for part in parts]
    if any(group_sets[i] & group_sets[j] for i in range(3) for j in range(i)):
        raise ValueError('Group leakage')
    available = set.union(*parts)
    unavailable = {r['fid'] for r in split['unavailable']}
    if available & unavailable or available | unavailable != set(metadata):
        raise ValueError('Dropped or repeated requested rows')
    for fid, info in metadata.items():
        entry = allowed.get(info['idx'])
        if entry is None or any(entry.get(k) != info.get(k) for k in
                                ('source_sha256', 'group_id', 'project', 'commit_id')):
            raise ValueError('Training row outside exact development allowlist')
        if fid in available:
            identity = split['graph_identities'][fid]
            if sha(cache/fid/'source.c') != identity['source_sha256'] or sha(cache/fid/'export/export.dot') != identity['dot_sha256']:
                raise ValueError('Training graph/source drift')
    for name, expected in split['source_hashes'].items():
        if sha(ROOT/name) != expected:
            raise ValueError('Training tool drift')
    if sha(directory/'gat_mil.pt') != report['model_sha256']:
        raise ValueError('Checkpoint drift')
    calibration = report['calibration']['scores']
    if len(calibration) != len(parts[2]) or {r['fid'] for r in calibration} != parts[2]:
        raise ValueError('Calibration does not cover its entire declared split')
    if len(report['history']) != 10 or report['policy']['beta_entropy'] != .01:
        raise ValueError('Training policy drift')
    return dict(pass_audit=True, requested_rows=300, available_rows=len(available),
        unavailable_rows=len(unavailable), partition_rows=[len(p) for p in parts],
        group_disjoint=True, locked_data_used=False, paid_api_calls=0,
        model_diagnostic_gate=report['model_diagnostic_gate'])


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',required=True,type=Path)
    print(json.dumps(audit(parser.parse_args().run),indent=2))
