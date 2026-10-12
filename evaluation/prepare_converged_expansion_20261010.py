"""Prepare ALL frozen admitted development rows; decode only selected JSON objects."""
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import contextlib
import io
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def sha(path):
    import hashlib
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024*1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def selected_objects(blob, wanted):
    """Skip unselected array elements as opaque bytes, never JSON-decode them."""
    i, index, found = 0, 0, set()
    while i < len(blob) and blob[i] in b' \r\n\t':
        i += 1
    if blob[i:i+1] != b'[':
        raise ValueError('Expected JSON array')
    i += 1
    while True:
        while i < len(blob) and blob[i] in b' \r\n\t':
            i += 1
        if blob[i:i+1] == b']':
            i += 1
            break
        if blob[i:i+1] != b'{':
            raise ValueError('Expected object element')
        start, depth, quoted, escaped = i, 0, False, False
        while i < len(blob):
            value = blob[i]
            if quoted:
                if escaped:
                    escaped = False
                elif value == 92:
                    escaped = True
                elif value == 34:
                    quoted = False
            elif value == 34:
                quoted = True
            elif value in (123, 91):
                depth += 1
            elif value in (125, 93):
                depth -= 1
                if depth == 0:
                    i += 1
                    break
            i += 1
        if depth != 0 or quoted:
            raise ValueError('Unterminated element')
        if index in wanted:
            found.add(index)
            yield index, json.loads(blob[start:i])
        index += 1
        while i < len(blob) and blob[i] in b' \r\n\t':
            i += 1
        if blob[i:i+1] == b',':
            i += 1
            peek = i
            while peek < len(blob) and blob[peek] in b' \r\n\t':
                peek += 1
            if blob[peek:peek+1] == b']':
                raise ValueError('Trailing comma')
        elif blob[i:i+1] != b']':
            raise ValueError('Expected array separator')
    if blob[i:].strip() or found != set(wanted):
        raise ValueError('Trailing input or missing selected indices')


def prepare_one(meta, directory):
    os.environ['JOERN_TIMEOUT_SECONDS'] = '180'
    from graph.build_cpg import build_cpg, _dot_has_func_method
    from graph.load_graph import load_graph
    from development.converged_graph_v2_candidate_20261010.minimal_features import graph_to_arrays
    import torch
    torch.set_num_threads(1)
    sample = Path(directory)/meta['sample_id']
    result = dict(meta)
    try:
        if sha(sample/'source.c') != meta['source_raw_sha256']:
            raise ValueError('Source drift')
        with contextlib.redirect_stdout(io.StringIO()):
            build_cpg(str(sample/'source.c'), str(sample))
            dot = sample/'export/export.dot'
            if not _dot_has_func_method(str(dot)):
                raise ValueError('Missing defined function body')
            graph = load_graph(str(dot))
            arrays = graph_to_arrays(graph)
        if arrays is None:
            raise ValueError('Empty graph')
        result.update(graph_nodes=len(graph), graph_edges=graph.number_of_edges(),
                      dot_sha256=sha(dot), status='prepared')
    except Exception as exc:
        result.update(status='failed', error=repr(exc))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--workers', type=int, default=2)
    parser.add_argument('--freeze-only', action='store_true')
    parser.add_argument('--resume', action='store_true')
    args = parser.parse_args()
    if args.workers != 2:
        raise ValueError('Frozen policy: two workers')
    from config import DEVIGN_JSON_PATH, JOERN_PARSE_CMD, JOERN_EXPORT_CMD
    from evaluation.build_clean_protocol import code_hash
    for path in (JOERN_PARSE_CMD, JOERN_EXPORT_CMD, DEVIGN_JSON_PATH):
        if not Path(path).is_file():
            raise FileNotFoundError(path)
    admission_path = ROOT/'output/dataset_admission_audit_20261010/report.json'
    admission = read(admission_path)
    selected = admission['eligible_manifest']
    allow_path = ROOT/'evaluation/protocol_clone_v2_20261005/development.json'
    allowed = {row['idx']: row for row in read(allow_path)}
    baseline = read(ROOT/'output/converged_minimal_gat_training_20261010/split.json')
    held_groups = set(baseline['group_membership'].values())
    if len(selected) != 2344 or len({r['idx'] for r in selected}) != 2344:
        raise ValueError('Frozen expansion scope mismatch')
    if any(row != allowed.get(row['idx']) or row['group_id'] in held_groups for row in selected):
        raise ValueError('Admission or group overlap')
    protocol = read(ROOT/'evaluation/protocol_clone_v2_20261005/audit.json')
    if sha(DEVIGN_JSON_PATH) != protocol['dataset_sha256']:
        raise ValueError('Dataset version mismatch')
    paths = [Path(__file__), ROOT/'evaluation/train_converged_expanded_20261010.py',
        ROOT/'graph/build_cpg.py', ROOT/'graph/load_graph.py', ROOT/'learning/gat_model.py',
        ROOT/'development/converged_graph_v2_candidate_20261010/minimal_features.py',
        ROOT/'evaluation/CONVERGED_EXPANSION_PROTOCOL_20261010.md',
        ROOT/'evaluation/fixtures/converged_expansion_environment.c']
    binding = dict(requested=2344, workers=2, timeout_seconds_per_phase=180,
        admission_sha256=sha(admission_path), allowlist_sha256=sha(allow_path),
        dataset_sha256=protocol['dataset_sha256'], baseline_split_sha256=sha(ROOT/'output/converged_minimal_gat_training_20261010/split.json'),
        source_hashes={str(p.relative_to(ROOT)): sha(p) for p in paths},
        tool_hashes={str(p): sha(p) for p in map(Path, (JOERN_PARSE_CMD, JOERN_EXPORT_CMD))},
        selection='ALL frozen admitted rows; no label filtering or representative sampling',
        policy='one attempt per row; resume only unattempted; no API/locked-data use')
    if args.resume:
        if read(args.output/'protocol.json') != binding or read(args.output/'manifest.json') != selected:
            raise ValueError('Frozen preparation drift')
        metadata = read(args.output/'frozen_metadata.json')
    else:
        if args.output.exists():
            raise ValueError('Refuse overwrite')
        args.output.mkdir(parents=True)
        (args.output/'manifest.json').write_text(json.dumps(selected, indent=2), encoding='utf8')
        (args.output/'protocol.json').write_text(json.dumps(binding, indent=2), encoding='utf8')
        selected_by_idx = {r['idx']: r for r in selected}
        metadata = {}
        for idx, raw in selected_objects(Path(DEVIGN_JSON_PATH).read_bytes(), set(selected_by_idx)):
            row = selected_by_idx[idx]
            if code_hash(raw['func']) != row['source_sha256'] or raw.get('project') != row['project'] or raw.get('commit_id') != row['commit_id']:
                raise ValueError('Selected source identity mismatch')
            if raw.get('target') not in (0, 1):
                raise ValueError('Invalid label')
            fid = f'sample_{idx:06d}'
            directory = args.output/fid
            directory.mkdir()
            (directory/'source.c').write_bytes(raw['func'].encode('utf8'))
            metadata[fid] = dict(row, sample_id=fid, target=int(raw['target']),
                source_raw_sha256=sha(directory/'source.c'))
        (args.output/'frozen_metadata.json').write_text(json.dumps(metadata, indent=2), encoding='utf8')
    if args.freeze_only:
        print(json.dumps(dict(frozen_rows=len(metadata), scope=2344, graphs_built=0)), flush=True)
        return
    receipts = args.output/'preparation.jsonl'
    previous = {r['sample_id']: r for r in (json.loads(line) for line in receipts.read_text(encoding='utf8').splitlines())} if receipts.exists() else {}
    pending = [m for fid, m in sorted(metadata.items()) if fid not in previous]
    with receipts.open('a', encoding='utf8') as handle, ProcessPoolExecutor(max_workers=2) as pool:
        futures = {pool.submit(prepare_one, m, str(args.output.resolve())): m for m in pending}
        for future in as_completed(futures):
            meta = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = dict(meta, status='failed', error=repr(exc))
            previous[result['sample_id']] = result
            handle.write(json.dumps(result)+'\n')
            handle.flush()
            print(json.dumps(dict(completed=len(previous), total=2344, idx=result['idx'],
                status=result['status'], error=result.get('error', '')[:200])), flush=True)
    if set(previous) != set(metadata):
        raise ValueError('Incomplete denominator')
    (args.output/'meta.json').write_text(json.dumps(previous, indent=2), encoding='utf8')
    for name, expected in binding['source_hashes'].items():
        if sha(ROOT/name) != expected:
            raise ValueError('Source changed during preparation')
    report = dict(requested=2344, completed=len(previous),
        prepared=sum(r['status']=='prepared' for r in previous.values()),
        failed=sum(r['status']=='failed' for r in previous.values()),
        protocol_sha256=sha(args.output/'protocol.json'), metadata_sha256=sha(args.output/'meta.json'),
        api_calls=0, training_started=False)
    (args.output/'report.json').write_text(json.dumps(report, indent=2), encoding='utf8')
    print(json.dumps(report), flush=True)


if __name__ == '__main__':
    main()
