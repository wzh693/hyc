"""Independent full-scope readiness audit before expanded training; no model calls."""
import contextlib
import io
import json
from pathlib import Path

from evaluation.prepare_converged_expansion_20261010 import ROOT, read, sha
from evaluation.build_clean_protocol import code_hash
from graph.build_cpg import _dot_has_func_method, _source_fingerprint
from graph.load_graph import load_graph
from development.converged_graph_v2_candidate_20261010.minimal_features import graph_to_arrays
from development.converged_graph_v2_candidate_20261010.audit_training import audit


def main():
    run = ROOT/'output/converged_expansion_cpg_20261010'
    protocol, report = read(run/'protocol.json'), read(run/'report.json')
    frozen, metadata = read(run/'frozen_metadata.json'), read(run/'meta.json')
    manifest = read(run/'manifest.json')
    baseline_run = ROOT/'output/converged_minimal_gat_training_20261010'
    original = audit(baseline_run)
    split = read(baseline_run/'split.json')
    if sha(baseline_run/'split.json') != protocol['baseline_split_sha256']:
        raise ValueError('Baseline split drift')
    if set(metadata) != set(frozen) or len(metadata) != 2344 or {r['idx'] for r in metadata.values()} != {r['idx'] for r in manifest}:
        raise ValueError('Full denominator mismatch')
    if sha(run/'protocol.json') != report['protocol_sha256'] or sha(run/'meta.json') != report['metadata_sha256']:
        raise ValueError('Preparation receipt mismatch')
    for name, expected in protocol['source_hashes'].items():
        if sha(ROOT/name) != expected:
            raise ValueError('Frozen source drift')
    for name, expected in protocol['tool_hashes'].items():
        if sha(name) != expected:
            raise ValueError('Joern launcher drift')
    held = set(split['group_membership'].values())
    prepared = failed = nodes = edges = 0
    for fid, info in metadata.items():
        if any(info.get(k) != v for k, v in frozen[fid].items()) or info['group_id'] in held:
            raise ValueError('Metadata or grouping mismatch')
        source = run/fid/'source.c'
        code = source.read_text(encoding='utf8')
        if sha(source) != info['source_raw_sha256'] or code_hash(code) != info['source_sha256']:
            raise ValueError('Source mismatch')
        if info['status'] == 'failed':
            if not info.get('error'):
                raise ValueError('Failure not explained')
            failed += 1
            continue
        if info['status'] != 'prepared':
            raise ValueError('Unknown status')
        dot = run/fid/'export/export.dot'
        if sha(dot) != info['dot_sha256'] or not _dot_has_func_method(str(dot)):
            raise ValueError('Invalid graph')
        if read(run/fid/'.hgl_cpg_cache.json')['source_fingerprint'] != _source_fingerprint(code, str(source)):
            raise ValueError('Parser/source fingerprint mismatch')
        with contextlib.redirect_stdout(io.StringIO()):
            graph = load_graph(str(dot))
        arrays = graph_to_arrays(graph)
        if arrays is None or arrays['x'].shape != (len(graph), 7) or len(graph) != info['graph_nodes'] or graph.number_of_edges() != info['graph_edges']:
            raise ValueError('Graph/feature mismatch')
        prepared += 1
        nodes += len(graph)
        edges += graph.number_of_edges()
    if prepared != report['prepared'] or failed != report['failed']:
        raise ValueError('Incorrect preparation counts')
    result = dict(pass_integrity=True, ready_for_single_training=prepared/2344 >= .9,
        requested=2344, prepared=prepared, failed=failed, nodes=nodes, edges=edges,
        baseline_audit=original, source_sha256=sha(Path(__file__)),
        protocol_sha256=sha(run/'protocol.json'), paid_api_calls=0)
    (run/'preparation_audit.json').write_text(json.dumps(result, indent=2), encoding='utf8')
    print(json.dumps(result, indent=2), flush=True)
    if not result['ready_for_single_training']:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
