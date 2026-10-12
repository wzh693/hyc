"""Read-only diagnostics: no graph rebuilding, inference, or prediction edits."""
import contextlib
import io
import json
import os
import re
from pathlib import Path
import sys
from collections import Counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from evaluation.test_graph_guided_foundation import verify_foundation


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def lines(path):
    return [json.loads(s) for s in path.read_text(encoding='utf8').splitlines()]


def main():
    receipt = verify_foundation()
    os.environ.update(receipt['settings'])
    sys.path.insert(0, str(ROOT/'development/type_coverage_reconstructed_20261008/src'))
    import networkx as nx
    from linearization.typed_paths import _slice_source, _collect_graph_anchors
    from retrieval.candidate_paths import extract_candidate_paths_from_node
    from retrieval.path_ranker import _compute_variable_lifecycle_completeness
    from graph.load_graph import load_graph_from_dot
    from evaluation.audit_graph_read_evidence import sections
    from evaluation.audit_graph_read_evidence import sha

    old_dir = ROOT/'output/graph_read_evidence_v2_20261009'
    old = {r['idx']: r for r in lines(old_dir/'rows.jsonl')}
    current = ROOT/'output/graph_window_llm1016_20261011/control'
    api = lines(current/'api_receipts.jsonl')
    first = [r for r in api if r['step'] == 1]
    # Some runners number the initial step zero; require exactly two per sample.
    if len(first) != 508:
        initial = min(r['step'] for r in api)
        first = [r for r in api if r['step'] == initial]
    matches = []
    for r in first:
        content = r['request']['messages'][-1]['content']
        src, dep = sections(content)
        matches.append(src == old[r['idx']]['src'] and dep == old[r['idx']]['dep'])
    assert len(first) == 508 and len({r['idx'] for r in first}) == 254
    assert all(matches), 'Historical audit differs from actual current inputs'
    manifest = read(ROOT/'output/sven_complete_src_eval_20261008/manifest.json')
    health = []
    for sample in manifest['samples']:
        directory = Path(sample['cache_path'])
        dots = list(directory.rglob('export.dot'))
        assert len(dots) == 1, (sample['idx'], dots)
        assert sha(dots[0]) == sample['cpg_sha256']
        assert sha(Path(sample['source_path'])) == sample['wrapped_source_sha256']
        with contextlib.redirect_stdout(io.StringIO()):
            graph = load_graph_from_dot(str(dots[0]))
        types = Counter(a.get('node_type') for _, a in graph.nodes(data=True))
        health.append(dict(idx=sample['idx'], nodes=len(graph), edges=graph.number_of_edges(),
                           calls=types['CALL'], returns=types['RETURN']))

    display_bodies = []
    duplicate_display_rows = 0
    for row in old.values():
        parts = re.split(r'(?:^|\n)P\d+(?: \[[^\n]*\])?: ', row['dep'])[1:]
        display_bodies.extend(p.strip() for p in parts)
        duplicate_display_rows += len(set(parts)) < len(parts)

    synthetic = {}
    source = 'int f(char *p) {\n int n;\n n = 7;\n n++;\n *p = 1;\n return n;\n}'
    sliced = _slice_source(source, max_chars=1000)
    synthetic['ordinary_assignment_missing'] = 'n = 7;' not in sliced
    synthetic['increment_missing'] = 'n++;' not in sliced
    synthetic['leading_deref_missing'] = '*p = 1;' not in sliced
    synthetic['slice_output'] = sliced
    graph = nx.MultiDiGraph()
    graph.add_node('1', code='p[index]', node_type='CALL')
    graph.add_node('2', code='length = count', node_type='CALL')
    synthetic['topk_does_not_change_anchors'] = (_collect_graph_anchors(graph, [['1']]) ==
                                               _collect_graph_anchors(graph, []))
    for n in range(4):
        graph.add_node(str(n), code='x', node_type='CALL')
    for n in range(3):
        graph.add_edge(str(n), str(n+1), edge_type='DFG')
    paths = extract_candidate_paths_from_node(graph, '0', max_hop=1)
    synthetic['max_hop_1_actual_max_edges'] = max(len(p)-1 for p in paths)
    unrelated = nx.MultiDiGraph()
    unrelated.add_node('free', code='free(a)', node_type='CALL')
    unrelated.add_node('use', code='printf("%s", b)', node_type='CALL')
    unrelated.add_edge('free', 'use', edge_type='CFG')
    synthetic['unrelated_variables_lifecycle_score'] = _compute_variable_lifecycle_completeness(unrelated, ['free', 'use'])
    assert all(synthetic[k] for k in ('ordinary_assignment_missing', 'increment_missing',
               'leading_deref_missing', 'topk_does_not_change_anchors'))
    assert synthetic['max_hop_1_actual_max_edges'] == 2
    output = dict(scope='full 254 exposed SVEN rows; diagnosis only; zero API calls',
                  foundation_files_verified=len(receipt['code_hashes']),
                  actual_first_requests=len(first), src_dep_matches=sum(matches),
                  cpg_hashes_verified=len(health),
                  graphs_without_calls=[r for r in health if not r['calls']],
                  synthetic=synthetic, audit_summary=read(old_dir/'report.json')['summaries']['all'],
                  graph_health=health,
                  displayed_path_strings=len(display_bodies),
                  definitely_cut_path_strings=sum(not p.endswith(']') for p in display_bodies),
                  identical_display_rows=duplicate_display_rows,
                  api_length_finishes=sum(r.get('finish_reason') == 'length' for r in api),
                  limits='Lexical survival is not semantic validity or detection accuracy; repeated sources are not independent.')
    destination = ROOT/'output/foundation_four_stage_diagnosis_v2_20261011.json'
    if destination.exists():
        raise ValueError('Never overwrite a diagnostic receipt')
    destination.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding='utf8')
    compact = {k: v for k, v in output.items() if k not in ('graph_health', 'audit_summary')}
    print(json.dumps(compact, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
