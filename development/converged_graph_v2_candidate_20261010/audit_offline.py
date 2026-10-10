"""Read-only graph/source reconstruction audit for every preflight row."""
import argparse
import contextlib
import io
import json
from pathlib import Path
from .run_offline import ROOT, read, sha


def audit(directory):
    manifest, report = read(directory/'manifest.json'), read(directory/'report.json')
    for name, expected in manifest['source_tool_hashes'].items():
        if sha(ROOT/name) != expected:
            raise ValueError('Source/tool drift: '+name)
    old = read(ROOT/'output/sven_complete_src_eval_20261008/manifest.json')
    if sha(old['dataset']) != manifest['dataset_sha256']:
        raise ValueError('Dataset drift')
    dataset = read(old['dataset'])
    samples = {s['idx']: s for s in old['samples']}
    rows = [json.loads(line) for line in (directory/'candidate_rows.jsonl').read_text(encoding='utf8').splitlines()]
    controls = [json.loads(line) for line in (directory/'control/rows.jsonl').read_text(encoding='utf8').splitlines()]
    if len(rows) != 254 or len(controls) != 254 or any({r['idx'] for r in part} != set(range(254)) for part in (rows, controls)):
        raise ValueError('Full paired scope missing')
    if not report['pass'] or any(r.get('error') for r in rows + controls):
        raise ValueError('Failed rows must remain failed')
    from graph.load_graph import load_graph
    from linearization.source_mapping import source_line_offset
    verified_paths = verified_lines = 0
    for row in rows:
        sample = samples[row['idx']]
        dot = Path(sample['cache_path'])/'export/export.dot'
        if sha(dot) != sample['cpg_sha256']:
            raise ValueError('Graph drift')
        with contextlib.redirect_stdout(io.StringIO()):
            graph = load_graph(str(dot))
        node_of = {str(n): n for n in graph}
        result, source = row['result'], dataset[row['idx']]['input']
        if sha(sample['source_path']) != sample['wrapped_source_sha256']:
            raise ValueError('Wrapped source drift')
        offset = source_line_offset(source, Path(sample['source_path']).read_text(encoding='utf8'))
        compressed = result['compression']
        kept = compressed['kept_node_ids']
        if not set(kept) <= set(node_of) or not set(compressed['force_kept']) <= set(kept):
            raise ValueError('Unknown/lost force-keep nodes')
        if len(kept) != compressed['kept_nodes'] or compressed['estimated_tokens'] > manifest['settings']['graph_budget']:
            raise ValueError('Compression budget violation')
        for path in result['topk']:
            if not set(path) <= set(kept):
                raise ValueError('Path escaped compressed graph')
            if any(not graph.has_edge(node_of[a], node_of[b]) for a, b in zip(path, path[1:])):
                raise ValueError('Invented path edge')
        trace = result['trace']
        if len(trace) != 1 or result['main_pred'] is not None or result['final_pred'] is not None:
            raise ValueError('Fixture accidentally interpreted as quality output')
        request = trace[0]['request']
        prompt = request['messages'][1]['content']
        src, rest = prompt.removeprefix('SRC:\n').split('\n\nPATHS:\n', 1)
        paths, state = rest.split('\n\nSTATE:\n', 1)
        evidence = trace[0]['evidence']
        lines = source.splitlines()
        if src != '\n'.join(lines[i-1] for i in evidence['source_lines']):
            raise ValueError('Source evidence not exact source lines')
        verified_lines += len(evidence['source_lines'])
        parsed = [json.loads(line) for line in paths.splitlines()]
        if [[n['id'] for n in path] for path in parsed] != evidence['displayed_paths']:
            raise ValueError('Receipt differs from actual request')
        for path in parsed:
            ids = [n['id'] for n in path]
            if ids not in result['topk']:
                raise ValueError('Displayed unselected path')
            for i, item in enumerate(path):
                attrs = graph.nodes[node_of[item['id']]]
                if item['c'] != (attrs.get('code') or '') or item['l'] != attrs.get('line_number'):
                    raise ValueError('Node text/location clipped or invented')
                actual = sorted({attrs.get('edge_type', 'OTHER') for attrs in
                    graph.get_edge_data(node_of[ids[i-1]], node_of[ids[i]], default={}).values()}) if i else []
                if item['e'] != actual:
                    raise ValueError('Invented edge type')
            verified_paths += 1
        # Independently reconstruct reverse dependence closure on the ORIGINAL
        # graph: no AST/CFG reachability substituted for control dependence.
        dependencies = {'DFG', 'REACHING_DEF', 'CDG', 'CONTROL_DEPENDENCE'}
        criteria = evidence['criteria_node_ids']
        if not set(criteria) <= set(result['selected_criteria']):
            raise ValueError('Slice criterion not selected by shared score')
        if any(n not in node_of for n in criteria):
            raise ValueError('Unknown criterion')
        reachable, pending = set(criteria), list(criteria)
        while pending:
            target = pending.pop()
            for pred, _, attrs in graph.in_edges(node_of[target], data=True):
                name = str(pred)
                if attrs.get('edge_type') in dependencies and name not in reachable:
                    reachable.add(name)
                    pending.append(name)
        visited = set(evidence['visited_node_ids'])
        if not visited <= reachable:
            raise ValueError('Slice contains unrelated nodes')
        if not evidence['node_cap_hit'] and visited != reachable:
            raise ValueError('Slice dropped reachable dependence')
        eligible_lines = set()
        for node in visited:
            try:
                line = int(graph.nodes[node_of[node]].get('line_number')) - offset
            except (TypeError, ValueError):
                continue
            if 1 <= line <= len(lines):
                eligible_lines.add(line)
        if not set(evidence['source_lines']) <= eligible_lines:
            raise ValueError('Unrelated source line in slice')
        for start, end, kind in evidence['dependence_witnesses']:
            actual = graph.get_edge_data(node_of[start], node_of[end], default={})
            if kind not in dependencies or not any(attrs.get('edge_type') == kind for attrs in actual.values()):
                raise ValueError('Invented dependence witness')
        if (len(src) > manifest['settings']['source_chars'] or
                len(paths) > manifest['settings']['path_chars'] or
                len(state) > manifest['settings']['state_chars'] or
                request['max_tokens'] != 150 or result['security_net']['mode'] != 'shadow'):
            raise ValueError('Budget/net scope violation')
    return dict(pass_audit=True, paired_rows=508, candidate_requests=254,
                verified_paths=verified_paths, verified_source_lines=verified_lines,
                paid_api_calls=0, detection_quality_claim=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True, type=Path)
    print(json.dumps(audit(parser.parse_args().run), indent=2))
