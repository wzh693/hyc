"""Display-first, whole-unit evidence. No model, label, or API vocabulary."""
from collections import deque
import json

DEPENDENCIES = frozenset({'DFG', 'REACHING_DEF', 'CDG', 'CONTROL_DEPENDENCE'})


def pack_whole_paths(graph, paths, budget=1000):
    units, displayed, omitted = [], [], []
    for path in paths:
        if not path or any(n not in graph for n in path):
            raise ValueError('Path node missing from its source graph')
        nodes = []
        for i, node in enumerate(path):
            attrs = graph.nodes[node]
            edges = []
            if i:
                data = graph.get_edge_data(path[i-1], node)
                if not data:
                    raise ValueError('Path edge missing from its source graph')
                edges = sorted({a.get('edge_type', 'OTHER') for a in data.values()})
            nodes.append(dict(id=str(node), c=attrs.get('code') or '',
                              l=attrs.get('line_number'), e=edges))
        unit = json.dumps(nodes, ensure_ascii=False, separators=(',', ':'))
        if len('\n'.join(units + [unit])) <= budget:
            units.append(unit)
            displayed.append(list(path))
        else:
            omitted.append(list(map(str, path)))
    return '\n'.join(units), displayed, omitted


def pack_paths(graph, paths, budget=1000):
    text, displayed, omitted = pack_whole_paths(graph, paths, budget)
    if displayed:
        return text, displayed, omitted
    # Only repair an otherwise EMPTY display. Preserve all previously feasible
    # rows byte-for-byte. Respect existing Top-K order; do not score new paths.
    for rank, path in enumerate(paths):
        # Prefer the longest contiguous feasible window, then closest to the
        # original endpoint. No added nodes/edges; single-node windows allowed.
        for size in range(len(path)-1, 0, -1):
            for end in range(len(path), size-1, -1):
                start = end-size
                window = path[start:end]
                unit, shown, _ = pack_whole_paths(graph, [window], budget)
                if not shown:
                    continue
                value = json.loads(unit)
                # Explicit provenance in actual model input, not only audit.
                value[0]['w'] = [rank, start, end, len(path)]
                unit = json.dumps(value, ensure_ascii=False, separators=(',', ':'))
                if len(unit) <= budget:
                    return unit, [list(window)], omitted
    return text, displayed, omitted


def window_receipts(paths, displayed):
    result = []
    for window in displayed:
        exact = [rank for rank,path in enumerate(paths) if list(path) == list(window)]
        ordered = exact or range(len(paths))
        for rank in ordered:
            path = paths[rank]
            positions = [start for start in range(len(path)-len(window)+1)
                         if list(path[start:start+len(window)]) == list(window)]
            if positions:
                start = max(positions)
                result.append(dict(topk_rank=rank, start=start, end=start+len(window),
                    original_nodes=len(path), window_nodes=list(map(str, window)),
                    partial=len(window) != len(path)))
                break
        else:
            raise ValueError('Displayed window is not contiguous in original Top-K')
    return result


def aligned_slice(original, displayed, source, offset=0, budget=600, node_cap=2048):
    # All displayed nodes are criteria, including intermediate length updates.
    # CFG reachability is NOT control dependence; traverse only real PDG edges.
    criteria = list(dict.fromkeys(n for path in displayed for n in path))
    if any(n not in original for n in criteria):
        raise ValueError('Displayed criteria missing from original graph')
    if len(criteria) > node_cap:
        raise ValueError('Criteria exceed slicing cap')
    distances = {n: 0 for n in criteria}
    queue, witnesses, capped = deque(criteria), [], False
    while queue:
        node = queue.popleft()
        for pred, _, attrs in sorted(original.in_edges(node, data=True),
                                    key=lambda e: (str(e[0]), str(e[2].get('edge_type')))):
            kind = attrs.get('edge_type')
            if kind not in DEPENDENCIES:
                continue
            if pred not in distances:
                if len(distances) >= node_cap:
                    capped = True
                    continue
                distances[pred] = distances[node] + 1
                queue.append(pred)
            witnesses.append([str(pred), str(node), kind])
    lines, priority, unmapped = source.splitlines(), {}, []
    for node, distance in distances.items():
        try:
            line = int(original.nodes[node].get('line_number')) - offset
        except (ValueError, TypeError):
            line = 0
        if not 1 <= line <= len(lines):
            unmapped.append(str(node))
            continue
        priority[line] = min(priority.get(line, (distance, line)), (distance, line))
    kept, size = [], 0
    for line in sorted(priority, key=priority.get):
        cost = len(lines[line-1]) + bool(kept)
        if size + cost <= budget:
            kept.append(line)
            size += cost
    kept.sort()
    text = '\n'.join(lines[n-1] for n in kept)
    return text, dict(enabled=True, criteria_node_ids=list(map(str, criteria)),
        visited_node_ids=sorted(map(str, distances)), dependence_witnesses=witnesses,
        source_lines=kept, omitted_lines=len(priority)-len(kept), unmapped_nodes=unmapped,
        node_cap_hit=capped, char_budget=budget, fallback=False,
        source_origin='original_graph_dependence_closure')
