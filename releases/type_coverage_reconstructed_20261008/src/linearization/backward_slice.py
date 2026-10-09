"""Bounded dependence slicing. CFG reachability is not control dependence."""
import re
from collections import deque
from config import DANGEROUS_APIS

DEPENDENCE_EDGES = {'REACHING_DEF', 'DFG', 'CDG', 'CONTROL_DEPENDENCE'}
_CALL = re.compile(r'\b(' + '|'.join(map(re.escape, sorted(DANGEROUS_APIS))) + r')\s*\(')


def backward_evidence_slice(graph, paths, source, *, line_offset=0, max_chars=600,
                            max_nodes=2048):
    """Return whole source lines and an explicit coverage/budget receipt.

    Joern line numbers refer to its input file; callers must provide the exact
    prefix offset when a function was wrapped. No textual rematching of nodes.
    Missing criteria/locations cause fallback, never invented evidence.
    """
    criteria = []
    for path in paths:
        for node in path:
            attrs = graph.nodes.get(node, {})
            name = attrs.get('name', '')
            if (_CALL.search(attrs.get('code', '') or '') or
                    name in {'<operator>.indirection', '<operator>.indexAccess',
                             '<operator>.indirectIndexAccess', '<operator>.indirectFieldAccess'}):
                if node not in criteria:
                    criteria.append(node)
    seen = set(criteria)
    queue = deque(criteria)
    edge_counts = {}
    capped = len(seen) > max_nodes
    while queue and not capped:
        node = queue.popleft()
        for pred, _, data in graph.in_edges(node, data=True):
            kind = data.get('edge_type', '')
            if kind not in DEPENDENCE_EDGES:
                continue
            edge_counts[kind] = edge_counts.get(kind, 0) + 1
            if pred not in seen:
                if len(seen) >= max_nodes:
                    capped = True
                    break
                seen.add(pred)
                queue.append(pred)
    lines = source.splitlines()
    selected, unmapped = set(), 0
    for node in seen:
        try:
            line = int(graph.nodes[node].get('line_number')) - line_offset
        except (TypeError, ValueError):
            unmapped += 1
            continue
        if 1 <= line <= len(lines):
            selected.add(line)
        else:
            unmapped += 1
    # Prioritize the actual criterion lines, then dependencies; render source order.
    criterion_lines = set()
    for node in criteria:
        try:
            criterion_lines.add(int(graph.nodes[node].get('line_number')) - line_offset)
        except (TypeError, ValueError):
            pass
    kept, size = [], 0
    for line in sorted(selected, key=lambda n: (n not in criterion_lines, n)):
        cost = len(lines[line - 1]) + (1 if kept else 0)
        if size + cost <= max_chars:
            kept.append(line)
            size += cost
    text = '\n'.join(lines[n - 1] for n in sorted(kept))
    return text, {'enabled': True, 'criteria': len(criteria), 'visited_nodes': len(seen),
                  'dependence_edges': edge_counts, 'unmapped_nodes': unmapped,
                  'source_lines': sorted(kept), 'omitted_lines': len(selected) - len(kept),
                  'node_cap_hit': capped, 'char_budget': max_chars,
                  'fallback': not bool(text), 'control_dependence_available':
                  any(d.get('edge_type') in {'CDG', 'CONTROL_DEPENDENCE'}
                      for _, _, d in graph.edges(data=True))}
