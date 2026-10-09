"""Bounded dependence slicing. CFG reachability is not control dependence."""
import re
from collections import deque
from config import DANGEROUS_APIS

DEPENDENCE_EDGES = {'REACHING_DEF', 'DFG', 'CDG', 'CONTROL_DEPENDENCE'}
_CALL = re.compile(r'\b(' + '|'.join(map(re.escape, sorted(DANGEROUS_APIS))) + r')\s*\(')


def backward_evidence_slice(graph, paths, source, *, line_offset=0, max_chars=600,
                            max_nodes=2048, atomic_groups=False):
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
    group_audit = {'enabled': False}
    if atomic_groups and kept:
        from linearization.evidence_groups import pack_evidence_groups
        kept, group_audit = pack_evidence_groups(graph, criteria, source, kept,
            line_offset=line_offset, max_chars=max_chars, max_nodes=max_nodes)
        selected |= {n for group in group_audit['groups'] for n in group['source_lines']}
    text = '\n'.join(lines[n - 1] for n in sorted(kept))
    audit = {'enabled': True, 'criteria': len(criteria), 'visited_nodes': len(seen),
                  'dependence_edges': edge_counts, 'unmapped_nodes': unmapped,
                  'source_lines': sorted(kept), 'omitted_lines': len(selected-set(kept)),
                  'node_cap_hit': capped, 'char_budget': max_chars,
                  'fallback': not bool(text), 'atomic_groups': group_audit,
                  'control_dependence_available':
                  any(d.get('edge_type') in {'CDG', 'CONTROL_DEPENDENCE'}
                      for _, _, d in graph.edges(data=True))}
    from config import RECORD_REASONING_TRACE
    if RECORD_REASONING_TRACE:
        # Local receipts only: never serialized into the LLM context.
        audit.update(criteria_node_ids=sorted(map(str, criteria)),
                     visited_node_ids=sorted(map(str, seen)),
                     selected_source_lines=sorted(selected),
                     budget_omitted_source_lines=sorted(selected-set(kept)))
    return text, audit
