"""Atomic mapped dependence groups; CFG reachability is not control dependence."""
import re
from collections import deque
DEPENDENCE = {'REACHING_DEF', 'DFG', 'CDG', 'CONTROL_DEPENDENCE'}
CONTROL = {'CDG', 'CONTROL_DEPENDENCE'}
EXIT = re.compile(r'^\s*(?:return\b|break\b|goto\b)')
LIFETIME = re.compile(r'\b(?:malloc|calloc|realloc|alloca|free|kfree|kmalloc|kzalloc|kcalloc|av_malloc\w*|av_freep?)\s*\(')


def pack_evidence_groups(graph, criteria, source, baseline_lines, *, line_offset,
                         max_chars, max_nodes=2048):
    lines = source.splitlines()
    def line_of(node):
        try:
            n = int(graph.nodes[node].get('line_number'))-line_offset
            return n if 1 <= n <= len(lines) else None
        except (TypeError, ValueError):
            return None
    def render(ids):
        return '\n'.join(lines[n-1] for n in sorted(ids))
    baseline = set(baseline_lines)
    old_text = render(baseline)
    # Characters/bytes are not an exact tokenizer for the remote model.
    char_cap = min(max_chars, len(old_text))
    byte_cap = len(old_text.encode('utf-8'))
    protected = baseline & {line_of(n) for n in criteria}
    protected |= {n for n in baseline if LIFETIME.search(lines[n-1])}
    def fits(ids):
        text = render(ids)
        return len(text) <= char_cap and len(text.encode('utf-8')) <= byte_cap
    groups = []
    skipped = []
    for criterion in criteria:
        if graph.nodes[criterion].get('node_type') != 'CALL':
            skipped.append(str(criterion))
            continue
        if line_of(criterion) is None:
            continue
        seen, queue = {criterion}, deque([criterion])
        capped = False
        while queue and not capped:
            node = queue.popleft()
            for pred, _, edge in graph.in_edges(node, data=True):
                if edge.get('edge_type') in DEPENDENCE and pred not in seen:
                    if len(seen) >= max_nodes:
                        capped = True
                        break
                    seen.add(pred); queue.append(pred)
        # Only explicit control-dependent terminations, no arbitrary CFG walks.
        exits = set()
        control_roots = {u for u, v, d in graph.edges(data=True)
                         if v in seen and d.get('edge_type') in CONTROL}
        for guard in sorted(control_roots, key=str):
            for _, child, edge in graph.out_edges(guard, data=True):
                attrs = graph.nodes[child]
                if (edge.get('edge_type') in CONTROL and
                        (attrs.get('node_type') == 'RETURN' or EXIT.search(attrs.get('code', '') or ''))):
                    exits.add(child)
        capped = capped or len(seen | exits) > max_nodes
        ids = {line_of(n) for n in seen | exits}
        ids.discard(None)
        groups.append({'criterion_node_id': str(criterion), 'source_lines': sorted(ids),
                       'control_node_ids': sorted(map(str, control_roots)),
                       'exit_node_ids': sorted(map(str, exits)), 'traversal_capped': capped,
                       'unmapped_nodes': sum(line_of(n) is None for n in seen | exits)})
    kept = set(protected)
    admitted = 0
    for group in groups:
        proposed = kept | set(group['source_lines'])
        group['admitted'] = not group['traversal_capped'] and fits(proposed)
        if group['admitted']:
            kept = proposed
            admitted += 1
    if admitted == 0:
        kept = baseline
        fallback = True
    else:
        fallback = False
        for n in sorted(baseline):
            if fits(kept | {n}):
                kept.add(n)
    for group in groups:
        group['mapped_lines_complete_in_output'] = set(group['source_lines']) <= kept
    assert fits(kept) and protected <= kept
    return sorted(kept), {'enabled': True, 'groups': groups, 'admitted_groups': admitted,
        'fallback_to_plain': fallback, 'protected_plain_lines': sorted(protected),
        'skipped_non_call_criteria': skipped,
        'plain_chars': len(old_text), 'grouped_chars': len(render(kept)),
        'plain_utf8_bytes': byte_cap, 'grouped_utf8_bytes': len(render(kept).encode('utf-8')),
        'remote_token_count_known': False,
        'scope': 'Atomic mapped groups, not proof of protection or complete program semantics.'}
