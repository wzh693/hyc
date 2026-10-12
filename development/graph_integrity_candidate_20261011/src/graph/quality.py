"""Source-coordinate provenance and fail-closed executable-body checks.

These checks do not certify C semantics or reconstruct missing contracts.
"""
from linearization.source_mapping import source_line_offset


class GraphEvidenceError(RuntimeError):
    pass


def annotate_quality(graph, source, wrapped):
    offset = source_line_offset(source, wrapped)
    count = len(source.splitlines())
    aligned = 0 <= offset <= len(wrapped.splitlines()) - count
    operations = []
    for node, attrs in graph.nodes(data=True):
        line = attrs.get('line_number')
        original = aligned and isinstance(line,int) and offset < line <= offset+count
        attrs['source_origin'] = 'original_line_range' if original else 'wrapper_or_unmapped'
        attrs['original_line_number'] = line-offset if original else None
        if (original and attrs.get('node_type') in {'CALL','RETURN','CONTROL_STRUCTURE'}
                and not attrs.get('is_external',False)):
            operations.append(node)
    # Require AST ownership by a real body, not an unrelated global/stub CALL.
    bodies = set()
    for node,attrs in graph.nodes(data=True):
        if (attrs.get('node_type')=='METHOD' and not attrs.get('is_external',False)
                and not (attrs.get('name') or '').startswith('<')):
            for _,child,edge in graph.out_edges(node,data=True):
                if edge.get('edge_type')=='AST' and graph.nodes[child].get('node_type')=='BLOCK':
                    bodies.add(child)
    owned = set(bodies)
    queue = list(bodies)
    while queue:
        node=queue.pop()
        for _,child,edge in graph.out_edges(node,data=True):
            if edge.get('edge_type')=='AST' and child not in owned:
                owned.add(child); queue.append(child)
    operations = sorted(set(operations)&owned, key=str)
    receipt = dict(source_mapping_valid=aligned, source_line_offset=offset,
        original_line_count=count, mapped_operation_count=len(operations),
        mapped_operation_nodes=operations, body_count=len(bodies),
        usable=bool(aligned and operations),
        semantic_status='not_certified; wrapper types, omitted scopes and helper contracts remain unknown')
    from graph.wrapping import audit_wrapper
    receipt['wrapper_risk']=audit_wrapper(source,wrapped)
    graph.graph['quality']=receipt
    return receipt
