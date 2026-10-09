"""Whole graph expressions and bounded incoming dependence, never safety proof.

All text comes from the supplied path graph, not reconstructed source or labels.
Omitted nodes are recorded outside the model context. CFG/AST are not dependence.
"""
import re
from collections import deque

READ_ARGUMENTS = {
    'strchr': (0,), 'strrchr': (0,), 'strlen': (0,), 'strnlen': (0, 1),
    'memcpy': (1, 2), 'memmove': (1, 2), 'memcmp': (0, 1, 2),
    'strcpy': (1,), 'strncpy': (1, 2), 'strcat': (0, 1),
    'strncat': (0, 1, 2), 'strcmp': (0, 1), 'strncmp': (0, 1, 2), 'memchr': (0, 2),
}
DEPENDENCE = {'REACHING_DEF', 'DFG', 'CDG', 'CONTROL_DEPENDENCE'}
CONDITIONS = {'<operator>.' + n for n in (
    'lessThan', 'greaterThan', 'lessEqualsThan', 'greaterEqualsThan',
    'equals', 'notEquals', 'logicalAnd', 'logicalOr', 'logicalNot')}
INCREMENTS = {'<operator>.' + n for n in (
    'postIncrement', 'preIncrement', 'postDecrement', 'preDecrement')}


def masked(text):
    from graph.security_net import _mask_noncode
    return _mask_noncode(text)


def identifiers(text):
    return set(re.findall(r'\b[A-Za-z_]\w*\b', masked(text))) - {
        'sizeof', 'NULL', 'int', 'char', 'unsigned', 'long', 'short', 'const'}


def arguments(text):
    opening = text.find('(')
    if opening < 0: return None
    stack, start, result = [], opening + 1, []
    pairs = {')': '(', ']': '[', '}': '{'}
    for pos in range(start, len(text)):
        char = text[pos]
        if char in '([{': stack.append(char)
        elif char in ')]}':
            if char == ')' and not stack:
                result.append(text[start:pos].strip())
                return result if not text[pos+1:].strip().rstrip(';') else None
            if not stack or stack.pop() != pairs[char]: return None
        elif char == ',' and not stack:
            result.append(text[start:pos].strip()); start = pos + 1
    return None


def read_names(graph, nid):
    node = graph.nodes.get(nid, {})
    if node.get('node_type') != 'CALL': return None
    code, name = masked(node.get('code') or '').strip(), node.get('name') or ''
    if name in READ_ARGUMENTS:
        if not re.match(r'^' + re.escape(name) + r'\s*\(', code): return None
        args, indices = arguments(code), READ_ARGUMENTS[name]
        if args is None or len(args) <= max(indices): return None
        return identifiers(' '.join(args[i] for i in indices))
    if name not in {'<operator>.indexAccess', '<operator>.indirectIndexAccess', '<operator>.indirection'}:
        return None
    for parent, _, attrs in graph.in_edges(nid, data=True):
        if attrs.get('edge_type') == 'AST' and graph.nodes[parent].get('name') == '<operator>.assignment':
            index = node.get('argument_index', node.get('argumentIndex'))
            lhs = re.split(r'=(?!=)', masked(graph.nodes[parent].get('code') or ''), maxsplit=1)[0].strip()
            if index in (1, '1') or code == lhs or index is None: return None
    return identifiers(code)


def ancestors(graph, read, max_hops=4, max_nodes=128):
    """Deterministic bounded witness chains: each edge ends at the next node."""
    found, queue, capped = {read: []}, deque([read]), False
    while queue:
        nid = queue.popleft()
        if len(found[nid]) >= max_hops: continue
        edges = sorted(graph.in_edges(nid, keys=True, data=True), key=lambda e: (str(e[0]), str(e[2])))
        for parent, _, key, attrs in edges:
            et = attrs.get('edge_type')
            if et not in DEPENDENCE or parent in found: continue
            if len(found) >= max_nodes: capped = True; continue
            found[parent] = [(parent, nid, key, et)] + found[nid]
            queue.append(parent)
    return found, capped


def pack_graph_evidence(graph, path, max_len, label):
    if max_len < 0: raise ValueError('Negative evidence budget')
    if len(path) < 2 or not all(isinstance(n, (str, int)) and n in graph for n in path): return ''
    receipt = dict(policy='whole_graph_evidence_v1', path=list(path), budget=max_len,
                   included=[], omitted=[], witnesses={}, traversal_capped=False,
                   scope_capacity_dominance='unknown; graph context only')
    reads = [(n, read_names(graph, n)) for n in dict.fromkeys(path)]
    reads = [(n, names) for n, names in reads if names is not None]
    parts, emitted = ['GRAPH context; scope unknown:'], set()

    def emit(nid, role, read=None, witness=None):
        if nid in emitted: return True
        node = graph.nodes[nid]
        code = (node.get('code') or '').strip()
        if not code:
            receipt['omitted'].append(dict(node=nid, reason='no_expression')); return False
        security = label(node)
        token = f'[{role}#{nid}' + (f'/{security}' if security else '') + f':{code}]'
        if len(' '.join(parts + [token])) > max_len:
            receipt['omitted'].append(dict(node=nid, reason='whole_expression_over_budget', chars=len(token)))
            return False
        parts.append(token); emitted.add(nid)
        receipt['included'].append(dict(node=nid, role=role, code=code, read=read))
        if witness: receipt['witnesses'][str(nid)] = witness
        return True

    for read, names in reads:
        if not emit(read, 'READ'): continue  # Never attach updates to an invisible read.
        upstream, capped = ancestors(graph, read)
        receipt['traversal_capped'] |= capped
        updates, conditions = [], []
        # Two binding rounds allow len=ptr-line -> line=ptr+1, only where a
        # recorded incoming dependence chain exists. Not execution/dominance proof.
        for _ in range(2):
            for nid, witness in sorted(upstream.items(), key=lambda item: (len(item[1]), str(item[0]))):
                if not witness or nid in updates: continue
                node = graph.nodes[nid]; name = node.get('name') or ''
                if node.get('node_type') != 'CALL': continue
                if not (name.startswith('<operator>.assignment') or name in INCREMENTS): continue
                code = masked(node.get('code') or '')
                lhs = re.split(r'(?:[+*/%-]?=(?!=)|\+\+|--)', code, maxsplit=1)[0]
                if identifiers(lhs) & names:
                    updates.append(nid); names |= identifiers(code)
        for nid, witness in upstream.items():
            node = graph.nodes[nid]
            if witness and node.get('node_type') == 'CALL' and node.get('name') in CONDITIONS and identifiers(node.get('code') or '') & names:
                conditions.append(nid)
        for role, nodes in [('UPSTREAM_UPDATE', updates), ('UPSTREAM_CONDITION', conditions)]:
            for nid in nodes: emit(nid, role, read, upstream[nid])
    # No invented edge between disconnected cards; each retains its graph ID.
    for nid in dict.fromkeys(path):
        if graph.nodes[nid].get('node_type') not in {'BLOCK', 'METHOD', 'METHOD_RETURN', 'FILE'}:
            emit(nid, 'NODE')
    body = ' '.join(parts) if emitted else '(whole graph expressions omitted)'
    if len(body) > max_len: body = ''
    receipt['body'] = body
    graph.graph.setdefault('display_selection_receipt', {})[str(tuple(path)) + ':' + str(max_len)] = receipt
    return body
