"""Conservative experimental verifier; missing graph evidence means abstain.

CFG reachability is structural, not symbolic path feasibility. This is not a
complete C vulnerability detector. It deliberately omits API-count signals and
alias inference. Use the full CPG, with sinks anchored in retrieved evidence.
"""
import re
from graph.security_net import (SecuritySignal, _mask_noncode, _FREE_RE,
                                _canonical_expr, _strong_use_re, _reassignment_re)


def _adjacency(graph, allowed):
    result = {}
    for u, v, data in graph.edges(data=True):
        types = set(re.findall(r'[A-Z_]+', str(data.get('edge_type', ''))))
        if types & allowed:
            result.setdefault(u, set()).add(v)
    return result


def _reachable(start, target, adjacency, blocked=frozenset()):
    # Require at least one edge, not self-matching within a large code node.
    seen = {start}
    pending = list(adjacency.get(start, ()))
    while pending:
        node = pending.pop()
        if node in blocked:
            continue
        if node == target:
            return True
        if node not in seen:
            seen.add(node)
            pending.extend(adjacency.get(node, ()))
    return False


def graph_security_signal(graph, paths):
    anchors = {n for path in paths for n in path if n in graph}
    # BLOCK/METHOD/CONTROL_STRUCTURE contain whole bodies, not operations.
    code = {n: _mask_noncode(d.get('code', '') or '')
            for n, d in graph.nodes(data=True)
            if d.get('node_type') in {'CALL', 'RETURN'}}
    cfg = _adjacency(graph, {'CFG'})
    dfg = _adjacency(graph, {'REACHING_DEF', 'DFG'})
    releases = [(n, _canonical_expr(m.group('expr')))
                for n, text in code.items() for m in _FREE_RE.finditer(text)
                # av_freep clears the pointer; do not model it as plain free.
                if not m.group().lstrip().startswith('av_freep')]
    uaf_pairs, double_pairs, taint_pairs = set(), set(), set()
    for start, expr in releases:
        kills = {n for n, text in code.items()
                 if n != start and _reassignment_re(expr).search(text)}
        for target in anchors:
            text = code.get(target, '')
            if target == start or target in kills:
                continue
            if not _reachable(start, target, cfg, kills):
                continue
            if _strong_use_re(expr).search(text):
                uaf_pairs.add((start, target, expr))
            if any(_canonical_expr(m.group('expr')) == expr
                   for m in _FREE_RE.finditer(text)
                   if not m.group().lstrip().startswith('av_freep')):
                double_pairs.add((start, target, expr))
    # Only simple, same-expression command arguments are supported. API
    # co-occurrence, literal commands, and unverified aliases cannot trigger.
    ident = r'[A-Za-z_]\w*(?:\s*->\s*[A-Za-z_]\w*)?'
    for target in anchors:
        command = re.search(r'\b(?:system|popen)\s*\(\s*(' + ident + r')\s*[,)]',
                            code.get(target, ''))
        if not command:
            continue
        expr = _canonical_expr(command.group(1))
        kills = {n for n, text in code.items()
                 if n != target and _reassignment_re(expr).search(text)}
        for start, text in code.items():
            source = re.search(r'\b(?:read|recv)\s*\([^,;]+,\s*(' + ident + r')\s*,', text)
            returned = re.search(r'\b(' + ident + r')\s*=\s*getenv\s*\(', text)
            match = source or returned
            if match and _canonical_expr(match.group(1)) == expr and start != target:
                if (_reachable(start, target, cfg, kills - {start})
                        and _reachable(start, target, dfg, kills - {start})):
                    taint_pairs.add((start, target, expr))
    uaf, double = len(uaf_pairs), len(double_pairs)
    score = min(uaf, 2) * 4 + min(double, 2) * 5 + (4 if taint_pairs else 0)
    reasons = tuple(name for name, found in
                    [('cfg-free-to-use', uaf), ('cfg-double-free', double),
                     ('cfg-dfg-taint-to-command', taint_pairs)] if found)
    signal = SecuritySignal(score, uaf, double, 0, bool(taint_pairs), reasons)
    pairs = sorted(uaf_pairs | double_pairs | taint_pairs, key=lambda p: tuple(map(str, p)))
    return signal, [{'source': str(a), 'sink': str(b), 'expression': expr}
                    for a, b, expr in pairs]


def zero_token_graph_verify(b_pred, graph, paths, threshold=4):
    signal, evidence = graph_security_signal(graph, paths)
    triggered = signal.score >= threshold
    flipped = b_pred == 0 and triggered
    return (1 if flipped else b_pred), {
        'verifier': 'graph_candidate_v1', 'triggered': triggered,
        'flipped': flipped, 'threshold': threshold, 'signal': signal.to_dict(),
        'evidence': evidence, 'audit_tokens': 0,
        'limitations': 'Structural reachability only; no symbolic feasibility or alias proof.'}
