"""Single candidate: read-bound source evidence; no prediction/graph-rank changes."""
import re
from collections import deque

DEPENDENCE_EDGES = {'REACHING_DEF', 'DFG', 'CDG', 'CONTROL_DEPENDENCE'}
READ_APIS = {'strchr': (0, None), 'strrchr': (0, None), 'strlen': (0, None),
             'strnlen': (0, 1), 'memcpy': (1, 2), 'memmove': (1, 2),
             'memcmp': (0, 2), 'strcmp': (0, None), 'strncmp': (0, 2),
             'strcpy': (1, None), 'strncpy': (1, 2), 'strcat': (1, None),
             'strncat': (1, 2), 'memchr': (0, 2)}
READ_OPERATORS = {'<operator>.indexAccess', '<operator>.indirectIndexAccess', '<operator>.indirection'}
KEYWORDS = set('if else for while return void int char long short unsigned signed const static struct sizeof NULL size_t uint32_t uint64_t'.split())


def _mask(code):
    pattern = r'/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    return re.sub(pattern, lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), code)


def _ids(code):
    calls = set(re.findall(r'\b([A-Za-z_]\w*)\s*\(', code))
    return set(re.findall(r'\b[A-Za-z_]\w*\b', _mask(code))) - KEYWORDS - calls


def _args(fragment, api):
    clean = _mask(fragment)
    matches = list(re.finditer(r'\b'+re.escape(api)+r'\s*\(', clean))
    if len(matches) != 1: return None
    start = clean.find('(', matches[0].start())
    depth, cuts = 1, [start+1]
    for pos in range(start+1, len(clean)):
        if clean[pos] in '([{': depth += 1
        elif clean[pos] in ')]}':
            depth -= 1
            if depth == 0:
                return [fragment[a:b].strip() for a, b in zip(cuts, [c-1 for c in cuts[1:]]+[pos])]
        elif clean[pos] == ',' and depth == 1: cuts.append(pos+1)
    return None


def _scope_pairs(source):
    clean = _mask(source)
    stack, pairs, unmatched = [], [], False
    line = 1
    for char in clean:
        if char == '\n': line += 1
        elif char == '{': stack.append(line)
        elif char == '}':
            if stack: pairs.append((stack.pop(), line))
            else: unmatched = True
    return pairs, unmatched or bool(stack)


def _closure(selected, lines, pairs):
    result = set(selected)
    for opening, closing in pairs:
        if any(opening <= n <= closing for n in selected):
            result.update((opening, closing))
            if lines[opening-1].strip() == '{' and opening > 1: result.add(opening-1)
    for n in selected:
        if n > 1 and re.match(r'^\s*(?:if|else|for|while)\b', lines[n-2]): result.add(n-1)
    return result


def _render(selected, lines):
    pieces = ['/* graph excerpt; omitted code/contracts unknown */']
    last = 0
    for n in sorted(selected):
        if n > last+1: pieces.append(f'/* omitted L{last+1}-L{n-1} */')
        pieces.append(lines[n-1]); last = n
    if last < len(lines): pieces.append(f'/* omitted L{last+1}-L{len(lines)} */')
    return '\n'.join(pieces)


def backward_evidence_slice(graph, paths, source, *, line_offset=0, max_chars=600, max_nodes=2048):
    """Existing source_evidence hook; only this module differs from foundation.

    Criteria come from supplied Top-K nodes; predecessors from unchanged full
    graph. Source is never reconstructed from graph CODE; no synthetic braces,
    invented helper/capacity contracts or CFG-as-dominance inference.
    """
    lines = source.splitlines()
    criteria, bindings = [], {}
    unmapped = 0
    cap = min(max_nodes, 128)
    def line_of(node):
        try: value = int(graph.nodes[node].get('line_number'))-line_offset
        except (TypeError, ValueError): return None
        return value if 1 <= value <= len(lines) else None
    for path in paths:
        for node in path:
            if node in criteria: continue
            attrs = graph.nodes.get(node, {})
            name = attrs.get('name') or attrs.get('method') or ''
            if name not in READ_APIS and name not in READ_OPERATORS: continue
            if attrs.get('node_type') != 'CALL': continue
            line = line_of(node)
            if line is None: unmapped += 1; continue
            if name in READ_APIS:
                fragment = '\n'.join(lines[line-1:min(len(lines), line+3)])
                statement = fragment.split(';', 1)[0]
                arguments = _args(statement, name)
                source_index, width_index = READ_APIS[name]
                if arguments is None or len(arguments) <= source_index: unmapped += 1; continue
                targets = [arguments[source_index]]
                if name in {'memcmp', 'strcmp', 'strncmp'} and len(arguments) > 1: targets.append(arguments[1])
                width = arguments[width_index] if width_index is not None and len(arguments) > width_index else ''
                names = _ids(' '.join(targets)+' '+width)
            else:
                expression = attrs.get('code') or ''
                pure_write = any(graph.nodes[p].get('name') == '<operator>.assignment' and
                                 re.match(r'^\s*'+re.escape(expression)+r'\s*=(?!=)', graph.nodes[p].get('code') or '')
                                 for p, _, e in graph.in_edges(node, data=True) if e.get('edge_type') == 'AST')
                if pure_write: continue
                targets, width, names = [expression], '', _ids(expression)
            if not names: continue
            criteria.append(node)
            bindings[node] = dict(targets=targets, width_expression=width or None, identifiers=sorted(names), source_line=line,
                                  capacity_contract='unknown')
    pairs, incomplete_scope = _scope_pairs(source)
    selected = {1} if lines else set()
    accepted, all_lines, all_seen = [], set(), set()
    edge_counts = {}
    capped = False
    for root in criteria:
        if root not in all_seen and len(all_seen) >= cap:
            capped = True
            break
        names = set(bindings[root]['identifiers'])
        seen, queue = {root}, deque([(root, 0)])
        ordered = [root]
        while queue:
            node, depth = queue.popleft()
            if depth >= 5: continue
            for pred, _, edge in graph.in_edges(node, data=True):
                kind = edge.get('edge_type')
                if kind not in DEPENDENCE_EDGES or pred in seen: continue
                attrs = graph.nodes[pred]
                if attrs.get('node_type') in {'METHOD', 'BLOCK', 'FILE'}: continue
                pred_names = _ids(attrs.get('code') or '')
                is_control = kind in {'CDG', 'CONTROL_DEPENDENCE'}
                if not is_control and not pred_names.intersection(names): continue
                if len(all_seen | seen) >= cap: capped = True; break
                seen.add(pred); ordered.append(pred); queue.append((pred, depth+1))
                edge_counts[kind] = edge_counts.get(kind, 0)+1
                if not is_control: names.update(pred_names)
        all_seen.update(seen)
        source_lines = [line_of(n) for n in ordered if line_of(n) is not None]
        all_lines.update(source_lines)
        root_line = bindings[root]['source_line']
        proposed = _closure(selected | {root_line}, lines, pairs)
        if len(_render(proposed, lines)) > max_chars: continue
        selected = proposed; accepted.append(root)
        for dependency_line in source_lines[1:]:
            proposed = _closure(selected | {dependency_line}, lines, pairs)
            if len(_render(proposed, lines)) <= max_chars: selected = proposed
    text = _render(selected, lines) if accepted else ''
    if len(text) > max_chars: raise ValueError('Read slice exceeded original SRC character budget')
    return text, dict(enabled=True, policy='graph_read_dependency_src_v1', criteria=len(criteria), accepted_criteria=len(accepted),
                      read_bindings=bindings, visited_nodes=len(all_seen), dependence_edges=edge_counts,
                      unmapped_nodes=unmapped, source_lines=sorted(selected) if text else [],
                      omitted_lines=len(set(range(1, len(lines)+1))-selected) if text else len(lines),
                      dependency_lines_omitted=len(all_lines-selected), node_cap_hit=capped,
                      char_budget=max_chars, fallback=not bool(text), scope_is_complete=None,
                      supplied_scope_unbalanced=incomplete_scope, helper_and_capacity_contracts='unknown',
                      control_dependence_available=any(e.get('edge_type') in {'CDG', 'CONTROL_DEPENDENCE'} for _, _, e in graph.edges(data=True)))
