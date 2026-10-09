"""Budgeted contiguous source windows; never cut a selected source line.

Experimental input builder, not a program slicer or feasibility analysis.
Selection uses code/graph only, never labels or predictions.
"""
import re
from graph.security_net import _mask_noncode


def source_windows(source, graph, paths, budget):
    raw = source.splitlines()
    masked = _mask_noncode(source).splitlines()
    meaningful = [i for i, line in enumerate(masked) if line.strip()]
    if not meaningful or budget <= 0:
        return ''
    positions = {line:pos for pos,line in enumerate(meaningful)}
    retrieved = {n for path in paths for n in path}
    scores = {}
    for n, node in graph.nodes(data=True):
        if node.get('node_type') not in {'CALL','RETURN'}:
            continue
        code = _mask_noncode(node.get('code','') or '')
        # Real operation nodes, never whole METHOD/BLOCK/CONTROL_STRUCTURE.
        dangerous = bool(re.search(r'\b(?:free|av_free|kfree|malloc|qemu_malloc|av_mallocz|calloc|realloc|memcpy|strcpy|read|recv)\s*\(',code))
        memory = bool(re.search(r'->|\[[^]]+\]|\*\s*[A-Za-z_]',code))
        if not (dangerous or memory):
            continue
        try:
            line = int(node.get('line_number'))-1
        except (TypeError,ValueError):
            continue
        if line not in positions:
            continue
        scores[line] = max(scores.get(line,0), (8 if dangerous else 3)+(3 if n in retrieved else 0))
    # Windows contain two meaningful predecessors and successors, including
    # guards/returns/declarations and braces, not just the scored operation.
    windows = []
    for center,score in scores.items():
        pos = positions[center]
        indices = meaningful[max(0,pos-2):pos+3]
        windows.append((score, center, min(indices), max(indices)))
    if not windows:
        return ''  # Explicit abstention; caller must keep the original slice.
    # Keep the complete (possibly multiline) signature instead of its first
    # line only. This is source context, not an operation window.
    selected = {meaningful[0]}
    depth = masked[meaningful[0]].count('(')-masked[meaningful[0]].count(')')
    for i in meaningful[1:]:
        if depth <= 0: break
        selected.add(i)
        depth += masked[i].count('(')-masked[i].count(')')
    header = set(selected)
    def render(indices):
        lines, previous = [], None
        for i in sorted(indices):
            if previous is not None and i > previous+1:
                lines.append('...')
            # Keep original literal values and exact source, not masked text.
            if masked[i].strip():
                lines.append(raw[i].rstrip())
            previous = i
        return '\n'.join(lines)
    if len(render(selected)) > budget:
        return ''  # Do not manufacture a partial signature.
    for _,_,lo,hi in sorted(windows,key=lambda w:(-w[0],w[1])):
        candidate = selected | set(range(lo,hi+1))
        if len(render(candidate)) <= budget:
            selected = candidate
    # Unlike legacy character clipping, no admitted line is cut in half.
    return render(selected) if selected != header else ''
