import networkx as nx
import re
from retrieval.path_ranker import rank_paths
from config import TOP_K_PATHS


# One isolated candidate: reorder existing paths against the unchanged smallest
# DEP display budget. No new nodes, source lines, graph edges or safety claims.
READ_ARGUMENTS = {
    'strchr': (0,), 'strrchr': (0,), 'strlen': (0,), 'strnlen': (0, 1),
    'memcpy': (1, 2), 'memmove': (1, 2), 'memcmp': (0, 1, 2),
    'strcpy': (1,), 'strncpy': (1, 2), 'strcat': (0, 1),
    'strncat': (0, 1, 2), 'strcmp': (0, 1), 'strncmp': (0, 1, 2),
    'memchr': (0, 2),
}
DEPENDENCE = {'REACHING_DEF', 'DFG', 'CDG', 'CONTROL_DEPENDENCE'}


def _arguments(text):
    """Split masked call arguments; reject incomplete/nested imbalance."""
    opening = text.find('(')
    if opening < 0: return None
    depth, start, result = 0, opening + 1, []
    for pos in range(opening + 1, len(text)):
        char = text[pos]
        if char in '([{': depth += 1
        elif char in ')]}':
            if char == ')' and depth == 0:
                result.append(text[start:pos].strip())
                return result
            depth -= 1
            if depth < 0: return None
        elif char == ',' and depth == 0:
            result.append(text[start:pos].strip()); start = pos + 1
    return None


def _read_names(G, nid):
    from graph.security_net import _mask_noncode
    node = G.nodes.get(nid, {})
    if node.get('node_type') != 'CALL': return None
    code = _mask_noncode(node.get('code') or '').strip()
    name = node.get('name') or ''
    if name in READ_ARGUMENTS:
        if not re.match(r'^' + re.escape(name) + r'\s*\(', code): return None
        args = _arguments(code)
        indices = READ_ARGUMENTS[name]
        if args is None or len(args) <= max(indices): return None
        # Destination allocation is not source-readable capacity.
        expressions = ' '.join(args[i] for i in indices)
    elif name in {'<operator>.indexAccess', '<operator>.indirectIndexAccess', '<operator>.indirection'}:
        # Joern AST argument1 of simple assignment is write-only. Compound
        # assignments still read. Refuse ambiguous missing argument metadata.
        for parent, _, attrs in G.in_edges(nid, data=True):
            if attrs.get('edge_type') == 'AST' and G.nodes[parent].get('name') == '<operator>.assignment':
                index = node.get('argument_index', node.get('argumentIndex'))
                parent_code = _mask_noncode(G.nodes[parent].get('code') or '')
                lhs = re.split(r'=(?!=)', parent_code, maxsplit=1)[0].strip()
                if index in (1, '1') or code == lhs or index is None: return None
        expressions = code
    else: return None
    names = set(re.findall(r'\b[A-Za-z_]\w*\b', expressions))
    return names - {'sizeof', 'NULL', 'int', 'char', 'unsigned', 'long', 'short', 'const'}


def _visible_features(G, path, max_len=260):
    """Only complete unchanged serializer node tokens count as visible evidence."""
    from linearization.typed_paths import _labeled_compact_path
    from graph.security_net import _mask_noncode
    text = _labeled_compact_path(G, path, max_len=max_len)
    visible, cursor = set(), 0
    for nid in path:
        node = G.nodes.get(nid, {})
        code = (node.get('code') or node.get('name') or '?').strip()
        marker = f"[{node.get('node_type', '?')}:{code[:35]}]"
        position = text.find(marker, cursor)
        if position < 0: break  # The unchanged serializer emits a prefix.
        cursor = position + len(marker)
        if code and len(code) <= 35:
            visible.add(nid)
    reads = {nid: _read_names(G, nid) for nid in visible}
    reads = {nid: names for nid, names in reads.items() if names is not None}
    relations = set()
    for read, names in reads.items():
        rpos = path.index(read)
        for nid in visible - {read}:
            node = G.nodes[nid]
            name = node.get('name') or ''
            if node.get('node_type') != 'CALL': continue
            kind = 'update' if name.startswith('<operator>.assignment') or name in {
                '<operator>.postIncrement', '<operator>.preIncrement',
                '<operator>.postDecrement', '<operator>.preDecrement'} else 'condition' if name in {
                '<operator>.lessThan', '<operator>.greaterThan', '<operator>.lessEqualsThan',
                '<operator>.greaterEqualsThan', '<operator>.equals', '<operator>.notEquals',
                '<operator>.logicalAnd', '<operator>.logicalOr', '<operator>.logicalNot'} else None
            if not kind: continue
            ids = set(re.findall(r'\b[A-Za-z_]\w*\b', _mask_noncode(node.get('code') or '')))
            if not ids.intersection(names): continue
            left, right = sorted((rpos, path.index(nid)))
            # CFG adjacency is never promoted to data dependency/dominance.
            if all(any(attrs.get('edge_type') in DEPENDENCE
                       for attrs in (G.get_edge_data(path[i], path[i+1]) or {}).values())
                   for i in range(left, right)):
                relations.add((read, nid, kind))
    return dict(text=text, reads=set(reads), relations=relations, visible=visible)


def _select_display_paths(G, candidates, legacy, scores, k):
    if k <= 0: return legacy
    # The unchanged builder always displays at least two paths (four for large
    # source). Optimize just these guaranteed slots; retain legacy tail choices.
    features = [(p, _visible_features(G, p)) for p in candidates]
    selected, seen_reads, seen_relations, seen_text = [], set(), set(), set()
    for _ in range(min(2, k)):
        eligible = [(p, f) for p, f in features if p not in selected and f['text'] not in seen_text
                    and f['reads'] - seen_reads]
        if not eligible: break
        path, feature = max(eligible, key=lambda pair: (
            len(pair[1]['reads'] - seen_reads),
            len(pair[1]['relations'] - seen_relations), scores.get(tuple(pair[0]), float('-inf'))))
        selected.append(path); seen_reads |= feature['reads']; seen_relations |= feature['relations']
        seen_text.add(feature['text'])
    if not selected: return legacy
    for path in legacy:
        if path not in selected: selected.append(path)
        if len(selected) >= k: break
    return selected[:k]


def retrieve_topk(
    G: nx.MultiDiGraph,
    candidate_paths: list,
    k: int = TOP_K_PATHS,
    vuln_type: str = "Generic",
    learned_scores: dict = None,
) -> list:
    """
    从候选路径中检索 Top-K 漏洞相关路径。

    流程:
      1. 对所有候选路径进行结构化特征编码
      2. 基于加权特征评分排序（漏洞类型条件权重）
      3. 返回 Top-K 路径

    learned_scores: 技术点②学习式节点重要性（None = 关闭）
    """
    scored = rank_paths(G, candidate_paths, top_k=k, vuln_type=vuln_type, learned_scores=learned_scores)
    topk = [path for _, path in scored]
    raw = rank_paths(G, candidate_paths, top_k=0, vuln_type=vuln_type, learned_scores=learned_scores)
    scores = {tuple(path): score for score, path in raw}
    legacy = topk
    topk = _select_display_paths(G, [p for _, p in raw], legacy, scores, k)
    G.graph['display_selection_receipt'] = {
        'policy': 'visible_read_diversity_v2', 'selection_budget_chars': 260,
        'optimized_slots': min(2, max(0, k)), 'legacy_paths': legacy,
        'selected_paths': topk, 'changed': topk != legacy,
        'capacity_and_guard_dominance': 'unknown; not inferred',
    }
    print(
        f"[RetrieveTopK] 从 {len(candidate_paths)} 条候选路径中选出 Top-{len(topk)}"
    )
    for i, p in enumerate(topk):
        print(f"  #{i+1}: base_score={scores.get(tuple(p), 0):.2f}, 长度={len(p)}")
    return topk
