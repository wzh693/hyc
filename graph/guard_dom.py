"""v18 GUARD-DOM 图判定层：数据流对齐的守卫支配性分析。

背景（v17 后探针 _guard_dom_probe.json 实证）：
  - FP 样本 8/8 sink 被守卫支配——LLM "no guard visible" 判词与图事实
    系统性矛盾，守卫事实对 LLM 可见有价值；
  - 但 TP 11/12 sink 也被守卫支配——裸守卫（任何 NULL/边界/长度模式，
    人均 30-210 个）无判别力，直接当良性判据会复现 v15 双刃剑。

判别力钥匙 = **数据流对齐**：守卫条件使用的变量与 sink 参数变量有交集
（如 if (n > sizeof dst) 对 memcpy(dst, src, n)）。本模块只计算并呈现
结构事实，不做良性/漏洞判词（v15 教训：证据只能呈现，不能带结论）。

v18 修复（sample_000194 冒烟实证，逻辑移植自验证过的探针 _guard_dom_probe.py）：
  - sink 识别只认 CALL 类节点的 CODE 字段正则——原 _node_text_fields
    拼串（code+name+method）会把 name/method 含 "memcpy" 的怪节点
    （BLOCK code="{"、CONTROL_STRUCTURE code="if (name##_len) {"）误判
    SINK 并占满 max_facts 配额，真 sink 被挤掉 → 事实行全 0；
  - entry 选取排除伪 METHOD（<global>/<includes>/<operator>*）、要求有
    出边、取可达集最大者，回退入度 0 节点——原实现未排除伪名且不要求
    出边，可能选中无可达集的入口，支配树覆盖不到 sink。

注意：支配性在压缩图 SG 上计算是近似（压缩丢中间节点可能高估支配），
v18 首版接受——SG 的 force_keep 已保证危险节点与守卫条件节点存活。
实测 SG 的 CFG 会被压缩打成碎片（真实 METHOD 入口可达仅 2 节点），故
入口选取按"sink 覆盖数优先"（见 _pick_entry）：原始 G 上等价于探针的
METHOD 入口，SG 上退化为覆盖 sink 的碎片根。sink 全不可达/支配不可算
时返回空（层静默省略）。
"""
import re
import networkx as nx

from linearization.typed_paths import (
    _node_security_hit,
    _node_text_fields,  # 冒烟脚本经本模块转引（typed_paths 的节点文本拼接）
    _SAFE_NULL_RE,
    _SAFE_BOUND_RE,
    _SAFE_SIZE_RE,
    _ALLOC_CALL_RE,
)

_IDENT_RE = re.compile(r'\b([a-zA-Z_]\w*)\b')
# 对齐排除：C 关键字 + 常见危险/安全 API 名（对齐是"守卫变量≈sink 变量"，
# API 名本身不是变量）
_STOPWORDS = {
    "if", "else", "for", "while", "switch", "case", "return", "sizeof",
    "strlen", "array_size", "NULL", "null", "void", "int", "char", "unsigned",
    "long", "size_t", "const", "struct", "static", "goto", "break", "continue",
    "memcpy", "strcpy", "strcat", "sprintf", "snprintf", "strncpy", "strncat",
    "memset", "memmove", "gets", "system", "execve", "popen", "scanf",
}

# 伪 METHOD 名（Joern DOT 会带出 <global>/<includes>/操作符桩方法）
_PSEUDO_METHOD_NAMES = {"<global>", "<includes>", "<empty>"}
_DOM_CHAIN_CAP = 4096


def _is_guard(code: str) -> bool:
    """守卫模式命中（复用 v15 的正则组；守卫≠判词，只做节点筛选）。"""
    if not code:
        return False
    low = code.lower()
    if _SAFE_NULL_RE.search(low):
        return True
    if _SAFE_SIZE_RE.search(low) and not _ALLOC_CALL_RE.search(low):
        return True
    if _SAFE_BOUND_RE.search(low):
        return True
    return False


def _aligned_idents(guard_code: str, sink_code: str) -> set:
    """守卫与 sink 的对齐变量：双方 code 标识符交集（排除关键字/API 名）。"""
    g = set(_IDENT_RE.findall(guard_code)) - _STOPWORDS
    s = set(_IDENT_RE.findall(sink_code)) - _STOPWORDS
    return g & s


def _is_sink_node(nd: dict) -> bool:
    """sink = CALL 类节点且 CODE 字段命中危险 API（SINK 优先级词表）。

    探针验证口径：只认 CODE 字段（name/method 含 API 名的怪节点不是
    sink——sample_000194 冒烟实证）；BLOCK/METHOD 的大文本 CODE
    （整块/整函数）也不参与（CALL 类型限制天然排除）。
    """
    if (nd.get("node_type") or "") != "CALL":
        return False
    code = nd.get("code") or ""
    return bool(code) and _node_security_hit({"code": code})[0] == "SINK"


def _guard_code_of(nd: dict) -> str:
    """守卫节点的匹配/展示文本（探针验证口径）。

    CALL 用 CODE；CONTROL_STRUCTURE 只取首个 "{" 前的条件段（Joern 的
    CODE 含整个语句体，体内任意 if(!p) 会把外层结构误判成守卫）；
    BLOCK/METHOD 大文本节点不参与（返回空）。
    """
    nt = nd.get("node_type")
    code = (nd.get("code") or "").strip()
    if nt == "CONTROL_STRUCTURE":
        return code.split("{", 1)[0].strip()
    if nt == "CALL":
        return code
    return ""


def _cfg_subgraph(G: nx.MultiDiGraph) -> nx.DiGraph:
    """CFG 子图（探针验证版）：edge_type 含 "CFG" 的边，携带节点属性。"""
    H = nx.DiGraph()
    nodes, edges = set(), []
    for u, v, edata in G.edges(data=True):
        if "CFG" in str(edata.get("edge_type", "")):
            nodes.add(u)
            nodes.add(v)
            edges.append((u, v))
    H.add_nodes_from((n, dict(G.nodes[n])) for n in nodes)
    H.add_edges_from(edges)
    return H


def _pick_entry(H: nx.DiGraph, cfg_sinks: set):
    """CFG 入口（探针验证版 + SG 碎片适配）。

    候选 = 真实 METHOD（排除伪名、须有出边）∪ 入度 0 且有出边的节点。
    选取：覆盖 CFG sink 数最多 > 可达集最大 > METHOD 优先。

    原始 G 上真实 METHOD 覆盖全部 sink，行为与探针一致；压缩图 SG 上
    CFG 被打成碎片（实测 entry 可达仅 2 节点、碎片根 40+），退化为
    "覆盖 sink 的碎片根"——支配性在 SG 上本就是近似（压缩丢中间节点
    可能高估支配，v18 首版接受）。
    """
    cands = set()
    for n, nd in H.nodes(data=True):
        if nd.get("node_type") != "METHOD":
            continue
        name = (nd.get("name") or "").strip()
        if name in _PSEUDO_METHOD_NAMES or name.startswith("<operator"):
            continue
        if H.out_degree(n) > 0:
            cands.add(n)
    cands.update(n for n in H.nodes if H.in_degree(n) == 0 and H.out_degree(n) > 0)
    if not cands:
        return None

    def _score(n):
        reach = {n} | nx.descendants(H, n)
        return (len(reach & cfg_sinks), len(reach),
                1 if H.nodes[n].get("node_type") == "METHOD" else 0)

    return max(cands, key=_score)


def _dominator_chain(idom: dict, entry, node, cap: int = _DOM_CHAIN_CAP) -> list:
    """沿支配树回溯收集 node 的全部支配者（探针验证版；node 须可达）。"""
    chain, cur = [], node
    for _ in range(cap):
        chain.append(cur)
        if cur == entry:
            break
        cur = idom[cur]
    return chain


def _fact_line(sink_code: str, guard_code: str, max_line: int) -> str:
    """事实行：行长硬上限 max_line+3（冒烟断言 ≤73ch）。

    预算分配：守卫代码是本层 payload（sink 上下文已在 DEP PATHS 层），
    但 sink 保底 10ch 避免空引用；两码超预算时 sink[:10] + 守卫[:24]。
    """
    cap = max_line + 3
    if guard_code:
        s, g = sink_code[:34], guard_code[:34]
        if len(s) + len(g) > cap - 39:  # 39 = "DOM-GUARD: "+" | aligned guard dominates: "
            s, g = sink_code[:10], guard_code[:24]
        line = "DOM-GUARD: " + s + " | aligned guard dominates: " + g
    else:
        s = sink_code[:min(44, cap - 40)]  # 40 = "DOM-GUARD: "+" | no aligned guard dominates"
        line = "DOM-GUARD: " + s + " | no aligned guard dominates"
    return line[:cap]


def guard_dom_pairs(G: nx.MultiDiGraph, topk_paths: list = None,
                    max_pairs: int = 2) -> list:
    """结构化 (sink_code, guard_code|None) 对（v19 仲裁层/离线试点用）。

    与 guard_dom_facts 同一识别口径（CALL+CODE sink、对齐守卫支配链），
    但返回未截断的代码对而非格式化事实行——二次精审 prompt 需要
    完整的守卫代码与 sink 代码。max_pairs 与事实行一致（Top-K 路径
    上的 sink 优先）。
    """
    if G is None or G.number_of_nodes() == 0:
        return []
    H = _cfg_subgraph(G)
    if H.number_of_nodes() == 0:
        return []
    cfg_sinks = {n for n, nd in H.nodes(data=True) if _is_sink_node(nd)}
    if not cfg_sinks:
        return []
    entry = _pick_entry(H, cfg_sinks)
    if entry is None:
        return []
    reach = {entry} | nx.descendants(H, entry)
    try:
        idom = nx.immediate_dominators(H.subgraph(reach).copy(), entry)
    except Exception:
        return []

    sink_order, seen = [], set()
    for path in (topk_paths or []):
        for nid in path:
            if nid in cfg_sinks and nid not in seen:
                sink_order.append(nid)
                seen.add(nid)
    for n in H.nodes:
        if n in cfg_sinks and n not in seen:
            sink_order.append(n)
            seen.add(n)

    pairs = []
    for sid in sink_order[:max_pairs]:
        if sid not in reach:
            continue
        sink_code = (H.nodes.get(sid, {}).get("code") or "").strip()
        if not sink_code:
            continue
        best_guard, best_len = None, 0
        for gid in _dominator_chain(idom, entry, sid):
            if gid == sid:
                continue
            gcode = _guard_code_of(H.nodes.get(gid, {}))
            if gcode and _is_guard(gcode) and _aligned_idents(gcode, sink_code):
                if len(gcode) > best_len:
                    best_guard, best_len = gcode, len(gcode)
        pairs.append((sink_code, best_guard))
    return pairs


def guard_dom_facts(G: nx.MultiDiGraph, topk_paths: list = None,
                    max_facts: int = 2, max_line: int = 70) -> list:
    """生成 GUARD-DOM 事实行（供 Step1 上下文，只呈现事实不带判词）。

    事实行格式（行长 ≤ max_line+3）：
      DOM-GUARD: <sink代码> | aligned guard dominates: <守卫代码>
      DOM-GUARD: <sink代码> | no aligned guard dominates

    sink = CFG 子图内 CALL 类节点 CODE 命中危险 API，Top-K 路径上的优先
    （LLM 正在看的那批证据），不足再取图内其余 sink。守卫 = sink 支配者
    中与 sink 变量对齐的守卫（code 最长者，条件表达式越长信息越多）。
    返回空 = 无 sink 或支配不可算（SG 压缩破坏 CFG 连通性时该层静默
    省略，不影响其他层）。
    """
    if G is None or G.number_of_nodes() == 0:
        return []

    H = _cfg_subgraph(G)
    if H.number_of_nodes() == 0:
        return []
    cfg_sinks = {n for n, nd in H.nodes(data=True) if _is_sink_node(nd)}
    if not cfg_sinks:
        return []
    entry = _pick_entry(H, cfg_sinks)
    if entry is None:
        return []
    reach = {entry} | nx.descendants(H, entry)
    try:
        idom = nx.immediate_dominators(H.subgraph(reach).copy(), entry)
    except Exception:
        return []

    # Top-K 路径上的 sink 优先，图内其余 sink 补位
    sink_order, seen = [], set()
    for path in (topk_paths or []):
        for nid in path:
            if nid in cfg_sinks and nid not in seen:
                sink_order.append(nid)
                seen.add(nid)
    for n in H.nodes:
        if n in cfg_sinks and n not in seen:
            sink_order.append(n)
            seen.add(n)

    facts = []
    for sid in sink_order[:max_facts]:
        if sid not in reach:
            continue  # SG 压缩破坏连通性：不可达 sink 支配不可算，跳过
        sink_code = (H.nodes.get(sid, {}).get("code") or "").strip()
        if not sink_code:
            continue
        best_guard, best_len = None, 0
        for gid in _dominator_chain(idom, entry, sid):
            if gid == sid:
                continue
            gcode = _guard_code_of(H.nodes.get(gid, {}))
            if gcode and _is_guard(gcode) and _aligned_idents(gcode, sink_code):
                if len(gcode) > best_len:
                    best_guard, best_len = gcode, len(gcode)
        facts.append(_fact_line(sink_code, best_guard, max_line))
    return facts
