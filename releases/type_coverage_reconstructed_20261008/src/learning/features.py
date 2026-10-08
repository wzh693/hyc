"""
节点重要性特征提取（技术点①压缩 + ②路径排序 共享）。

v2：全量训练实证 anchor_sep≈0（节点自身特征无法区分漏洞/良性锚点），
新增上下文特征层：
  - 图级 API 组合（write/free/alloc/taint 族计数）——"函数里有什么"
  - 1-hop 邻域族聚合 —— "节点周围是什么"
  - 漏洞类型提示 one-hot（detect_vuln_type_hint）——"函数整体像什么漏洞"
学习目标从"绝对危险性"升级为"局部证据在漏洞/良性上下文中的判别力"。
"""

import re
import math
import numpy as np
import networkx as nx
from config import DANGEROUS_APIS, TAINT_SOURCES, MEMORY_OPS, BACKSTOP_SINK_APIS

FREE_FAMILY = {"free", "av_free", "av_freep", "kfree", "munmap", "fclose"}
ALLOC_FAMILY = {
    "malloc", "calloc", "realloc", "alloca", "mmap",
    "av_malloc", "av_calloc", "av_realloc", "av_mallocz", "av_malloc_array",
    "kmalloc", "kzalloc", "kcalloc", "strdup", "av_strdup",
}
FMT_FAMILY = {"printf", "fprintf", "sprintf", "snprintf"}

_ALL_APIS = (DANGEROUS_APIS | TAINT_SOURCES | MEMORY_OPS | BACKSTOP_SINK_APIS |
             FREE_FAMILY | ALLOC_FAMILY | FMT_FAMILY)
_RE_CACHE = {api: re.compile(r'\b' + re.escape(api.lower()) + r'\b') for api in _ALL_APIS}


def _hit(code_lower: str, api_set: set) -> bool:
    return any(_RE_CACHE[a].search(code_lower) for a in api_set)


def _count_hit(code_lower: str, api_set: set) -> int:
    return sum(1 for a in api_set if _RE_CACHE[a].search(code_lower))


# ── 上下文特征（v2 新增）──
_HINT_KEYS = ["UAF", "DoubleFree", "Overflow", "NullDeref", "FmtStr"]


def _node_family_flags(G: nx.MultiDiGraph) -> dict:
    """预计算每个节点的 API 族标志 {nid: [write, free, alloc, taint, fmt]}。"""
    flags = {}
    for nid, ndata in G.nodes(data=True):
        code = (ndata.get("code") or "").lower()
        flags[nid] = (
            _hit(code, BACKSTOP_SINK_APIS),
            _hit(code, FREE_FAMILY),
            _hit(code, ALLOC_FAMILY),
            _hit(code, TAINT_SOURCES),
            _hit(code, FMT_FAMILY),
        )
    return flags


def _graph_context(G: nx.MultiDiGraph, code: str = None) -> dict:
    """图级上下文 + 漏洞类型提示（所有节点共享）。"""
    ff = _node_family_flags(G)
    n_write = sum(1 for f in ff.values() if f[0])
    n_free = sum(1 for f in ff.values() if f[1])
    n_alloc = sum(1 for f in ff.values() if f[2])
    n_taint = sum(1 for f in ff.values() if f[3])
    n_fmt = sum(1 for f in ff.values() if f[4])

    ctx = {
        "g_log_nodes": math.log1p(G.number_of_nodes()),
        "g_log_edges": math.log1p(G.number_of_edges()),
        "g_n_write": math.log1p(n_write),
        "g_n_free": math.log1p(n_free),
        "g_n_alloc": math.log1p(n_alloc),
        "g_n_taint": math.log1p(n_taint),
        "g_n_fmt": math.log1p(n_fmt),
    }

    hint = "Generic"
    if code:
        try:
            from graph.summarize_graph import detect_vuln_type_hint
            hint = detect_vuln_type_hint(code)
        except Exception:
            hint = "Generic"
    for k in _HINT_KEYS:
        ctx["hint_" + k] = 1.0 if hint == k else 0.0
    return ctx


NODE_FEATURE_NAMES = [
    # ── 语义标签（节点自身）──
    "is_dangerous_api", "n_dangerous_apis", "is_write_sink", "is_taint_source",
    "is_memory_op", "is_free_family", "is_alloc_family", "is_fmt_family",
    # ── 节点类型 ──
    "is_call", "is_method", "is_control_structure",
    "is_identifier", "is_literal", "is_block",
    # ── 图拓扑 ──
    "in_degree", "out_degree", "degree_norm",
    "dfg_in", "dfg_out", "cfg_in", "cfg_out", "call_in", "call_out",
    # ── 代码形态 ──
    "code_len", "has_arrow", "has_index", "has_func_call",
    # ── 上下文 v2：图级 API 组合 ──
    "g_log_nodes", "g_log_edges",
    "g_n_write", "g_n_free", "g_n_alloc", "g_n_taint", "g_n_fmt",
    # ── 上下文 v2：1-hop 邻域族聚合 ──
    "nb_write", "nb_free", "nb_alloc", "nb_taint",
    # ── 上下文 v2：漏洞类型提示 one-hot ──
    "hint_UAF", "hint_DoubleFree", "hint_Overflow", "hint_NullDeref", "hint_FmtStr",
]

_N_BASE = 27          # 前 27 维：节点自身特征
_N_GRAPH_CTX = 7       # 图级上下文
_N_NB = 4              # 邻域聚合
_N_HINT = 5            # 漏洞提示


def _edge_stats(G: nx.MultiDiGraph, nid: str) -> dict:
    dfg_in = dfg_out = cfg_in = cfg_out = call_in = call_out = 0
    for _, _, edata in G.in_edges(nid, data=True):
        et = edata.get("edge_type", "") or edata.get("label", "")
        if "REACHING_DEF" in et or "DFG" in et or "DEF" in et:
            dfg_in += 1
        elif "CFG" in et or "CONTROL" in et or "CDG" in et:
            cfg_in += 1
        elif "CALL" in et:
            call_in += 1
    for _, _, edata in G.out_edges(nid, data=True):
        et = edata.get("edge_type", "") or edata.get("label", "")
        if "REACHING_DEF" in et or "DFG" in et or "DEF" in et:
            dfg_out += 1
        elif "CFG" in et or "CONTROL" in et or "CDG" in et:
            cfg_out += 1
        elif "CALL" in et:
            call_out += 1
    return {"dfg_in": dfg_in, "dfg_out": dfg_out,
            "cfg_in": cfg_in, "cfg_out": cfg_out,
            "call_in": call_in, "call_out": call_out}


def extract_node_features(G: nx.MultiDiGraph, nid: str,
                          ctx: dict = None, family_flags: dict = None,
                          n_nodes: int = None) -> np.ndarray:
    """提取单节点特征向量（与 NODE_FEATURE_NAMES 顺序一致）。"""
    if n_nodes is None:
        n_nodes = max(G.number_of_nodes(), 1)
    if ctx is None:
        ctx = _graph_context(G)
    if family_flags is None:
        family_flags = _node_family_flags(G)

    nd = G.nodes[nid]
    code = (nd.get("code") or "")
    code_lower = code.lower()
    node_type = nd.get("node_type", "") or ""
    es = _edge_stats(G, nid)

    # 邻域族聚合（1-hop）
    nb_write = nb_free = nb_alloc = nb_taint = 0
    for u in G.predecessors(nid):
        f = family_flags.get(u)
        if f:
            nb_write += f[0]; nb_free += f[1]; nb_alloc += f[2]; nb_taint += f[3]
    for v in G.successors(nid):
        f = family_flags.get(v)
        if f:
            nb_write += f[0]; nb_free += f[1]; nb_alloc += f[2]; nb_taint += f[3]

    feats = [
        float(_hit(code_lower, DANGEROUS_APIS)),
        float(_count_hit(code_lower, DANGEROUS_APIS)),
        float(_hit(code_lower, BACKSTOP_SINK_APIS)),
        float(_hit(code_lower, TAINT_SOURCES)),
        float(_hit(code_lower, MEMORY_OPS)),
        float(_hit(code_lower, FREE_FAMILY)),
        float(_hit(code_lower, ALLOC_FAMILY)),
        float(_hit(code_lower, FMT_FAMILY)),
        float("CALL" in node_type),
        float("METHOD" in node_type),
        float("CONTROL_STRUCTURE" in node_type),
        float("IDENTIFIER" in node_type),
        float("LITERAL" in node_type),
        float("BLOCK" in node_type),
        math.log1p(G.in_degree(nid)),
        math.log1p(G.out_degree(nid)),
        G.degree(nid) / n_nodes,
        math.log1p(es["dfg_in"]), math.log1p(es["dfg_out"]),
        math.log1p(es["cfg_in"]), math.log1p(es["cfg_out"]),
        math.log1p(es["call_in"]), math.log1p(es["call_out"]),
        math.log1p(len(code)),
        float("->" in code),
        float("[" in code),
        float(bool(re.search(r'\w\s*\(', code))),
        # 上下文：图级
        ctx["g_log_nodes"], ctx["g_log_edges"],
        ctx["g_n_write"], ctx["g_n_free"], ctx["g_n_alloc"],
        ctx["g_n_taint"], ctx["g_n_fmt"],
        # 上下文：邻域
        math.log1p(nb_write), math.log1p(nb_free),
        math.log1p(nb_alloc), math.log1p(nb_taint),
        # 上下文：漏洞提示
        ctx["hint_UAF"], ctx["hint_DoubleFree"], ctx["hint_Overflow"],
        ctx["hint_NullDeref"], ctx["hint_FmtStr"],
    ]
    return np.asarray(feats, dtype=np.float32)


def graph_feature_matrix(G: nx.MultiDiGraph, code: str = None):
    """整图特征矩阵。返回 (nids, X, nid_to_row)。code 用于漏洞类型提示。"""
    nids = list(G.nodes())
    n_nodes = max(len(nids), 1)
    ctx = _graph_context(G, code)
    family_flags = _node_family_flags(G)
    X = np.zeros((len(nids), len(NODE_FEATURE_NAMES)), dtype=np.float32)
    nid_to_row = {}
    for row, nid in enumerate(nids):
        nid_to_row[nid] = row
        X[row] = extract_node_features(G, nid, ctx=ctx, family_flags=family_flags,
                                       n_nodes=n_nodes)
    return nids, X, nid_to_row
