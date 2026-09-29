import re
import networkx as nx
from config import MAX_PATH_HOP, DANGEROUS_APIS, TAINT_SOURCES, MEMORY_OPS

# 联合 API 集合：危险操作 + 污点源 + 内存操作
ALL_SECURITY_APIS = DANGEROUS_APIS | TAINT_SOURCES | MEMORY_OPS

# Joern 4.x DOT 节点类型（能携带函数名的类型）
# POST_DOMINATE: name='select', method='select'（函数调用）
# BINDS:         name='DS_Sleep', method='DS_Sleep'（函数定义/绑定）
# DOMINATE:      name='mSecs'（变量名，非函数名——但不浪费，某些场景下有用）
FUNC_NAME_NODE_TYPES = {"POST_DOMINATE", "BINDS", "DOMINATE"}

# 通用回退节点类型（当两阶段匹配也失败时）
FALLBACK_NODE_TYPES = {
    "REACHING_DEF",  # 数据流到达定义
    "REF",           # 变量引用
    "CONTAINS",      # 包含关系（可能含函数调用表达式）
    "AST",           # AST 节点
}

# 边优先级：数据流边 > 控制依赖 > 调用 > 定义/引用 > AST
RELEVANT_EDGE_TYPES = {
    "REACHING_DEF", "DFG", "DEF", "REF",
    "CFG", "CDG", "CONTROLS",
    "CALL", "ALIAS_OF",
    "AST", "IS_AST_PARENT",
    "PDG", "DDG",
}


def _extract_api_calls_from_source(source_code: str) -> set:
    """
    阶段1：从 C 源码中提取所有安全相关 API 调用名。

    策略：
      - 匹配形如 `malloc(`, `free(`, `strcpy(` 的函数调用模式
      - 只保留在 ALL_SECURITY_APIS 集合中的函数名

    返回: {"malloc", "free", "strcpy", ...}
    """
    if not source_code:
        return set()

    found = set()

    for api in ALL_SECURITY_APIS:
        # 匹配函数调用模式: `api(` 或 `api (`（大小写敏感：C 语言函数名区分大小写）
        if re.search(r'\b' + re.escape(api) + r'\s*\(', source_code):
            found.add(api)
        # 也匹配 `= api` 模式（函数指针赋值）
        elif re.search(r'=\s*' + re.escape(api) + r'\b', source_code):
            found.add(api)

    return found


def _map_api_to_dot_nodes(G: nx.MultiDiGraph, api_names: set) -> set:
    r"""
    阶段2：将源码中提取的 API 名称映射到 Joern DOT 节点。

    BUG-01 修复（2026-09-17 审查报告）：Joern 4.x --repr all DOT 中
    POST_DOMINATE/BINDS/DOMINATE/CONTAINS 全部是**边标签**而非节点类型；
    节点类型是 CALL/IDENTIFIER/BLOCK/METHOD/...。旧实现依赖 load_graph
    的边标签污染 bug 才能命中，修复后恒为 0。

    新映射方式（_audit_fix_probe2.py 已验证，sample_000194 命中 2 起点
    /10 起点 606 条路径）：
      1. 全节点类型：name 字段词边界匹配 API（CALL 的 NAME=函数名）
      2. 全节点类型：method（METHOD_FULL_NAME）词边界匹配
         （覆盖 <operator> 之外的真实调用，如 METHOD_FULL_NAME="memcpy"）
      3. 全节点类型：code 字段 `\bapi\s*\(` 调用模式
         （覆盖 BLOCK 整块文本中宏内 API——Joern NewC 不展开宏）
    """
    import re as _re

    # 预编译：api 名全部小写（与字段 lower 后对比）
    api_res = {
        api: _re.compile(r'\b' + _re.escape(api.lower()) + r'\b')
        for api in api_names
    }
    api_call_res = {
        api: _re.compile(r'\b' + _re.escape(api.lower()) + r'\s*\(')
        for api in api_names
    }

    mapped_nodes = set()

    for nid in G.nodes():
        nd = G.nodes[nid]
        name = (nd.get("name") or "").lower()
        method = (nd.get("method") or "").lower()
        code = (nd.get("code") or "").lower()

        matched = False
        for api, r in api_res.items():
            # name/method 词边界（BUG-23：'free' 不再命中 'freeall'）
            if name and r.search(name):
                matched = True
                break
            if method and r.search(method):
                matched = True
                break
            # code 的调用模式（"api(" 形式，避免变量名误命中）
            if code and api_call_res[api].search(code):
                matched = True
                break
        if matched:
            mapped_nodes.add(nid)

    return mapped_nodes


def _fallback_by_label(G: nx.MultiDiGraph) -> set:
    r"""
    最终回退：当源码 API 提取/映射都失败时的起点选择。

    BUG-01 修复：旧版按 CONTAINS/REACHING_DEF/AST/REF 等**边标签**筛选
    节点类型，修复后恒为 0。改为 Joern 4.x 语义：取 CALL 节点中
    连接度最高的若干个（真实调用点，METHOD_FULL_NAME 携带函数名），
    限量防止组合爆炸。

    二级回退（API-less 纯逻辑函数，如 sample_000438：112 个 CALL 全是
    <operator>）：无真实调用时，取安全相关运算符节点作起点——下标访问/
    解引用/比较运算正是越界与空指针逻辑缺陷的证据所在。
    """
    real_calls = []
    op_calls = []
    for nid in G.nodes():
        nd = G.nodes[nid]
        if nd.get("node_type") != "CALL":
            continue
        method = nd.get("method", "")
        if not method:
            continue
        deg = G.degree(nid)
        if not method.startswith("<operator>"):
            real_calls.append((nid, deg))
        elif any(op in method for op in _SECURITY_RELEVANT_OPERATORS):
            op_calls.append((nid, deg))

    # BUG-04：按度数降序 + 节点 id 排序（跨进程可复现），限量 20 个起点
    def _sort_key(x):
        return (-x[1], int(x[0]) if str(x[0]).isdigit() else 0)

    pool = real_calls if real_calls else op_calls
    pool.sort(key=_sort_key)
    return {nid for nid, _ in pool[:20]}


# 安全相关运算符（二级回退用）：下标访问/解引用/比较/逻辑非
_SECURITY_RELEVANT_OPERATORS = (
    "indexAccess", "indirectIndexAccess", "indirection",
    "lessThan", "lessEqualsThan", "greaterThan", "greaterEqualsThan",
    "equals", "notEquals", "logicalNot",
)


def extract_candidate_paths_from_node(
    G: nx.MultiDiGraph,
    start_node: str,
    max_hop: int = MAX_PATH_HOP,
    max_paths_per_node: int = 5000,
) -> list:
    """
    从指定起点出发，沿多关系边（DFG/CFG/CALL/CONTROLS/ALIAS_OF）提取候选路径。
    返回 list of list[node_id]。

    边优先级：数据流边优先遍历，保证更可能传播漏洞的路径先被提取。

    Args:
        max_paths_per_node: 每个起点最多提取的路径数，防止组合爆炸
    """
    paths = []

    def dfs(node: str, current: list, depth: int):
        if len(paths) >= max_paths_per_node:
            return  # 已到达上限，提前终止
        if depth > max_hop:
            return
        # 按边类型优先级排序：数据流优先，调用其次，最后是控制流和AST
        outgoing = list(G.out_edges(node, data=True))
        # 给数据流边更高优先级，保证它们先被遍历
        def edge_priority(edge_info):
            _, _, edata = edge_info
            et = edata.get("edge_type", "")
            if any(t in et for t in ("REACHING_DEF", "DFG", "DEF", "REF")):
                return 0
            elif any(t in et for t in ("CFG", "CDG", "CONTROLS")):
                return 1
            elif any(t in et for t in ("CALL", "ALIAS_OF")):
                return 2
            elif any(t in et for t in ("AST", "IS_AST_PARENT")):
                return 3
            else:
                return 4
        outgoing.sort(key=edge_priority)

        for _, nxt, edata in outgoing:
            if len(paths) >= max_paths_per_node:
                return
            edge_type = edata.get("edge_type", "")
            if edge_type not in RELEVANT_EDGE_TYPES:
                continue
            if nxt in current:
                continue  # 避免环
            new_path = current + [nxt]
            paths.append(new_path)
            dfs(nxt, new_path, depth + 1)

    dfs(start_node, [start_node], 0)
    return paths


def extract_all_candidate_paths(
    G: nx.MultiDiGraph,
    max_hop: int = MAX_PATH_HOP,
    max_total_paths: int = 50000,
    max_paths_per_node: int = 5000,
    source_code: str = None,
    verbose: bool = True,
) -> list:
    """
    从图中所有感兴趣节点出发，提取候选路径。

    起点识别采用两阶段策略（适配 Joern 4.x --repr all DOT 格式）：

      **阶段1**：在 C 源码中通过正则匹配安全相关 API 调用名
        - 匹配模式：`malloc(`, `free(`, `strcpy(` 等
        - 提取到的 API 名称集合 → 进入阶段2

      **阶段2**：将 API 名称映射到 Joern DOT 节点
        - 遍历 POST_DOMINATE / BINDS / DOMINATE 节点
        - 检查 name/method 字段是否匹配阶段1提取的 API 名称
        - 匹配成功的节点作为起点

      **回退**：若两阶段匹配均为 0，则按 DOT node_type 类型筛选
        - REACHING_DEF / CONTAINS / AST / REF 等

    Args:
        source_code: 原始 C 源码（用于阶段1 API 提取）。为 None 时使用旧式匹配。
    """
    all_paths = []
    start_nodes = set()
    api_names = set()

    # ── 阶段1 + 阶段2：源码 API 提取 → DOT 节点映射 ──
    if source_code:
        api_names = _extract_api_calls_from_source(source_code)
        if verbose:
            print(f"[CandidatePaths] 阶段1: 从源码提取 {len(api_names)} 个安全 API: "
                  f"{sorted(api_names)[:15]}...")

        if api_names:
            start_nodes = _map_api_to_dot_nodes(G, api_names)
            if verbose:
                if start_nodes:
                    print(f"[CandidatePaths] 阶段2: 映射到 {len(start_nodes)} 个 DOT 节点 "
                          f"(POST_DOMINATE/BINDS/DOMINATE)")
                else:
                    print("[CandidatePaths] 阶段2: DOT 节点不含 API 名称 "
                          "(Joern 4.x 限制)，直接使用 node_type 回退策略")
        else:
            if verbose:
                print("[CandidatePaths] 阶段1: 源码中未找到安全 API")

    # ── DOT text 字段直接匹配（source_code=None 或阶段2为0时的降级策略）──
    if not start_nodes and not source_code:
        for nid in G.nodes():
            nd = G.nodes[nid]
            code = nd.get("code", "").lower()
            name = nd.get("name", "").lower()
            method = nd.get("method", "").lower()
            combined = f"{code} {name} {method}"

            if any(api.lower() in combined for api in DANGEROUS_APIS):
                start_nodes.add(nid)
            elif any(t.lower() in combined for t in TAINT_SOURCES):
                start_nodes.add(nid)
            elif any(op.lower() in combined for op in MEMORY_OPS):
                start_nodes.add(nid)

    # ── 最终回退：按 DOT node_type 筛选 ──
    if not start_nodes:
        if verbose:
            print("[CandidatePaths] 所有匹配为 0，回退到 DOT node_type 筛选...")
        start_nodes = _fallback_by_label(G)

    if verbose:
        print(f"[CandidatePaths] 从 {len(start_nodes)} 个感兴趣节点出发提取路径...")

    # BUG-04：set 迭代顺序受 PYTHONHASHSEED 影响 → 路径枚举顺序跨进程
    # 不可复现（位置偏置项 +13~29 分 → Top-K 漂移）。排序后迭代。
    for nid in sorted(start_nodes, key=lambda x: int(x) if str(x).isdigit() else 0):
        if len(all_paths) >= max_total_paths:
            break
        paths = extract_candidate_paths_from_node(
            G, nid, max_hop, max_paths_per_node
        )
        all_paths.extend(paths[:max_total_paths - len(all_paths)])

    unique_paths = []
    seen = set()
    for p in all_paths:
        path_tuple = tuple(p)
        if path_tuple not in seen:
            seen.add(path_tuple)
            unique_paths.append(p)

    if verbose:
        print(f"[CandidatePaths] 共提取 {len(all_paths)} 条，去重后 {len(unique_paths)} 条候选路径")
    return unique_paths