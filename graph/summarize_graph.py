"""
漏洞感知图压缩 (Vulnerability-aware Graph Summarization) v2.0

增强功能：
  1. 动态 Token 预算感知：根据可用上下文窗口自适应调整压缩率
  2. 分级压缩策略：budget 充足时保留更多细节，不足时激进压缩
  3. 缩减率统计：精确报告原始 vs 压缩后的节点/边/估计token数
"""

import re as _re
import networkx as nx
from collections import deque
from typing import Set, List, Tuple, Optional, Dict
from config import DANGEROUS_APIS, TAINT_SOURCES, MEMORY_OPS, MAX_PATH_HOP, LEARNED_NODE_WEIGHT


# 每节点/边估计token消耗（用于预算计算）
NODE_TOKEN_ESTIMATE = 8  # 平均每个节点序列化约消耗 8 tokens
EDGE_TOKEN_ESTIMATE = 4  # 平均每条边序列化约消耗 4 tokens


def _contains_any(code: str, api_set: set) -> bool:
    """检查代码中是否包含集合中的任意 API（词边界匹配）。"""
    code_lower = code.lower()
    return any(_re.search(r'\b' + _re.escape(api.lower()) + r'\b', code_lower) for api in api_set)


def _count_occurrences(code: str, api_set: set) -> int:
    """统计代码中 API 集合的实际出现总次数（词边界匹配）。

    v22 修复：原实现 sum(1 for api if search) 统计的是"命中的不同 API
    种类数"而非出现次数——语义与函数名/调用方（dangerous_api 权重 ×
    出现次数）不符。BLOCK 节点含多个同类调用时按实际次数计分。
    """
    code_lower = code.lower()
    return sum(
        len(_re.findall(r'\b' + _re.escape(api.lower()) + r'\b', code_lower))
        for api in api_set
    )


def estimate_token_usage(G: nx.MultiDiGraph) -> int:
    """
    估计子图线性化后的 token 消耗量。
    用于动态预算感知压缩中的预算检查。
    """
    return (G.number_of_nodes() * NODE_TOKEN_ESTIMATE +
            G.number_of_edges() * EDGE_TOKEN_ESTIMATE)


def compute_adaptive_token_budget(
    G: nx.MultiDiGraph,
    source_code: str = "",
    base_budget: int = 3072,
    min_budget: int = 2048,
    max_budget: int = 5120,
) -> int:
    """
    根据图复杂度和代码长度自适应计算 token_budget。

    策略：
      - 基础预算 = base_budget
      - 节点数多 → 预算↑（但不超过 max_budget）
      - 代码短 → 预算↓（节省 token）
      - 有漏洞模式 → 预算↑（保留更多证据）
    """
    n_nodes = G.number_of_nodes()
    n_edges = G.number_of_edges()
    code_len = len(source_code) if source_code else 1000

    complexity_factor = (n_nodes / 100.0 + n_edges / 200.0) / 2.0
    code_factor = min(code_len / 2000.0, 2.0)

    vuln_bonus = 1.0
    if source_code:
        vtype = detect_vuln_type_hint(source_code)
        if vtype != "Generic":
            vuln_bonus = 1.2

    budget = int(base_budget * (0.5 + 0.3 * complexity_factor + 0.2 * code_factor) * vuln_bonus)
    budget = max(min_budget, min(budget, max_budget))

    return budget


def detect_vuln_type_hint(code: str) -> str:
    """
    从源码中检测最可能的漏洞类型，用于条件权重选择。

    返回: "UAF" | "DoubleFree" | "Overflow" | "NullDeref" | "FmtStr" | "Generic"
    """
    code_lower = code.lower()

    free_vars = _re.findall(r'\b(?:free|kfree|av_free|av_freep)\s*\(\s*(\w+)\s*\)', code)
    has_free = len(free_vars) > 0
    has_alloc = bool(_re.search(r'\b(?:malloc|calloc|realloc|kmalloc|kzalloc)\b', code_lower))
    has_deref_after_free = False
    for var in set(free_vars):
        if _re.search(rf'\b{_re.escape(var)}\b\s*(?:->|\[|\.\w+\s*\()', code):
            has_deref_after_free = True
            break

    if has_free and has_deref_after_free:
        return "UAF"
    if has_free and len(set(free_vars)) < len(free_vars):
        return "DoubleFree"

    has_unsafe_copy = bool(_re.search(r'\b(?:strcpy|strcat|sprintf|gets)\b', code_lower))
    has_taint = bool(_re.search(r'\b(?:recv|read|fgets|scanf)\b', code_lower))
    if has_unsafe_copy and (has_taint or has_alloc):
        return "Overflow"

    if has_alloc:
        for var in _re.findall(r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc|kmalloc)\b', code):
            if not _re.search(rf'\b{_re.escape(var)}\s*(?:==|!=)\s*(?:NULL|0)\b', code):
                if not _re.search(rf'if\s*\(\s*!?\s*{_re.escape(var)}\b', code):
                    return "NullDeref"

    # FmtStr：printf 格式串=第 1 参数，fprintf 格式串=第 2 参数。
    # v17（BUG-10 激活时修正）：原正则对两者都取第 1 参数，导致
    # fprintf(stderr, "literal") 这类日志调用全部误判 FmtStr。
    fmt_args = _re.findall(r'\bprintf\s*\(\s*([^,")]+)', code)
    fmt_args += _re.findall(r'\bfprintf\s*\(\s*[^,]+,\s*([^,")]+)', code)
    for arg in fmt_args:
        if not arg.strip().startswith('"'):
            return "FmtStr"

    return "Generic"


VULN_CONDITIONAL_WEIGHTS = {
    "UAF": {
        "dangerous_api": 7.0,
        "taint_source": 3.0,
        "memory_op": 6.0,
        "dfg_participation": 1.0,
        "cfg_participation": 0.8,
    },
    "DoubleFree": {
        "dangerous_api": 5.0,
        "taint_source": 2.0,
        "memory_op": 8.0,
        "dfg_participation": 0.8,
        "cfg_participation": 1.0,
    },
    "Overflow": {
        "dangerous_api": 8.0,
        "taint_source": 7.0,
        "memory_op": 3.0,
        "dfg_participation": 1.2,
        "cfg_participation": 0.5,
    },
    "NullDeref": {
        "dangerous_api": 4.0,
        "taint_source": 2.0,
        "memory_op": 7.0,
        "dfg_participation": 0.8,
        "cfg_participation": 1.0,
    },
    "FmtStr": {
        "dangerous_api": 8.0,
        "taint_source": 6.0,
        "memory_op": 2.0,
        "dfg_participation": 1.0,
        "cfg_participation": 0.5,
    },
    "Generic": {
        "dangerous_api": 5.0,
        "taint_source": 4.0,
        "memory_op": 3.0,
        "dfg_participation": 0.5,
        "cfg_participation": 0.3,
    },
}


def score_node(G: nx.MultiDiGraph, node_id: str, vuln_type: str = "Generic") -> float:
    """
    增强版节点重要性打分（漏洞类型条件权重）。

    综合考虑六维因素，权重根据检测到的漏洞类型动态调整：
      1. 节点类型权重（CALL/METHOD 等语义权重）
      2. 危险 API 关联度
      3. 污点源关联度
      4. 内存操作关联度
      5. 图拓扑重要性（度中心性）
      6. 数据流/控制流参与度
    """
    node = G.nodes[node_id]
    code = node.get("code", "")
    node_type = node.get("node_type", "")

    cw = VULN_CONDITIONAL_WEIGHTS.get(vuln_type, VULN_CONDITIONAL_WEIGHTS["Generic"])

    score = 0.0

    type_weights = {
        "CALL": 3.0, "METHOD": 2.0, "METHOD_PARAMETER_IN": 1.5,
        "METHOD_PARAMETER_OUT": 1.5, "METHOD_RETURN": 2.0, "LOCAL": 1.0,
        "IDENTIFIER": 1.0, "LITERAL": 0.3, "BLOCK": 0.5,
        "CONTROL_STRUCTURE": 1.5, "FIELD_IDENTIFIER": 1.0, "RETURN": 1.0,
        "UNKNOWN": 0.5, "JUMP_TARGET": 1.0, "TAG": 0.5, "MEMBER": 1.0,
        "ARGUMENT": 1.0, "MODIFIER": 0.5, "TYPE_DECL": 0.5,
        "NAMESPACE_BLOCK": 0.3, "METHOD_REF": 1.5, "TYPE_REF": 0.5,
    }
    type_matched = False
    for key, weight in type_weights.items():
        if key in node_type:
            score += weight
            type_matched = True
            break
    if not type_matched:
        score += 0.5

    if _contains_any(code, DANGEROUS_APIS):
        score += cw["dangerous_api"] * max(1, _count_occurrences(code, DANGEROUS_APIS))

    if _contains_any(code, TAINT_SOURCES):
        score += cw["taint_source"]

    if _contains_any(code, MEMORY_OPS):
        score += cw["memory_op"]

    # 5. 度中心性（归一化）- 提升拓扑重要性
    degree = G.degree(node_id)
    score += min(degree / max(G.number_of_nodes() * 0.05, 1), 5.0)

    # 6. 数据流/控制流参与度 - 更全面的边类型覆盖
    dfg_count = 0
    cfg_count = 0
    call_count = 0
    for _, _, edata in G.out_edges(node_id, data=True):
        et = edata.get("edge_type", "")
        if "DFG" in et or "REACHING_DEF" in et or "DEF" in et:
            dfg_count += 1
        elif "CFG" in et or "CONTROL" in et:
            cfg_count += 1
        elif "CALL" in et:
            call_count += 1
    for _, _, edata in G.in_edges(node_id, data=True):
        et = edata.get("edge_type", "")
        if "DFG" in et or "REACHING_DEF" in et or "DEF" in et:
            dfg_count += 1
        elif "CFG" in et or "CONTROL" in et:
            cfg_count += 1
        elif "CALL" in et:
            call_count += 1
    score += min(dfg_count * cw["dfg_participation"], 3.0)
    score += min(cfg_count * cw["cfg_participation"], 2.0)
    score += min(call_count * 0.3, 2.0)

    return score


def score_edge(G: nx.MultiDiGraph, u: str, v: str, key: int) -> float:
    """
    边重要性打分。
    优先保留数据流、控制流、调用边，弱化纯语法边（AST）。
    """
    edge_data = G.get_edge_data(u, v, key)
    if edge_data is None:
        return 0.0
    edge_type = edge_data.get("edge_type", "")

    edge_weights = {
        "REACHING_DEF": 5.0,
        "DFG": 5.0,
        "CFG": 4.0,
        "CALL": 4.0,
        "CONTROLS": 3.0,
        "ALIAS_OF": 3.0,
        "CDG": 3.0,
        "DEF": 4.0,
        "AST": 0.5,
        "REF": 1.0,
        "IS_AST_PARENT": 0.3,
        "CONTAINS": 0.3,
        "SOURCE_FILE": 0.1,
        "EVAL_TYPE": 1.0,
        "PARENT": 0.5,
        "BINDS": 1.0,
        "CAPTURE": 0.5,
        "RECEIVER": 0.5,
        "ARGUMENT": 1.0,
    }
    for key_w, weight in edge_weights.items():
        if key_w in edge_type:
            return weight
    return 1.0


def _adjust_threshold_for_budget(
    G: nx.MultiDiGraph,
    node_scores: dict,
    force_keep: set,
    token_budget: int,
    base_threshold: float = 1.2,
    min_threshold: float = 0.3,
    max_threshold: float = 5.0,
    verbose: bool = True,
) -> tuple:
    """
    动态调整节点阈值以适配 Token 预算。

    返回值:
        (adjusted_threshold, capped_force_keep)

    capped_force_keep 是当 force_keep 节点太多导致无论如何压缩都超预算时，
    仅保留得分最高的 top-N 危险节点。

    策略：
      1. 二分查找最佳阈值
      2. 若 max_threshold 仍超预算 → 截断 force_keep 集合
      3. 先用严格阈值 + 截断 force_keep 再试
    """
    # 构建当前阈值的保留节点集
    def build_subgraph_with_threshold(thresh, fk_set):
        keep = set()
        for nid in fk_set:
            keep.add(nid)
        for nid, s in node_scores.items():
            if s >= thresh:
                keep.add(nid)
        return keep

    keep_nodes = build_subgraph_with_threshold(base_threshold, force_keep)
    if len(keep_nodes) < 5:
        keep_nodes = build_subgraph_with_threshold(base_threshold * 0.5, force_keep)

    n_nodes = len(keep_nodes)
    n_edges = sum(1 for u, v in G.edges() if u in keep_nodes and v in keep_nodes)
    estimated_tokens = n_nodes * NODE_TOKEN_ESTIMATE + n_edges * EDGE_TOKEN_ESTIMATE

    if verbose:
        print(f"  [Budget] 预估token: {estimated_tokens}, 预算: {token_budget}, "
              f"节点: {n_nodes}, 边: {n_edges}, force_keep: {len(force_keep)}")

    # 在预算范围内（上下浮动20%都接受）
    if estimated_tokens <= token_budget * 1.2:
        if verbose:
            print(f"  [Budget] 阈值 {base_threshold:.2f} 在预算内，无需调整")
        return base_threshold, force_keep

    # ── 阶段1：二分查找最佳阈值 ──
    lo, hi = base_threshold, max_threshold
    best_threshold = base_threshold
    best_tokens = estimated_tokens

    for iteration in range(15):
        mid = (lo + hi) / 2
        keep = build_subgraph_with_threshold(mid, force_keep)
        n_est = len(keep)
        keep_set = keep
        e_est = sum(1 for u, v in G.edges() if u in keep_set and v in keep_set)
        t_est = n_est * NODE_TOKEN_ESTIMATE + e_est * EDGE_TOKEN_ESTIMATE

        if verbose and iteration == 0:
            print(f"  [Budget] 调整阈值至 {mid:.2f} → 预估 {t_est} tokens")

        if t_est <= token_budget:
            best_threshold = mid
            best_tokens = t_est
            lo = mid + 0.1
        else:
            hi = mid
            if iteration >= 14:  # 最后迭代仍超标，记录最佳
                if t_est < best_tokens:
                    best_threshold = mid
                    best_tokens = t_est

        if abs(t_est - token_budget) / token_budget < 0.1:
            break

    if verbose:
        pct = best_tokens / token_budget * 100
        print(f"  [Budget] 二分搜索后阈值: {best_threshold:.2f}, "
              f"预估token: {best_tokens}/{token_budget} ({pct:.0f}%)")

    # ── 阶段2：若仍严重超预算，逐级强化压缩 ──
    if best_tokens > token_budget * 1.5 and len(force_keep) > 5:

        # 策略A：扩展 max_threshold 到 20.0，二分搜索更严格阈值
        hi = 20.0
        for iteration in range(10):
            mid = (best_threshold + hi) / 2
            keep = build_subgraph_with_threshold(mid, force_keep)
            n_est = len(keep)
            e_est = sum(1 for u, v in G.edges() if u in keep and v in keep)
            t_est = n_est * NODE_TOKEN_ESTIMATE + e_est * EDGE_TOKEN_ESTIMATE

            if verbose:
                print(f"  [Budget] 严格阈值 {mid:.1f} → {t_est} tokens ({t_est/token_budget*100:.0f}%)")

            # 安全约束：确保至少保留 min_keep 个节点
            min_keep = max(30, int(G.number_of_nodes() * 0.08))
            if n_est < min_keep:
                if verbose:
                    print(f"  [Budget] 阈值 {mid:.1f} 保留 {n_est} 节点 < 安全下限 {min_keep}，停止加压")
                break

            if t_est <= token_budget * 1.2:
                best_threshold = mid
                best_tokens = t_est
                if verbose:
                    print(f"  [Budget] 严格阈值 {mid:.1f} 达标")
                break
            elif t_est < best_tokens:
                best_threshold = mid
                best_tokens = t_est

            if t_est <= token_budget:
                break
            hi = mid + 1.0

        # 策略B：仍超标则截断 force_keep
        if best_tokens > token_budget * 1.5 and len(force_keep) > 10:
            scored_fk = [(node_scores.get(nid, 0), nid) for nid in force_keep]
            scored_fk.sort(reverse=True)

            for cap in [50, 30, 20, 15, 10, 5]:
                if len(scored_fk) <= cap:
                    break
                capped_fk = {nid for _, nid in scored_fk[:cap]}
                keep = build_subgraph_with_threshold(best_threshold, capped_fk)
                n_est = len(keep)
                e_est = sum(1 for u, v in G.edges() if u in keep and v in keep)
                t_est = n_est * NODE_TOKEN_ESTIMATE + e_est * EDGE_TOKEN_ESTIMATE

                if verbose:
                    print(f"  [Budget] force_keep 截断 {len(force_keep)}→{cap} → "
                          f"{t_est} tokens ({t_est/token_budget*100:.0f}%)")

                if t_est <= token_budget * 1.5:
                    if verbose:
                        print(f"  [Budget] 截断后达标")
                    return max(best_threshold, 2.0), capped_fk

            # 最终保底：top-5 force_keep
            capped_fk = {nid for _, nid in scored_fk[:5]}
            if verbose:
                print(f"  [Budget] 强制保底 force_keep 截断至 5")
            return max(best_threshold, 5.0), capped_fk

        # 策略C：force_keep 本身已很少，直接 top-N 节点截断
        if best_tokens > token_budget * 1.5:
            target_nodes = int(token_budget * 1.2 / NODE_TOKEN_ESTIMATE)
            sorted_nodes = sorted(node_scores.items(), key=lambda x: x[1], reverse=True)
            capped_fk = {nid for _, nid in sorted_nodes[:min(target_nodes, 100)]}
            capped_fk.update(force_keep)
            if verbose:
                print(f"  [Budget] 直接截断至 top-{len(capped_fk)} 节点 "
                      f"(预算target={target_nodes})")
            return max(best_threshold, 5.0), capped_fk

    return max(best_threshold, min_threshold), force_keep


def summarize_graph(
    G: nx.MultiDiGraph,
    node_threshold: float = 1.2,
    edge_threshold: float = 0.5,
    token_budget: int = None,
    source_code: str = "",
    verbose: bool = True,
    learned_scores: dict = None,
) -> nx.MultiDiGraph:
    """
    增强版漏洞感知图压缩 v2.0 (Vulnerability-aware Graph Summarization)。

    新增动态预算感知 + 漏洞类型条件权重：
      当 token_budget 指定时，自动调整 node_threshold 以控制子图规模。
      当 source_code 指定时，检测漏洞类型并使用条件权重。
      不指定时，行为与原版一致（向后兼容）。

    技术点①（学习式层次图摘要）：
      learned_scores 指定时，node_score += LEARNED_NODE_WEIGHT * p_learned。
      弱监督模型学习"漏洞函数锚点 vs 良性函数锚点"的判别性，
      force_keep 集合不变（证据保留优先于 token 削减的硬约束），
      仅重排阈值筛选的相对次序并影响预算截断时的取舍。

    参数:
        G: 原始 CPG
        node_threshold: 节点保留阈值（未指定 token_budget 时使用）
        edge_threshold: 边保留阈值
        token_budget: LLM 上下文 token 预算上限
        source_code: 源代码（用于漏洞类型检测和条件权重选择）
        verbose: 是否打印详细信息
        learned_scores: {nid: p} 学习式节点重要性（None = 关闭）

    返回:
        SG: 压缩后的子图
    """
    if G.number_of_nodes() == 0:
        return G

    vuln_type = "Generic"
    if source_code:
        vuln_type = detect_vuln_type_hint(source_code)
        if verbose:
            print(f"  [Summarize] 检测漏洞类型: {vuln_type}")

    node_scores = {nid: score_node(G, nid, vuln_type=vuln_type) for nid in G.nodes()}

    # 强制保留危险 API 节点和污点源节点
    force_keep = set()
    for nid in G.nodes():
        code = G.nodes[nid].get("code", "")
        node_type = G.nodes[nid].get("node_type", "")
        if _contains_any(code, DANGEROUS_APIS) or _contains_any(code, TAINT_SOURCES):
            force_keep.add(nid)
        elif "METHOD" in node_type or "CALL" in node_type:
            if _contains_any(code, MEMORY_OPS):
                force_keep.add(nid)

    # 技术点①：学习式打分（纯惩罚，仅作用于非 force_keep 的背景节点）
    # - force_keep 豁免：证据节点分数不受影响（预算截断排序也不变），
    #   保证证据保留优先于 token 削减的硬约束
    # - 背景 s += W * (rank-1) ∈ [-W, 0]：压缩图是基线的近似子集
    if learned_scores:
        node_scores = {
            nid: (s if nid in force_keep
                  else s + LEARNED_NODE_WEIGHT * learned_scores.get(nid, 0.0))
            for nid, s in node_scores.items()
        }

    # 如果没有识别到任何危险节点，保留结构关键节点（按度排序）
    # 避免 force_keep=0 时过度压缩丢失语义
    if len(force_keep) < 3:
        # 按度数排序取 top-10 结构重要节点
        degree_sorted = sorted(G.degree(), key=lambda x: x[1], reverse=True)
        for nid, deg in degree_sorted[:10]:
            force_keep.add(nid)
        if verbose:
            print(f"  [Summarize] 危险节点不足，替补保留 {len(force_keep)} 个高连接度节点")

    # 记录原始图规模
    orig_nodes = G.number_of_nodes()
    orig_edges = G.number_of_edges()

    # 动态调整阈值（如果指定了 token_budget）
    capped_force_keep = force_keep
    if token_budget is not None and token_budget > 0:
        adjusted_threshold, capped_force_keep = _adjust_threshold_for_budget(
            G, node_scores, force_keep,
            token_budget=token_budget,
            base_threshold=node_threshold,
            verbose=verbose,
        )
        node_threshold = adjusted_threshold

    # 选择保留节点（使用可能已截断的 force_keep）
    keep_nodes = set()
    for nid, s in node_scores.items():
        if s >= node_threshold or nid in capped_force_keep:
            keep_nodes.add(nid)

    # 如果保留节点太少（< 5），降低阈值重新选择
    if len(keep_nodes) < 5:
        if verbose:
            print(f"[Summarize] 保留节点过少 ({len(keep_nodes)})，降低阈值至 {node_threshold * 0.5:.2f}...")
        keep_nodes = set()
        for nid, s in node_scores.items():
            if s >= node_threshold * 0.5 or nid in capped_force_keep:
                keep_nodes.add(nid)

    # 构建子图
    SG = nx.MultiDiGraph()
    for nid in keep_nodes:
        SG.add_node(nid, **G.nodes[nid])

    for u, v, key, edata in G.edges(keys=True, data=True):
        if u in keep_nodes and v in keep_nodes:
            edge_score = score_edge(G, u, v, key)
            if edge_score >= edge_threshold:
                SG.add_edge(u, v, key=key, **edata)

    # 确保高危节点间的连通性：补充最短路径
    # 技术点①：学习式压缩（learned_scores 启用）时施加恢复上限，
    # 防止激进收缩后恢复机制绕过预算回填过多节点（图膨胀反例实证）。
    # 基线（learned_scores=None）行为保持不变（单变量实验纪律）。
    restore_cap = (max(15, int(len(keep_nodes) * 0.3))
                   if learned_scores else None)
    restored = 0
    # BUG-21 修复：set → list 顺序随 PYTHONHASHSEED 变化，先恢复的 pair
    # 先得节点 → SG 跨进程不可复现。排序后迭代。
    force_list = sorted(force_keep, key=lambda x: int(x) if str(x).isdigit() else 0)
    if len(force_list) <= 80:
        force_pairs = [(force_list[i], force_list[j]) for i in range(len(force_list)) for j in range(i + 1, len(force_list))]
    else:
        import random as _rng
        _rng.seed(42)
        force_pairs = _rng.sample([(force_list[i], force_list[j]) for i in range(len(force_list)) for j in range(i + 1, min(i + 6, len(force_list)))], min(2000, len(force_list) * 5))
    for u, v in force_pairs:
        if restore_cap is not None and restored >= restore_cap:
            break
        if SG.has_node(u) and SG.has_node(v):
            if not nx.has_path(SG, u, v) and nx.has_path(G, u, v):
                try:
                    path = nx.shortest_path(G, u, v)
                    for nid in path:
                        if nid not in SG:
                            if restore_cap is not None and restored >= restore_cap:
                                break
                            SG.add_node(nid, **G.nodes[nid])
                            restored += 1
                    for pi in range(len(path) - 1):
                        a, b = path[pi], path[pi + 1]
                        if not SG.has_edge(a, b) and G.has_edge(a, b):
                            edge_data = G.get_edge_data(a, b)
                            for key, edata in edge_data.items():
                                SG.add_edge(a, b, key=key, **edata)
                except nx.NetworkXNoPath:
                    pass

    # 计算缩减率统计
    sg_nodes = SG.number_of_nodes()
    sg_edges = SG.number_of_edges()
    node_reduction = (1 - sg_nodes / orig_nodes) * 100 if orig_nodes > 0 else 0
    edge_reduction = (1 - sg_edges / orig_edges) * 100 if orig_edges > 0 else 0
    est_token_reduction = (1 - estimate_token_usage(SG) / max(estimate_token_usage(G), 1)) * 100

    if verbose:
        print(
            f"[Summarize] {orig_nodes}节点/{orig_edges}边"
            f" -> {sg_nodes}节点/{sg_edges}边"
            f" (强制保留 {len(force_keep)} 个危险节点)"
        )
        print(
            f"  [Reduction] 节点缩减: {node_reduction:.1f}%, "
            f"边缩减: {edge_reduction:.1f}%, "
            f"估计token缩减: {est_token_reduction:.1f}%"
        )

    # 在子图上附加缩减统计信息
    SG.graph["reduction_stats"] = {
        "orig_nodes": orig_nodes,
        "orig_edges": orig_edges,
        "compressed_nodes": sg_nodes,
        "compressed_edges": sg_edges,
        "node_reduction_pct": round(node_reduction, 2),
        "edge_reduction_pct": round(edge_reduction, 2),
        "est_token_reduction_pct": round(est_token_reduction, 2),
        "node_threshold_used": round(node_threshold, 2),
        "force_retained": len(force_keep),
    }

    return SG


def summarize_graph_slice_aware(
    G: nx.MultiDiGraph,
    source_code: str = None,
    token_budget: int = None,
    fallback_threshold: float = 1.2,
    verbose: bool = True,
) -> nx.MultiDiGraph:
    """
    HGL-Vul 增强版图压缩 v2.1 (Vulnerability-dependency Enhanced)。

    将 VulnerabilitySlicer 的 chop 切片结果集成到 HGL-Vul 的
    漏洞感知图压缩流程中，形成"切片优先保留 + 打分补充 + 预算裁剪"
    的三阶段压缩策略：

    Step 1: VulnerabilitySlicer 自动识别 source/sink → chop 切片
    Step 2: 切片节点 100% 保留（漏洞传播链完整性保证）
    Step 3: 切片外节点按原始打分机制补充（上下文不遗漏）
    Step 4: 预算感知微调（复用 HGL-Vul 原有预算逻辑）

    参数:
        G: 原始 CPG
        source_code: 原始 C 源码（用于 source/sink 识别）
        token_budget: LLM 上下文 token 预算
        fallback_threshold: 切片外节点的保留阈值
        verbose: 是否打印详细信息

    返回:
        SG: 切片感知压缩子图
    """
    if G.number_of_nodes() == 0:
        return G

    orig_nodes = G.number_of_nodes()
    orig_edges = G.number_of_edges()

    slice_nodes = set()
    slice_stats = {}

    try:
        slicer = _VulnerabilitySlicer(G)
        slice_nodes, slice_stats = slicer.auto_slice(source_code)
        if verbose:
            print(f"  [Slice-Aware] 切片模式: {slice_stats.get('mode', 'unknown')}, "
                  f"切片节点: {len(slice_nodes)}/{orig_nodes} "
                  f"({slice_stats.get('reduction_pct', 0):.1f}% 缩减)")
    except Exception as e:
        if verbose:
            print(f"  [Slice-Aware] 切片失败 ({e})，回退到标准压缩")

    use_slicing = len(slice_nodes) > 0

    if use_slicing:
        node_scores = {nid: score_node(G, nid) for nid in G.nodes()}

        force_keep = set()
        for nid in G.nodes():
            code = G.nodes[nid].get("code", "")
            node_type = G.nodes[nid].get("node_type", "")
            if _contains_any(code, DANGEROUS_APIS) or _contains_any(code, TAINT_SOURCES):
                force_keep.add(nid)
            elif "METHOD" in node_type or "CALL" in node_type:
                if _contains_any(code, MEMORY_OPS):
                    force_keep.add(nid)

        keep_nodes = set(slice_nodes) | force_keep

        extra_keep = set()
        for nid, s in node_scores.items():
            if nid not in keep_nodes and s >= fallback_threshold:
                extra_keep.add(nid)
        keep_nodes |= extra_keep

        if token_budget is not None and token_budget > 0:
            est_tokens = len(keep_nodes) * NODE_TOKEN_ESTIMATE
            if est_tokens > token_budget * 1.2:
                cap = int(token_budget * 1.2 / NODE_TOKEN_ESTIMATE)
                if len(slice_nodes) > cap * 0.7:
                    sorted_extra = sorted(
                        [(node_scores.get(n, 0), n) for n in extra_keep],
                        reverse=True
                    )
                    extra_limit = max(0, cap - len(slice_nodes))
                    extra_keep = {n for _, n in sorted_extra[:extra_limit]}
                    keep_nodes = set(slice_nodes) | force_keep | extra_keep
                    if verbose:
                        print(f"  [Slice-Aware Budget] 切片节点 {len(slice_nodes)} + "
                              f"额外 {len(extra_keep)} = {len(keep_nodes)}, "
                              f"est={len(keep_nodes)*NODE_TOKEN_ESTIMATE} tokens")
    else:
        return summarize_graph(G, token_budget=token_budget, verbose=verbose)

    SG = nx.MultiDiGraph()
    for nid in keep_nodes:
        SG.add_node(nid, **G.nodes[nid])

    for u, v, key, edata in G.edges(keys=True, data=True):
        if u in keep_nodes and v in keep_nodes:
            edge_score = score_edge(G, u, v, key)
            if edge_score >= 0.3 or (u in slice_nodes and v in slice_nodes):
                SG.add_edge(u, v, key=key, **edata)

    sg_nodes = SG.number_of_nodes()
    sg_edges = SG.number_of_edges()
    node_reduction = (1 - sg_nodes / orig_nodes) * 100 if orig_nodes > 0 else 0
    edge_reduction = (1 - sg_edges / orig_edges) * 100 if orig_edges > 0 else 0

    if verbose:
        print(f"  [Slice-Aware Summarize] {orig_nodes}节点→{sg_nodes}节点 "
              f"({node_reduction:.1f}% 缩减) "
              f"切片贡献: {len(slice_nodes)} 节点")

    SG.graph["reduction_stats"] = {
        "orig_nodes": orig_nodes,
        "orig_edges": orig_edges,
        "compressed_nodes": sg_nodes,
        "compressed_edges": sg_edges,
        "node_reduction_pct": round(node_reduction, 2),
        "edge_reduction_pct": round(edge_reduction, 2),
        "slice_nodes": len(slice_nodes),
        "slice_mode": slice_stats.get("mode", "none"),
        "extra_nodes": len(extra_keep) if use_slicing else 0,
        "force_retained": len(force_keep),
    }

    return SG


# ──────────────────────────────────────────────────────────────────
# 内部依赖优先级切片器 (Internal Vulnerability-dependency Slicer)
# 作为 summarize_graph_slice_aware 的内部增强组件，不对外暴露
# ──────────────────────────────────────────────────────────────────

_BACKWARD_EDGE_TYPES = {
    "REACHING_DEF", "DFG", "DEF",
    "CDG", "CONTROLS",
    "CALL",
    "ALIAS_OF", "REF",
    "CFG",
}

_FORWARD_EDGE_TYPES = {
    "REACHING_DEF", "DFG", "DEF",
    "CFG",
    "CDG",
    "CALL",
    "ALIAS_OF",
    "REF",
}


class _VulnerabilitySlicer:
    """
    内部依赖优先级切片器。

    不对外暴露，仅用于 summarize_graph_slice_aware 内部的
    三步压缩策略中确定"高传播链价值"节点。
    """

    def __init__(self, G: nx.MultiDiGraph):
        self.G = G

    def backward_slice(self, seeds, max_depth=MAX_PATH_HOP, edge_types=None):
        if edge_types is None:
            edge_types = _BACKWARD_EDGE_TYPES
        visited = set()
        from collections import deque
        queue = deque()
        depth = {}
        for node in seeds:
            if self.G.has_node(node):
                queue.append(node)
                visited.add(node)
                depth[node] = 0
        while queue:
            cur = queue.popleft()
            cd = depth[cur]
            if cd >= max_depth:
                continue
            for src, _, edata in self.G.in_edges(cur, data=True):
                et = edata.get("edge_type", "")
                if not self._match(et, edge_types):
                    continue
                if src not in visited:
                    visited.add(src)
                    depth[src] = cd + 1
                    queue.append(src)
        return visited

    def forward_slice(self, seeds, max_depth=MAX_PATH_HOP, edge_types=None):
        if edge_types is None:
            edge_types = _FORWARD_EDGE_TYPES
        visited = set()
        from collections import deque
        queue = deque()
        depth = {}
        for node in seeds:
            if self.G.has_node(node):
                queue.append(node)
                visited.add(node)
                depth[node] = 0
        while queue:
            cur = queue.popleft()
            cd = depth[cur]
            if cd >= max_depth:
                continue
            for _, dst, edata in self.G.out_edges(cur, data=True):
                et = edata.get("edge_type", "")
                if not self._match(et, edge_types):
                    continue
                if dst not in visited:
                    visited.add(dst)
                    depth[dst] = cd + 1
                    queue.append(dst)
        return visited

    def chop_slice(self, sources, sinks, max_depth=MAX_PATH_HOP):
        fwd = self.forward_slice(sources, max_depth)
        bwd = self.backward_slice(sinks, max_depth)
        return (fwd & bwd) | set(sources) | set(sinks)

    def identify_sources(self, source_code=None):
        source_nodes = []
        alloc_apis = {"malloc", "calloc", "realloc", "alloca", "mmap",
                      "av_malloc", "av_calloc", "av_mallocz",
                      "kmalloc", "kzalloc", "kcalloc"}
        taint_apis = {"recv", "read", "fread", "scanf", "gets", "fgets",
                      "recvfrom", "argv", "getenv", "copy_from_user"}
        for nid in self.G.nodes():
            nd = self.G.nodes[nid]
            code = nd.get("code", "").lower()
            name = nd.get("name", "").lower()
            method = nd.get("method", "").lower()
            combined = f"{code} {name} {method}"
            is_source = False
            for api in alloc_apis:
                if _re.search(rf'\b{_re.escape(api)}\b', combined):
                    is_source = True
                    break
            if not is_source:
                for api in taint_apis:
                    if _re.search(rf'\b{_re.escape(api)}\b', combined):
                        is_source = True
                        break
            if is_source:
                source_nodes.append(nid)
        return source_nodes

    def identify_sinks(self, source_code=None):
        sink_nodes = []
        free_apis = {"free", "munmap", "av_free", "av_freep", "kfree"}
        danger_apis = {"system", "execve", "popen", "strcpy", "strcat",
                       "sprintf", "memcpy", "memmove", "gets", "printf"}
        for nid in self.G.nodes():
            nd = self.G.nodes[nid]
            code = nd.get("code", "").lower()
            name = nd.get("name", "").lower()
            method = nd.get("method", "").lower()
            combined = f"{code} {name} {method}"
            is_sink = False
            for api in free_apis:
                if _re.search(rf'\b{_re.escape(api)}\b', combined):
                    is_sink = True
                    break
            if not is_sink:
                for api in danger_apis:
                    if _re.search(rf'\b{_re.escape(api)}\b', combined):
                        is_sink = True
                        break
            if is_sink:
                sink_nodes.append(nid)
        return sink_nodes

    def auto_slice(self, source_code=None, max_depth=MAX_PATH_HOP):
        orig_nodes = self.G.number_of_nodes()
        sources = self.identify_sources(source_code)
        sinks = self.identify_sinks(source_code)
        stats = {"orig_nodes": orig_nodes, "num_sources": len(sources), "num_sinks": len(sinks)}
        if sources and sinks:
            nodes = self.chop_slice(sources, sinks, max_depth)
            stats["mode"] = "chop"
        elif sinks:
            nodes = self.backward_slice(sinks, max_depth)
            stats["mode"] = "backward_only"
        elif sources:
            nodes = self.forward_slice(sources, max_depth)
            stats["mode"] = "forward_only"
        else:
            nodes = set(self.G.nodes())
            stats["mode"] = "full_graph"
        sliced_edges = sum(1 for u, v in self.G.edges() if u in nodes and v in nodes)
        stats["sliced_nodes"] = len(nodes)
        stats["sliced_edges"] = sliced_edges
        stats["reduction_pct"] = round((1 - len(nodes) / max(orig_nodes, 1)) * 100, 2)
        return nodes, stats

    def _match(self, edge_type, allowed):
        if not allowed:
            return True
        for t in allowed:
            if t == edge_type:
                return True
        return False