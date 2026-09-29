"""
智能路径排序 v2.0 (Slice-Aware Path Ranking)。

v2.0 新增切片感知特征：
  1. source-sink 完整性得分 — 路径是否覆盖完整漏洞链路
  2. 变量生命周期完整度 — malloc→free→deref 全链条
  3. 控制条件覆盖度 — 是否包含关键分支条件
  4. 路径多样性惩罚 — 去重重复的 source-sink 对

排序策略：
  - 密度特征（危险 API 密度、边类型分布）→ 基础分
  - 切片特征（完整度、生命周期）→ 加权分
  - 多样性特征（去重冗余路径）→ 惩罚项
"""

import re
import networkx as nx
import numpy as np
from collections import defaultdict
from config import DANGEROUS_APIS, TAINT_SOURCES, MEMORY_OPS, LEARNED_PATH_WEIGHT


def _extract_var_names(code: str) -> set:
    """从代码片段中提取变量名。"""
    import re
    vars_set = set(re.findall(r'\b([a-zA-Z_]\w*)\b', code))
    # 过滤关键词
    keywords = {
        "if", "else", "for", "while", "do", "return", "void", "int",
        "char", "float", "double", "long", "struct", "sizeof", "NULL",
        "const", "static", "unsigned", "signed", "break", "continue",
        "switch", "case", "default", "goto", "typedef", "enum",
    }
    return vars_set - keywords


def _compute_source_sink_completeness(
    G: nx.MultiDiGraph,
    path: list,
    node_ids_set: set,
    node_methods: dict,
) -> float:
    """
    评估路径的 source↔sink 完整度。

    一条"好的"漏洞路径应该覆盖从 source（分配/污点源）到 sink（释放/危险操作）的完整链条。
    完整度 = 匹配的 source-sink 对数 / 可能的组合数。
    """
    if len(path) < 2:
        return 0.0

    # 识别路径中的 source 和 sink 节点
    sources = []
    sinks = []

    for i, nid in enumerate(path):
        code = G.nodes.get(nid, {}).get("code", "").lower()

        # Source：内存分配、污点输入
        if any(re.search(rf'\b{re.escape(kw)}\b', code) for kw in ["malloc", "calloc", "realloc", "alloca"]):
            sources.append(("alloc", i, nid))
        if any(re.search(rf'\b{re.escape(kw)}\b', code) for kw in TAINT_SOURCES):
            sources.append(("taint", i, nid))

        # Sink：内存释放、危险操作、系统调用
        if re.search(r'\b(?:free|av_free|av_freep|kfree|munmap)\b', code):
            sinks.append(("free", i, nid))
        if any(re.search(rf'\b{re.escape(kw)}\b', code) for kw in ["system", "execve", "popen"]):
            sinks.append(("danger", i, nid))
        if any(re.search(rf'\b{re.escape(kw)}\b', code) for kw in ["memcpy", "strcpy", "strcat", "sprintf"]):
            sinks.append(("overflow", i, nid))

    # 计算完整度
    if not sources or not sinks:
        return 0.0

    matched = 0
    for src_type, src_idx, _ in sources:
        for sink_type, sink_idx, _ in sinks:
            # source 必须在 sink 之前（数据流方向）
            if src_idx < sink_idx:
                matched += 1

    completeness = matched / (len(sources) * len(sinks)) if sources and sinks else 0.0
    return completeness * 5.0  # 最高 5 分


def _compute_variable_lifecycle_completeness(
    G: nx.MultiDiGraph,
    path: list,
) -> float:
    """
    评估路径中变量生命周期的完整度。

    理想的生命周期链路：
      malloc → ... → free → ... → deref (UAF)
      malloc → ... → free → ... → free (Double Free)
      recv → ... → system (Taint)

    评分策略：
      - 有 alloc + free：+3
      - 有 alloc + deref：+2
      - 有 free + deref（UAF）：+5
      - 有 free + free（Double Free）：+5
    """
    if len(path) < 2:
        return 0.0

    score = 0.0
    lifecycle = []  # [(event, position), ...]

    for i, nid in enumerate(path):
        code = G.nodes.get(nid, {}).get("code", "").lower()

        if any(re.search(rf'\b{re.escape(kw)}\b', code) for kw in ["malloc", "calloc"]):
            lifecycle.append(("alloc", i))
        if re.search(r'\b(?:free|av_free|av_freep|kfree|munmap)\b', code):
            lifecycle.append(("free", i))
        if any(re.search(rf'\b{re.escape(kw)}\b', code) for kw in ["memcpy", "strcpy", "printf", "system"]):
            lifecycle.append(("use", i))

    events = [e for e, _ in lifecycle]

    # Check for UAF: ... free ... use ...
    try:
        free_idx = events.index("free")
        if any(e == "use" for e in events[free_idx + 1:]):
            score += 5.0  # UAF 模式
    except ValueError:
        pass

    # Check for Double Free
    free_count = events.count("free")
    if free_count >= 2:
        score += 5.0  # Double Free 模式

    # Complete alloc→free chain
    if "alloc" in events and "free" in events:
        score += 3.0

    # Taint: alloc/taint → use
    if ("alloc" in events or "free" in events) and "use" in events:
        score += 2.0

    return score


def _compute_control_condition_coverage(
    G: nx.MultiDiGraph,
    path: list,
) -> float:
    """
    评估路径中控制条件（if/for/while）的覆盖度。

    完整的漏洞分析需要了解关键的 branch 条件——
    即漏洞是否仅在特定条件下触发。
    """
    if len(path) < 2:
        return 0.0

    condition_nodes = 0
    for nid in path:
        node_type = G.nodes.get(nid, {}).get("node_type", "")
        code = G.nodes.get(nid, {}).get("code", "").lower()

        # 识别条件节点
        if "CONTROL_STRUCTURE" in node_type:
            condition_nodes += 1
        elif any(kw in code for kw in ["if (", "if(", "while (", "for (", "switch"]):
            condition_nodes += 1

    # 条件覆盖度 = 条件节点数 / 路径长度
    coverage = condition_nodes / len(path) if len(path) > 0 else 0
    return min(coverage * 5.0, 3.0)  # 最高 3 分


def _compute_path_diversity_penalty(
    all_scored_paths: list,
    path: list,
) -> float:
    """
    路径多样性惩罚：对于重复覆盖相同 source-sink 对的路径，降低其得分。

    避免多条几乎相同的路径占据 Top-K 位置。
    """
    if not all_scored_paths:
        return 0.0

    current_src = path[0]
    current_sink = path[-1]

    penalty = 0.0
    for _, existing_path in all_scored_paths:
        if len(existing_path) < 2:
            continue
        if existing_path[0] == current_src and existing_path[-1] == current_sink:
            penalty += 1.0  # 每条相同 source-sink 的路径罚 1 分

    return min(penalty, 5.0)  # 最多罚 5 分


def rank_paths(G: nx.MultiDiGraph, paths: list, top_k: int = 0, vuln_type: str = "Generic", learned_scores: dict = None) -> list:
    """
    v2.0 切片感知路径排序（漏洞类型条件权重）。

    技术点②（智能漏洞证据路径检索）：
      learned_scores 指定时，path_score += LEARNED_PATH_WEIGHT *
      min(sum(节点学习式重要性), 4.0)——学习式节点分数的路径级聚合，
      识别最具漏洞判别价值的证据路径（cap 防长路径线性膨胀）。

    排序维度（权重从高到低）：
      1. 变量生命周期完整度（UAF/DF/Taint 模式匹配）
      2. source-sink 完整性
      3. 危险 API 密度
      4. 数据流密度
      5. 控制流密度
      6. 跨函数加分
      7. 控制条件覆盖度
      8. 路径多样性惩罚

    vuln_type 控制各维度权重：
      - UAF: lifecycle 权重最高
      - Overflow: source-sink 权重最高
      - DoubleFree: lifecycle + memory_op 权重最高
      - Generic: 均衡权重

    返回:
        list of (score, path) tuples，按分数降序排列
    """
    if not paths:
        return []

    RANK_WEIGHTS = {
        "UAF":        {"lifecycle": 15.0, "source_sink": 5.0, "dangerous": 8.0, "control": 2.0},
        "DoubleFree": {"lifecycle": 12.0, "source_sink": 4.0, "dangerous": 6.0, "control": 3.0},
        "Overflow":   {"lifecycle": 5.0,  "source_sink": 12.0, "dangerous": 10.0, "control": 1.5},
        "NullDeref":  {"lifecycle": 8.0,  "source_sink": 5.0, "dangerous": 6.0, "control": 3.0},
        "FmtStr":     {"lifecycle": 4.0,  "source_sink": 10.0, "dangerous": 10.0, "control": 1.5},
        "Generic":    {"lifecycle": 10.0, "source_sink": 5.0, "dangerous": 10.0, "control": 3.0},
    }
    rw = RANK_WEIGHTS.get(vuln_type, RANK_WEIGHTS["Generic"])

    # 预处理：构建节点索引
    node_ids = list(G.nodes())
    N = len(node_ids)
    node_flags = np.zeros((N, 3), dtype=np.float32)
    node_methods = [""] * N
    nid_to_idx = {}

    for idx, nid in enumerate(node_ids):
        nid_to_idx[nid] = idx
        node = G.nodes[nid]
        code_lower = node.get("code", "").lower()
        node_flags[idx, 0] = float(any(re.search(rf'\b{re.escape(api)}\b', code_lower) for api in DANGEROUS_APIS))
        node_flags[idx, 1] = float(any(re.search(rf'\b{re.escape(api)}\b', code_lower) for api in TAINT_SOURCES))
        node_flags[idx, 2] = float(any(re.search(rf'\b{re.escape(api)}\b', code_lower) for api in MEMORY_OPS))
        node_methods[idx] = node.get("method", "")

    # 边类型缓存
    edge_cache = {}
    for u, v, data in G.edges(data=True):
        et = data.get("edge_type", "")
        key = (u, v)
        entry = (
            float("DFG" in et or "REACHING_DEF" in et),
            float("CFG" in et),
            float("CALL" in et),
        )
        if key not in edge_cache:
            edge_cache[key] = entry
        else:
            prev = edge_cache[key]
            edge_cache[key] = (
                max(prev[0], entry[0]),
                max(prev[1], entry[1]),
                max(prev[2], entry[2]),
            )

    P = len(paths)
    scores = np.zeros(P, dtype=np.float32)

    # 去重统计（用于多样性惩罚）
    source_sink_seen = defaultdict(int)

    for pi, path in enumerate(paths):
        plen = len(path)
        if plen < 2:
            continue

        idxs = [nid_to_idx.get(nid) for nid in path]
        idxs = [i for i in idxs if i is not None]
        if not idxs:
            continue

        # === 密度特征（v1.0 保留）===
        path_flags = node_flags[idxs]
        dangerous_count = float(path_flags[:, 0].sum())
        taint_count = float(path_flags[:, 1].sum())
        memory_op_count = float(path_flags[:, 2].sum())

        methods_in_path = set(node_methods[i] for i in idxs if node_methods[i])
        is_cross_function = float(len(methods_in_path) > 1)

        dfg_count = cfg_count = call_count = 0.0
        total_edges = 0.0
        for i in range(plen - 1):
            ec = edge_cache.get((path[i], path[i + 1]))
            if ec is not None:
                if ec[0]:
                    dfg_count += 1.0
                elif ec[1]:
                    cfg_count += 1.0
                elif ec[2]:
                    call_count += 0.5
                total_edges += 1.0
        total_edges = max(total_edges, 1.0)

        score = 0.0
        score += (dangerous_count / plen) * rw["dangerous"]
        # BUG-22 修复：taint/memory 原不归一（dangerous 归一）——长路径靠堆
        # taint/memory 节点刷分。统一按密度归一
        score += (taint_count / plen) * 5.0
        score += (memory_op_count / plen) * 4.0
        score += (dfg_count / total_edges) * 3.0
        score += (cfg_count / total_edges) * rw["control"] * 0.5
        score += call_count * 2.0
        score += is_cross_function * 3.0

        # 长度偏好：3-8 跳的路径最优
        if 3 <= plen <= 8:
            score += 2.0
        elif plen > 8:
            score += max(0.0, 2.0 - (plen - 8) * 0.5)

        # === v2.0 切片感知特征 ===

        # 1. 变量生命周期完整度
        lifecycle_score = _compute_variable_lifecycle_completeness(G, path)
        score += lifecycle_score * (rw["lifecycle"] / 10.0)

        # 2. source-sink 完整性
        completeness_score = _compute_source_sink_completeness(
            G, path, set(idxs), node_methods
        )
        score += completeness_score * (rw["source_sink"] / 5.0)

        # 3. 控制条件覆盖度
        control_score = _compute_control_condition_coverage(G, path)
        score += control_score * (rw["control"] / 3.0)

        # === v3.0 代码内容区分度（解决非标准 API 场景下全部分数相同的问题）===
        # 基于路径中每个节点的 code 属性提取变量名，计数唯一变量数
        unique_vars = set()
        func_calls = 0
        struct_access = 0
        for nid in path:
            code_text = G.nodes.get(nid, {}).get("code", "")
            vars_in_node = _extract_var_names(code_text)
            unique_vars.update(vars_in_node)
            if "->" in code_text:
                struct_access += 1
            if "(" in code_text and ")" in code_text:
                # 计数非关键字的函数调用
                before_paren = code_text.split("(")[0].strip().split()[-1] if code_text.split("(")[0].strip() else ""
                if before_paren and before_paren not in {"if", "for", "while", "switch", "return", "sizeof"}:
                    func_calls += 1
        # 变量多样性：每 5 个唯一变量加 1 分
        score += min(len(unique_vars) / 5.0, 3.0)
        # 结构体访问：每 2 次加 1 分（指向更高语义密度）
        score += min(struct_access / 2.0, 2.0)
        # 函数调用数：每 1 次加 0.5 分
        score += min(func_calls * 0.5, 2.0)
        # 边类型多样性：路径包含的独特边类型越多越好（区别于纯 AST 骨架）
        edge_labels_in_path = set()
        for i in range(plen - 1):
            edata_dict = G.get_edge_data(path[i], path[i+1])
            if edata_dict:
                for key, edata in edata_dict.items():
                    lbl = edata.get("label", edata.get("edge_type", ""))
                    if lbl:
                        edge_labels_in_path.add(str(lbl))
        # 每 2 种独特边类型加 1 分
        score += min(len(edge_labels_in_path) / 2.0, 3.0)
        # REACHING_DEF 边额外加分（数据流证据）
        rd_count = sum(1 for l in edge_labels_in_path if "REACHING_DEF" in l)
        score += rd_count * 1.5
        # 位置偏移确保分数唯一（基于路径顺序）
        # BUG-04 修复：原 0.001 系数下 P=13k~29k → 位置项最高 +13~29 分，
        # 与语义分（0~20）同量级，枚举顺序主导 Top-K。改为真 tie-break。
        score += (P - pi) * 1e-6

        # === 技术点②：学习式路径判别分（节点重要性聚合，cap=4 防长路径膨胀） ===
        if learned_scores:
            p_sum = 0.0
            for nid in path:
                p_sum += learned_scores.get(nid, 0.0)
            # BUG-05 修复：scorer v2.4 分数 ∈ [-1,0]，原只封顶不封底——
            # 10 跳全低分路径 -20 分足以压出任何语义高分的路径
            score += LEARNED_PATH_WEIGHT * max(min(p_sum, 4.0), -4.0)

        scores[pi] = score

    # === 多样性惩罚（后处理）===
    scored_paths = [(float(scores[pi]), paths[pi]) for pi in range(P)]
    scored_paths.sort(key=lambda x: x[0], reverse=True)

    if top_k > 0:
        # 带多样性惩罚的 Top-K 选择
        diversity_penalized = []
        for s, p in scored_paths:
            penalty = _compute_path_diversity_penalty(diversity_penalized, p)
            s -= penalty
            diversity_penalized.append((s, p))

        import heapq
        result = heapq.nlargest(top_k, diversity_penalized, key=lambda x: x[0])
    else:
        result = scored_paths

    return result