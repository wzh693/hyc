"""
弱监督数据集构造（技术点①②的训练数据）。

标签设计（针对 v10/v11 的结构性结论）：
  - 正样本：漏洞函数（target=1）中启发式管线锚定的证据节点
    （压缩图中危险 API 节点 + Top-K 路径节点）
  - 负样本：
      a) 良性函数（target=0）中的同类锚定节点 —— 核心判别信号：
         同样"看起来危险"的节点，在良性上下文中的特征模式
         （free 清理、带边界检查的拷贝等）应被打低分，
         直接针对 v11 "良性证据变富 → FP+7" 的实证问题
      b) 漏洞/良性函数中随机非锚定节点（背景负样本）

启发式管线与 modes/compare_devign._run_hgl_pipeline 保持一致
（token_budget=4096、无 source_code），避免训练/推理分布偏移。
"""

import re
import random
import numpy as np
import networkx as nx
from config import DANGEROUS_APIS, TAINT_SOURCES, MEMORY_OPS
from graph.summarize_graph import summarize_graph
from retrieval.candidate_paths import extract_all_candidate_paths
from retrieval.retrieve_topk import retrieve_topk
from learning.features import graph_feature_matrix, NODE_FEATURE_NAMES

# 词边界正则缓存（避免子串误匹配，如 "read" 命中 "thread"）
_ANCHOR_RES = {
    api: re.compile(r'\b' + re.escape(api) + r'\b')
    for api in DANGEROUS_APIS | TAINT_SOURCES | MEMORY_OPS
}

TRAIN_BUDGET = 4096  # 与 compare_devign.DEFAULT_TOKEN_BUDGET 一致

# 候选池缩减（训练标签用途；Top-K 锚点与全量几乎一致，耗时约降 6 倍）
_POOL_KW = dict(max_total_paths=8000, max_paths_per_node=800)


def heuristic_anchor_nodes(SG: nx.MultiDiGraph, topk_paths: list) -> set:
    """锚定证据节点：压缩图危险节点 + Top-K 路径节点（节点 ID 级）。"""
    anchors = set()
    for nid, ndata in SG.nodes(data=True):
        code = (ndata.get("code") or "").lower()
        if any(rx.search(code) for rx in _ANCHOR_RES.values()):
            anchors.add(nid)
    for path in (topk_paths or []):
        for nid in path:
            if nid in SG:
                anchors.add(nid)
    return anchors


def sample_selection(G: nx.MultiDiGraph, code: str, target: int,
                     rng: random.Random, max_anchor_nodes: int = 80,
                     neg_bg_ratio: float = 2.0, benign_bg_ratio: float = 0.5):
    """
    单函数 → (selected_nids, labels, n_anchors)。
    跑启发式管线定锚点并采样行（骨架，与特征无关，可缓存）。
    selected 前段为锚点节点（n_anchors 个），后段为背景采样。
    失败返回 (None, None, None)。
    """
    try:
        SG = summarize_graph(G, token_budget=TRAIN_BUDGET, verbose=False)
        # BUG-09 修复（同 compare_devign）：SG 空路径回退 G 时，rank/锚点
        # 提取须用路径同源图，否则 rank_paths 特征丢失、锚点被 SG 过滤
        sg_paths = extract_all_candidate_paths(
            SG, source_code=code, verbose=False, **_POOL_KW)
        if sg_paths:
            path_graph, candidate_paths = SG, sg_paths
        else:
            candidate_paths = extract_all_candidate_paths(
                G, source_code=code, verbose=False, **_POOL_KW)
            path_graph = G
        topk = retrieve_topk(path_graph, candidate_paths) \
            if candidate_paths else []
    except Exception:
        return None, None, None

    anchors = heuristic_anchor_nodes(path_graph, topk)
    nids = list(G.nodes())
    nid_set = set(nids)
    anchors = {a for a in anchors if a in nid_set}
    if not anchors:
        return None, None, None

    chosen = sorted(anchors)[:max_anchor_nodes]
    chosen_set = set(chosen)
    background = [n for n in nids if n not in chosen_set]
    rng.shuffle(background)

    selected = []
    labels = []
    if target == 1:
        for n in chosen:
            selected.append(n)
            labels.append(1)
        n_bg = min(len(background), int(len(chosen) * neg_bg_ratio))
        for n in background[:n_bg]:
            selected.append(n)
            labels.append(0)
    else:
        for n in chosen:
            selected.append(n)
            labels.append(0)
        n_bg = min(len(background), int(len(chosen) * benign_bg_ratio))
        for n in background[:n_bg]:
            selected.append(n)
            labels.append(0)
    return selected, labels, len(chosen)


def build_sample_dataset(G: nx.MultiDiGraph, code: str, target: int,
                         rng: random.Random):
    """
    单函数 → (X, y, anchor_mask, anchor_ids)。特征含上下文（v2）。
    """
    selected, labels, n_anchors = sample_selection(G, code, target, rng)
    if selected is None:
        return None, None, None, None

    nids, X_all, row_of = graph_feature_matrix(G, code)
    rows = [row_of[n] for n in selected]
    mask = np.zeros(len(labels), dtype=bool)
    mask[:n_anchors] = True
    X = X_all[rows]
    y = np.asarray(labels, dtype=np.int8)
    return X, y, mask, set(selected[:n_anchors])
