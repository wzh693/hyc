"""
学习式节点重要性 scorer（推理端，技术点①②共享）。

单例懒加载：模型缺失/未启用时返回 None，管线自动回退启发式（v10 行为）。
"""

import os
import threading
import joblib

from config import (
    USE_LEARNED_NODE_IMPORTANCE,
    USE_LEARNED_SUMMARIZE,
    USE_LEARNED_PATH_RANK,
    NODE_IMPORTANCE_MODEL_PATH,
)

_lock = threading.Lock()
_bundle = None
_loaded = False


def _load():
    global _bundle, _loaded
    if not os.path.exists(NODE_IMPORTANCE_MODEL_PATH):
        return None
    try:
        _bundle = joblib.load(NODE_IMPORTANCE_MODEL_PATH)
    except Exception:
        _bundle = None
    _loaded = True
    return _bundle


def get_node_scorer():
    """返回 scorer dict {model, kind, features} 或 None。"""
    if not USE_LEARNED_NODE_IMPORTANCE:
        return None
    with _lock:
        if not _loaded:
            _load()
        return _bundle


def summarize_enabled():
    """技术点①：学习式压缩打分是否启用。"""
    return get_node_scorer() is not None and USE_LEARNED_SUMMARIZE


def path_rank_enabled():
    """技术点②：学习式路径排序是否启用。"""
    return get_node_scorer() is not None and USE_LEARNED_PATH_RANK


def score_nodes(G, code=None):
    """对整图节点打分。返回 {nid: 图内归一化分数 [-1,+1]}；未启用返回 None。

    v2.2: 百分位归一化。实证迭代记录：
      - v2.0 原始概率加成 → 图膨胀（token 涨）
      - v2.1 z-score → 偏态分布下上中段节点 z 爆炸（图膨胀更严重）
      - v2.2 percentile rank → 均匀 [-1,+1]，中位数以下节点负调整，
        图收缩且幅度可控；锚点类 force_keep 不受影响（证据保留）。

    code: 原始源码（用于漏洞类型提示等上下文特征，v2）。
    """
    bundle = get_node_scorer()
    if bundle is None:
        return None
    import numpy as np
    from learning.features import graph_feature_matrix
    nids, X, _ = graph_feature_matrix(G, code)
    if len(nids) == 0:
        return {}
    p = bundle["model"].predict_proba(X)[:, 1]
    n = len(p)
    order = np.argsort(p, kind="stable")
    ranks = np.empty(n, dtype=np.float64)
    ranks[order] = np.arange(n) / max(n - 1, 1)
    # v2.4 纯惩罚：s = rank - 1 ∈ [-1, 0]
    # 最高分节点调整量为 0，其余按排名负惩罚。
    # 迭代实证：阈值 1.2 下填充节点集中在 0.8~1.1，任何正加成
    # （v2.2 对称 / v2.3 非对称）都会使其越过阈值导致图膨胀；
    # 纯惩罚保证压缩图是基线的严格子集（证据保留单调成立），
    # 收缩幅度由 LEARNED_NODE_WEIGHT 控制。
    s = ranks - 1.0
    return {nid: float(si) for nid, si in zip(nids, s)}
