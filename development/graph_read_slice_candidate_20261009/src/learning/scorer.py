"""
学习式节点重要性 scorer（推理端，技术点①②共享）。

单例懒加载：模型缺失/未启用时返回 None，管线自动回退启发式（v10 行为）。
"""

import os
import threading
import warnings
import joblib

from config import (
    USE_LEARNED_NODE_IMPORTANCE,
    USE_LEARNED_SUMMARIZE,
    USE_LEARNED_PATH_RANK,
    NODE_IMPORTANCE_MODEL_PATH,
    NODE_IMPORTANCE_BACKEND,
    GAT_NODE_IMPORTANCE_MODEL_PATH,
)

_lock = threading.Lock()
_bundle = None
_loaded = False


def _load():
    global _bundle, _loaded
    try:
        if NODE_IMPORTANCE_BACKEND == "gat":
            if not os.path.exists(GAT_NODE_IMPORTANCE_MODEL_PATH):
                _loaded = True
                return None
            import torch
            from learning.gat_model import GATMIL
            from learning.features import NODE_FEATURE_NAMES
            checkpoint = torch.load(GAT_NODE_IMPORTANCE_MODEL_PATH, map_location="cpu")
            saved_features = checkpoint.get("feature_names")
            if saved_features and list(saved_features) != list(NODE_FEATURE_NAMES):
                raise ValueError("GAT checkpoint feature schema does not match current code")
            config = dict(checkpoint.get("config", {}))
            # 兼容早期检查点中的字段名；新检查点统一保存 n_edge_types。
            if "edge_types" in config and "n_edge_types" not in config:
                config["n_edge_types"] = config.pop("edge_types")
            model = GATMIL(**config)
            model.load_state_dict(checkpoint["state_dict"])
            model.eval()
            _bundle = {"model": model, "kind": "gat",
                       "features": saved_features}
        else:
            if not os.path.exists(NODE_IMPORTANCE_MODEL_PATH):
                _loaded = True
                return None
            _bundle = joblib.load(NODE_IMPORTANCE_MODEL_PATH)
    except Exception as exc:
        warnings.warn(f"Node-importance model disabled: {exc}", RuntimeWarning)
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
    return USE_LEARNED_SUMMARIZE and get_node_scorer() is not None


def path_rank_enabled():
    """技术点②：学习式路径排序是否启用。"""
    return USE_LEARNED_PATH_RANK and get_node_scorer() is not None


def _percentile_penalties(probabilities):
    """Equal learned scores must receive equal penalties, regardless of order."""
    import numpy as np
    p = np.asarray(probabilities, dtype=np.float64)
    if p.ndim != 1 or not np.isfinite(p).all():
        raise ValueError('node importance scores must be a finite one-dimensional array')
    if len(p) == 0:
        return p
    values, inverse, counts = np.unique(p, return_inverse=True, return_counts=True)
    if len(values) == 1:
        return np.zeros_like(p)  # No relative learned information: neutral.
    starts = np.cumsum(counts) - counts
    mean_ranks = starts + (counts - 1) / 2
    return mean_ranks[inverse] / (len(p)-1) - 1.0


def score_nodes(G, code=None):
    """对整图节点打分。返回 {nid: 图内归一化分数 [-1,0]}；未启用返回 None。

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
    if bundle.get("kind") == "gat":
        import torch
        from learning.gat_model import graph_to_arrays
        arr = graph_to_arrays(G, code)
        with torch.no_grad():
            _, scores = bundle["model"](
                torch.from_numpy(arr["x"]),
                torch.from_numpy(arr["tok_flat"]),
                torch.from_numpy(arr["tok_offsets"]),
                torch.from_numpy(arr["edge_index"]),
                torch.from_numpy(arr["edge_type"]),
            )
        p = scores.cpu().numpy()
    else:
        p = bundle["model"].predict_proba(X)[:, 1]
    # v2.4 纯惩罚：s = rank - 1 ∈ [-1, 0]
    # 最高分节点调整量为 0，其余按排名负惩罚。
    # 迭代实证：阈值 1.2 下填充节点集中在 0.8~1.1，任何正加成
    # （v2.2 对称 / v2.3 非对称）都会使其越过阈值导致图膨胀；
    # 纯惩罚保证压缩图是基线的严格子集（证据保留单调成立），
    # 收缩幅度由 LEARNED_NODE_WEIGHT 控制。
    s = _percentile_penalties(p)
    return {nid: float(si) for nid, si in zip(nids, s)}
