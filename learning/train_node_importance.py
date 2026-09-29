"""
训练学习式节点重要性模型（技术点①②共享，纯离线）。

用法:
  python -m learning.train_node_importance

流程:
  1. 读取 output/train_cpg 缓存（build_train_cache.py 产物）
  2. 骨架缓存：sample_selection 结果（锚点/背景行选择，与特征无关，只算一次）
  3. 特征缓存：按特征版本哈希存 npz（特征迭代时自动重算）
  4. 按函数 80/20 分割（防节点级泄漏）
  5. 训练 LR / HistGBDT / GPU-MLP，按 holdout AUC + 锚点区分度选优
  6. 保存 joblib + 训练报告 JSON

关键报告指标:
  - auc / pr_auc: 节点级分类
  - anchor_sep: E[p|漏洞锚点] - E[p|良性锚点]（FP 抑制信号的直接度量）
"""

import os
import sys
import io
import json
import hashlib
import random
import contextlib
import pickle

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import joblib

from config import SEED
from graph.load_graph import load_graph
from learning.dataset import sample_selection
from learning.features import (NODE_FEATURE_NAMES, _graph_context,
                               _node_family_flags, extract_node_features)

CACHE_DIR = os.path.join("output", "train_cpg")
MODEL_DIR = os.path.join("learning", "model")
SKELETON_PATH = os.path.join(MODEL_DIR, "skeleton.pkl")

FEATURE_VER = hashlib.md5(
    ("|".join(NODE_FEATURE_NAMES) +
     str(os.path.getmtime(os.path.join(os.path.dirname(__file__), "features.py"))) +
     # load_graph.py 修复 node_type 崩坏后特征分布变化, 版本键须感知图解析层
     "graphfix_v1" + str(os.path.getmtime(os.path.join(
         os.path.dirname(os.path.dirname(__file__)), "graph", "load_graph.py"))) +
     # BUG-20（审查报告）：检索管线变更同样改变特征/锚点分布——
     # candidate_paths 起点匹配（BUG-01）、ranker 偏置（BUG-04）、
     # 图对象统一（BUG-09）都影响 skeleton 与特征缓存，版本键须覆盖
     "retrfix_v1" + str(os.path.getmtime(os.path.join(
         os.path.dirname(os.path.dirname(__file__)), "retrieval", "candidate_paths.py"))) +
     str(os.path.getmtime(os.path.join(
         os.path.dirname(os.path.dirname(__file__)), "retrieval", "path_ranker.py"))) +
     str(os.path.getmtime(os.path.join(
         os.path.dirname(os.path.dirname(__file__)), "graph", "summarize_graph.py")))
    ).encode()
).hexdigest()[:10]

_FUNC_CACHE = {}


def _load_func_source(idx):
    """从 devign 全集读取函数源码（训练只读 train fold，无泄漏）。"""
    if not _FUNC_CACHE:
        from learning.build_train_cache import DEVIGN_JSON
        with open(DEVIGN_JSON, encoding="utf-8") as f:
            data = json.load(f)
        for i, item in enumerate(data):
            _FUNC_CACHE[i] = item.get("func", "")
    return _FUNC_CACHE.get(idx)


def _load_or_build_skeleton(meta):
    """{fid: (target, selected_nids, labels, n_anchors)} —— 只跑一次启发式管线。"""
    skeleton = {}
    if os.path.exists(SKELETON_PATH):
        with open(SKELETON_PATH, "rb") as f:
            skeleton = pickle.load(f)

    rng = random.Random(SEED)
    todo = [fid for fid, info in meta.items()
            if not info.get("error")
            and os.path.exists(os.path.join(CACHE_DIR, fid, "export", "export.dot"))
            and fid not in skeleton]
    if todo:
        print(f"[Train] 骨架缓存缺失 {len(todo)} 个函数，构建中（一次性 ~3s/函数）...")
        for i, fid in enumerate(todo):
            info = meta[fid]
            code = _load_func_source(info["idx"])
            if code is None:
                continue
            try:
                G = load_graph(os.path.join(CACHE_DIR, fid, "export", "export.dot"),
                               os.path.join(CACHE_DIR, fid, "export", "export.dot"))
                with contextlib.redirect_stdout(io.StringIO()):
                    selected, labels, n_anchors = sample_selection(
                        G, code, info["target"], rng)
            except Exception:
                selected = None
            skeleton[fid] = (info["target"], selected or [], labels if selected else [], n_anchors or 0)
            if (i + 1) % 50 == 0:
                print(f"  骨架 {i+1}/{len(todo)}")
                with open(SKELETON_PATH, "wb") as f:
                    pickle.dump(skeleton, f)
        with open(SKELETON_PATH, "wb") as f:
            pickle.dump(skeleton, f)
    return skeleton


def _fid_features(fid, code, selected):
    """选中节点的特征矩阵（按 FEATURE_VER 缓存 npz）。"""
    npz = os.path.join(CACHE_DIR, fid, f"featsel_{FEATURE_VER}.npz")
    if os.path.exists(npz):
        z = np.load(npz)
        return z["X"]
    dot = os.path.join(CACHE_DIR, fid, "export", "export.dot")
    G = load_graph(dot, dot)
    ctx = _graph_context(G, code)
    flags = _node_family_flags(G)
    n_nodes = max(G.number_of_nodes(), 1)
    X = np.stack([extract_node_features(G, n, ctx=ctx, family_flags=flags,
                                        n_nodes=n_nodes) for n in selected]) \
        if selected else np.zeros((0, len(NODE_FEATURE_NAMES)), dtype=np.float32)
    np.savez(npz, X=X)
    return X


def load_training_data():
    meta_path = os.path.join(CACHE_DIR, "meta.json")
    with open(meta_path, encoding="utf-8") as f:
        meta = json.load(f)

    skeleton = _load_or_build_skeleton(meta)

    Xs, ys, fids, targets, anchor_flags = [], [], [], [], []
    n_done = n_skip = 0
    for fid, (target, selected, labels, n_anchors) in skeleton.items():
        if not selected:
            n_skip += 1
            continue
        code = _load_func_source(meta[fid]["idx"])
        if code is None:
            n_skip += 1
            continue
        try:
            X = _fid_features(fid, code, selected)
        except Exception:
            n_skip += 1
            continue
        if len(X) != len(labels):
            n_skip += 1
            continue
        Xs.append(X.astype(np.float32))
        ys.append(np.asarray(labels, dtype=np.int8))
        fids.extend([fid] * len(X))
        targets.extend([target] * len(X))
        af = np.zeros(len(labels), dtype=bool)
        af[:n_anchors] = True
        anchor_flags.extend(af.tolist())
        n_done += 1

    X = np.vstack(Xs)
    y = np.concatenate(ys)
    fids = np.asarray(fids)
    targets = np.asarray(targets)
    anchor_flags = np.asarray(anchor_flags, dtype=bool)
    print(f"[Train] 函数 {n_done} 个 (跳过 {n_skip}), 节点样本 {X.shape[0]}, "
          f"正 {int(y.sum())} / 负 {int((1-y).sum())}")
    return X, y, fids, targets, anchor_flags, n_done


def main():
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.metrics import roc_auc_score, average_precision_score

    os.makedirs(MODEL_DIR, exist_ok=True)

    X, y, fids, targets, anchor_flags, n_funcs = load_training_data()

    # 按函数分割（防泄漏）
    unique_fids = sorted(set(fids.tolist()))
    rng = random.Random(SEED)
    rng.shuffle(unique_fids)
    n_hold = max(1, int(len(unique_fids) * 0.2))
    hold_fids = set(unique_fids[:n_hold])
    tr_mask = np.asarray([f not in hold_fids for f in fids])
    ho_mask = ~tr_mask
    X_tr, y_tr = X[tr_mask], y[tr_mask]
    X_ho, y_ho = X[ho_mask], y[ho_mask]
    t_ho = targets[ho_mask]
    a_ho = anchor_flags[ho_mask]
    print(f"[Train] train {tr_mask.sum()} / holdout {ho_mask.sum()} 节点样本 "
          f"({len(unique_fids)-n_hold}/{n_hold} 函数)")

    candidates = {
        "lr": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=2000, C=1.0, class_weight="balanced")),
        ]),
        "gbdt": HistGradientBoostingClassifier(
            max_iter=300, learning_rate=0.1, max_depth=None,
            random_state=SEED),
    }
    try:
        from learning.torch_model import TorchMLPClassifier
        candidates["mlp_gpu"] = TorchMLPClassifier(epochs=200, lr=1e-3)
        import torch
        torch.manual_seed(SEED)
        print(f"[Train] GPU 候选: mlp_gpu (device={candidates['mlp_gpu'].device})")
    except Exception as e:
        print(f"[Train] torch 不可用，跳过 GPU 候选: {e}")

    best_kind, best_model, best_auc = None, None, -1.0
    report = {"n_functions": n_funcs, "feature_version": FEATURE_VER,
              "features": NODE_FEATURE_NAMES, "candidates": {}}

    for kind, model in candidates.items():
        model.fit(X_tr, y_tr)
        p_ho = model.predict_proba(X_ho)[:, 1]
        auc = roc_auc_score(y_ho, p_ho)
        aps = average_precision_score(y_ho, p_ho)
        # 锚点区分度：漏洞函数锚点 vs 良性函数锚点（FP 抑制信号的直接度量）
        p_vuln_anchor = p_ho[(y_ho == 1)]
        p_benign_anchor = p_ho[(t_ho == 0) & a_ho]
        sep = (float(p_vuln_anchor.mean() - p_benign_anchor.mean())
               if len(p_vuln_anchor) and len(p_benign_anchor) else float("nan"))
        report["candidates"][kind] = {
            "auc": round(float(auc), 4), "pr_auc": round(float(aps), 4),
            "anchor_separation": round(sep, 4),
            "mean_p_vuln_anchor": round(float(p_vuln_anchor.mean()), 4) if len(p_vuln_anchor) else None,
            "mean_p_benign_anchor": round(float(p_benign_anchor.mean()), 4) if len(p_benign_anchor) else None,
        }
        print(f"[Train] {kind}: AUC={auc:.4f} PR-AUC={aps:.4f} "
              f"anchor_sep={sep:.4f} "
              f"(p_vuln={p_vuln_anchor.mean():.3f} / p_ben_anchor={p_benign_anchor.mean():.3f})")
        if auc > best_auc:
            best_kind, best_model, best_auc = kind, model, auc

    # 特征重要性（LR 系数 / 其余用 holdout 单特征 AUC 近似）
    if best_kind == "lr":
        coefs = best_model.named_steps["clf"].coef_[0]
        imp = sorted(zip(NODE_FEATURE_NAMES, coefs), key=lambda x: -abs(x[1]))
        report["top_features"] = [(n, round(float(c), 3)) for n, c in imp[:12]]
    else:
        aucs = []
        for j, name in enumerate(NODE_FEATURE_NAMES):
            try:
                aucs.append((name, round(float(roc_auc_score(y_ho, X_ho[:, j])), 3)))
            except Exception:
                pass
        aucs.sort(key=lambda x: -abs(x[1] - 0.5))
        report["top_features"] = aucs[:12]
    print("[Train] top features:", report["top_features"])

    model_path = os.path.join(MODEL_DIR, "node_importance.joblib")
    joblib.dump({"model": best_model, "kind": best_kind,
                 "features": NODE_FEATURE_NAMES}, model_path)
    report_path = os.path.join(MODEL_DIR, "train_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"[Train] 最优: {best_kind} (AUC={best_auc:.4f}) → {model_path}")


if __name__ == "__main__":
    main()
