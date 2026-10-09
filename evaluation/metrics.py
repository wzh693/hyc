"""
评测指标模块。

包含：
  - 标准分类指标（Precision, Recall, F1, Accuracy）
  - 长距离专项指标（Long-Range F1, Hop-Aware F1）
  - Token 效率指标
  - 推理稳定性指标
"""

import numpy as np
from collections import defaultdict
from sklearn.metrics import (
    precision_score, recall_score, f1_score, accuracy_score,
    confusion_matrix, classification_report,
)


def compute_metrics(y_true: list, y_pred: list) -> dict:
    """
    计算标准分类指标。
    """
    if len(y_true) != len(y_pred):
        raise ValueError(f"y_true/y_pred length mismatch: {len(y_true)} != {len(y_pred)}")
    total = len(y_pred)
    if any(y not in (0, 1) for y in y_true):
        raise ValueError('Binary ground truth must be 0 or 1')
    missing_pos = sum(yt == 1 for yt, yp in zip(y_true, y_pred) if yp not in (0, 1))
    missing_neg = sum(yt == 0 for yt, yp in zip(y_true, y_pred) if yp not in (0, 1))
    valid = [(yt, yp) for yt, yp in zip(y_true, y_pred) if yp in (0, 1)]
    if not valid:
        return {"accuracy": 0, "precision": 0, "recall": 0, "f1": 0,
                "tp": 0, "fp": missing_neg, "tn": 0, "fn": missing_pos, "n": total,
                "n_errors": len(y_pred), "coverage": 0.0, "accuracy_all": 0.0,
                "f1_conservative": 0.0, "n_valid": 0,
                "accuracy_valid": 0.0, "f1_valid": 0.0}
    y_true = np.array([x[0] for x in valid])
    y_pred = np.array([x[1] for x in valid])

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    return {
        "accuracy": float((tp + tn) / total) if total else 0.0,
        "precision": float(tp / (tp + fp + missing_neg)) if tp + fp + missing_neg else 0.0,
        "recall": float(tp / (tp + fn + missing_pos)) if tp + fn + missing_pos else 0.0,
        "f1": float(2*tp / (2*tp + fp + fn + missing_pos + missing_neg))
              if 2*tp + fp + fn + missing_pos + missing_neg else 0.0,
        "tp": int(tp),
        "fp": int(fp + missing_neg),
        "tn": int(tn),
        "fn": int(fn + missing_pos),
        "n": total,
        "n_valid": len(valid),
        "accuracy_valid": accuracy_score(y_true, y_pred),
        "f1_valid": f1_score(y_true, y_pred, zero_division=0),
        "n_errors": max(0, total - len(valid)),
        "coverage": len(valid) / total if total else 0.0,
        "accuracy_all": float((tp + tn) / total) if total else 0.0,
        # Abstentions/errors count as errors, not hidden improvements through
        # dropping hard samples: positive abstention -> FN, negative -> FP.
        "f1_conservative": float(2 * tp / (2 * tp + fp + fn + missing_pos + missing_neg))
                           if (2 * tp + fp + fn + missing_pos + missing_neg) else 0.0,
    }


def compute_long_range_metrics(
    results: list,
    hop_key: str = "hop_count",
    label_key: str = "label",
    pred_key: str = "prediction",
) -> dict:
    """
    按跳数分层计算评测指标。

    参数:
        results: list of dict，每个 dict 包含 hop_count, label, prediction
    返回:
        {
            "overall": {...},
            "short": {...},
            "medium": {...},
            "long": {...},
            "very_long": {...},
        }
    """
    HOP_SPLITS = {
        "short": (1, 2),
        "medium": (3, 4),
        "long": (5, 7),
        "very_long": (8, 100),
    }

    valid_results = [r for r in results if r.get(pred_key) in (0, 1)]
    hop_split_results = defaultdict(list)
    for r in results:
        hop = r.get(hop_key, 0)
        classified = False
        for split_name, (lo, hi) in HOP_SPLITS.items():
            if lo <= hop <= hi:
                hop_split_results[split_name].append(r)
                classified = True
                break
        if not classified:
            hop_split_results["unclassified"].append(r)

    metrics = {}
    # 总体指标
    all_y_true = [r[label_key] for r in results]
    all_y_pred = [r.get(pred_key) for r in results]
    metrics["overall"] = compute_metrics(all_y_true, all_y_pred)
    metrics["overall"]["n_errors"] = len(results) - len(valid_results)

    # 分层指标
    for split_name, split_results in hop_split_results.items():
        if split_results:
            y_true = [r[label_key] for r in split_results]
            y_pred = [r.get(pred_key) for r in split_results]
            metrics[split_name] = compute_metrics(y_true, y_pred)
        else:
            metrics[split_name] = {
                "accuracy": 0, "precision": 0, "recall": 0, "f1": 0,
                "tp": 0, "fp": 0, "tn": 0, "fn": 0,
            }

    return metrics


def compute_token_efficiency(
    results: list,
    token_key: str = "tokens_used",
) -> dict:
    """
    计算 Token 效率指标。
    """
    tokens = [r.get(token_key) for r in results
              if isinstance(r.get(token_key), (int, float))]
    if not tokens:
        return {"avg_tokens": 0, "total_tokens": 0, "min_tokens": 0, "max_tokens": 0}

    return {
        "avg_tokens": float(np.mean(tokens)),
        "total_tokens": int(np.sum(tokens)),
        "min_tokens": int(np.min(tokens)),
        "max_tokens": int(np.max(tokens)),
        "median_tokens": float(np.median(tokens)),
        "std_tokens": float(np.std(tokens)),
    }


def compute_stability_metrics(
    results_list: list,  # list of list of results (多次运行)
    pred_key: str = "prediction",
) -> dict:
    """
    计算推理稳定性指标（多次运行的一致性）。

    参数:
        results_list: 多次运行的结果列表
    返回:
        {
            "prediction_variance": 平均预测方差,
            "agreement_rate": 多次运行一致的样本比例,
        }
    """
    if len(results_list) < 2:
        return {"prediction_variance": 0.0, "agreement_rate": 1.0}

    lengths = {len(results) for results in results_list}
    if len(lengths) != 1:
        raise ValueError("All stability runs must contain the same number of samples")
    n_samples = len(results_list[0])
    n_runs = len(results_list)

    # 仅比较每次运行都有有效判定的样本；异常/歧义不能伪装成良性 0。
    rows = []
    for sample_idx in range(n_samples):
        values = [results[sample_idx].get(pred_key) for results in results_list]
        if all(v in (0, 1) for v in values):
            rows.append(values)
    if not rows:
        return {"prediction_variance": 0.0, "agreement_rate": 0.0,
                "n_comparable": 0, "n_errors": n_samples}
    predictions = np.asarray(rows, dtype=float)

    variance = float(np.mean(np.var(predictions, axis=1)))

    # 计算一致率
    agreement_count = 0
    for i in range(len(rows)):
        if len(set(predictions[i])) == 1:
            agreement_count += 1
    agreement_rate = agreement_count / len(rows)

    return {
        "prediction_variance": variance,
        "agreement_rate": agreement_rate,
        "n_comparable": len(rows),
        "n_errors": n_samples - len(rows),
    }


def compute_code_reduction_metrics(results: list) -> dict:
    """
    计算代码缩减率统计指标。
    用于量化 HGL-Vul 的图压缩效率（VD-Slicing 增强版）。

    参数:
        results: list of dict，每个 dict 包含 orig_nodes, compressed_nodes 等

    返回:
        {
            "avg_node_reduction_pct": 平均节点缩减率,
            "avg_edge_reduction_pct": 平均边缩减率,
            "min_reduction": 最小缩减率,
            "max_reduction": 最大缩减率,
            "reduction_by_hop": {hop_level: avg_reduction, ...},
            "per_sample": [{...}],
        }
    """
    if not results:
        return {
            "avg_node_reduction_pct": 0,
            "avg_edge_reduction_pct": 0,
            "min_reduction": 0,
            "max_reduction": 0,
            "reduction_by_hop": {},
            "per_sample": [],
        }

    reductions = []
    per_sample = []
    for r in results:
        orig = r.get("orig_nodes", 0)
        compressed = r.get("compressed_nodes", 0)
        if orig <= 0:
            continue
        reduction = (1 - compressed / orig) * 100
        reductions.append(reduction)
        per_sample.append({
            "sample_id": r.get("sample_id", ""),
            "orig_nodes": orig,
            "compressed_nodes": compressed,
            "reduction_pct": round(reduction, 2),
            "hop_count": r.get("hop_count", 0),
        })

    # 按跳数分层
    by_hop = defaultdict(list)
    for r in per_sample:
        hop = r.get("hop_count", 0)
        by_hop[hop].append(r["reduction_pct"])

    reduction_by_hop = {}
    for hop, vals in sorted(by_hop.items()):
        reduction_by_hop[f"hop_{hop}"] = {
            "count": len(vals),
            "avg_reduction": round(sum(vals) / len(vals), 2),
        }

    return {
        "avg_node_reduction_pct": round(sum(reductions) / max(len(reductions), 1), 2),
        "min_reduction": round(min(reductions), 2) if reductions else 0,
        "max_reduction": round(max(reductions), 2) if reductions else 0,
        "reduction_by_hop": reduction_by_hop,
        "per_sample": per_sample,
    }


def compute_detailed_report(
    results: list,
    hop_key: str = "hop_count",
    label_key: str = "label",
    pred_key: str = "prediction",
    vul_type_key: str = "vul_type",
) -> str:
    """
    生成详细的评测报告。
    """
    lines = []
    lines.append("=" * 70)
    lines.append("DETAILED EVALUATION REPORT")
    lines.append("=" * 70)

    # 整体指标
    metrics = compute_long_range_metrics(results, hop_key, label_key, pred_key)
    lines.append("\n[Overall Metrics]")

    # 代码缩减率指标
    reduction_metrics = compute_code_reduction_metrics(results)
    lines.append(f"\n[Code Reduction Metrics]")
    lines.append(f"  Avg Node Reduction:  {reduction_metrics['avg_node_reduction_pct']:.1f}%")
    lines.append(f"  Min Reduction:       {reduction_metrics['min_reduction']:.1f}%")
    lines.append(f"  Max Reduction:       {reduction_metrics['max_reduction']:.1f}%")
    if reduction_metrics["reduction_by_hop"]:
        lines.append(f"  By Hop Count:")
        for hop_key, hop_data in reduction_metrics["reduction_by_hop"].items():
            lines.append(f"    {hop_key}: {hop_data['avg_reduction']:.1f}% (n={hop_data['count']})")

    # 长距离分层指标
    lines.append("\n[Long-Range Split Metrics]")
    lines.append(f"  {'Split':<15} {'F1':<10} {'Precision':<12} {'Recall':<10} {'Samples':<10}")
    lines.append(f"  {'-'*15} {'-'*10} {'-'*12} {'-'*10} {'-'*10}")
    for split_name in ["short", "medium", "long", "very_long"]:
        m = metrics.get(split_name, {})
        n = m.get("tp", 0) + m.get("fp", 0) + m.get("tn", 0) + m.get("fn", 0)
        lines.append(
            f"  {split_name:<15} {m.get('f1', 0):<10.4f} "
            f"{m.get('precision', 0):<12.4f} {m.get('recall', 0):<10.4f} {n:<10}"
        )

    # 按漏洞类型
    lines.append("\n[Per Vulnerability Type]")
    type_results = defaultdict(list)
    for r in results:
        vt = r.get(vul_type_key, "unknown")
        type_results[vt].append(r)

    for vt, vt_list in sorted(type_results.items()):
        valid = [r for r in vt_list if r.get(pred_key) in (0, 1)]
        f1 = compute_metrics([r[label_key] for r in vt_list],
                             [r.get(pred_key) for r in vt_list])['f1']
        lines.append(f"  {vt:<25}: F1={f1:.4f} "
                     f"({len(valid)}/{len(vt_list)} valid samples)")

    lines.append("\n" + "=" * 70)
    return "\n".join(lines)
