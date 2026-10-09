"""Compare two append-only SVEN evaluation outputs on identical samples.

The evaluator can contain retries and several pipeline fingerprints.  This
utility selects the fingerprint with the largest number of valid, unique
predictions in each run, then reports both independent and paired metrics.
"""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter, defaultdict
from pathlib import Path


def _load_run(path: Path) -> tuple[str, dict[int, dict]]:
    by_fp: dict[str, dict[int, dict]] = defaultdict(dict)
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("prediction") not in (0, 1):
                continue
            fp = row.get("pipeline_fp", "legacy")
            by_fp[fp][int(row["idx"])] = row
    if not by_fp:
        raise ValueError(f"no valid predictions in {path}")
    fingerprint, rows = max(by_fp.items(), key=lambda item: len(item[1]))
    return fingerprint, rows


def _metrics(rows: list[dict]) -> dict:
    tn = fp = fn = tp = 0
    for row in rows:
        target, pred = row["target"], row["prediction"]
        if target == 1 and pred == 1:
            tp += 1
        elif target == 1:
            fn += 1
        elif pred == 1:
            fp += 1
        else:
            tn += 1
    n = tn + fp + fn + tp
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    mcc_den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return {
        "n": n,
        "confusion": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "accuracy": (tp + tn) / n if n else 0.0,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "balanced_accuracy": (recall + specificity) / 2,
        "f1": f1,
        "mcc": ((tp * tn - fp * fn) / mcc_den) if mcc_den else 0.0,
        "positive_rate": (tp + fp) / n if n else 0.0,
        "mean_tokens": (
            sum(row.get("tokens_used", 0) or 0 for row in rows) / n if n else 0.0
        ),
    }


def _run_summary(fingerprint: str, rows: dict[int, dict]) -> dict:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for row in rows.values():
        grouped[row.get("cwe", "unknown")].append(row)
    types = Counter(
        row.get("arbitrate", {}).get("vulnerability_type", "missing")
        for row in rows.values()
        if row["prediction"] == 1
    )
    triggered = [row for row in rows.values() if row.get("arbitrate", {}).get("triggered")]
    flipped = [row for row in rows.values() if row.get("arbitrate", {}).get("flipped")]
    return {
        "pipeline_fp": fingerprint,
        "metrics": _metrics(list(rows.values())),
        "by_cwe": {cwe: _metrics(group) for cwe, group in sorted(grouped.items())},
        "positive_prediction_types": dict(types.most_common()),
        "arbitration": {
            "triggered": len(triggered),
            "flipped": len(flipped),
            "flips_correct": sum(row["prediction"] == row["target"] for row in flipped),
        },
    }


def _mcnemar_exact(left_only: int, right_only: int) -> float:
    """Two-sided exact McNemar p-value (binomial, p=0.5)."""
    discordant = left_only + right_only
    if discordant == 0:
        return 1.0
    tail = sum(
        math.comb(discordant, k) for k in range(min(left_only, right_only) + 1)
    ) / (2 ** discordant)
    return min(1.0, 2 * tail)


def compare(left: Path, right: Path) -> dict:
    left_fp, left_rows = _load_run(left)
    right_fp, right_rows = _load_run(right)
    common = sorted(left_rows.keys() & right_rows.keys())
    left_common = [left_rows[idx] for idx in common]
    right_common = [right_rows[idx] for idx in common]

    transitions = Counter()
    left_correct_right_wrong = right_correct_left_wrong = 0
    for left_row, right_row in zip(left_common, right_common):
        target = left_row["target"]
        old, new = left_row["prediction"], right_row["prediction"]
        transitions[f"{old}->{new}"] += 1
        left_ok, right_ok = old == target, new == target
        left_correct_right_wrong += left_ok and not right_ok
        right_correct_left_wrong += right_ok and not left_ok

    return {
        "left": _run_summary(left_fp, left_rows),
        "right": _run_summary(right_fp, right_rows),
        "paired": {
            "n": len(common),
            "left_metrics": _metrics(left_common),
            "right_metrics": _metrics(right_common),
            "prediction_transitions": dict(sorted(transitions.items())),
            "agreement": sum(
                left_rows[idx]["prediction"] == right_rows[idx]["prediction"]
                for idx in common
            ) / len(common) if common else 0.0,
            "left_correct_right_wrong": left_correct_right_wrong,
            "right_correct_left_wrong": right_correct_left_wrong,
            "mcnemar_exact_p": _mcnemar_exact(
                left_correct_right_wrong, right_correct_left_wrong
            ),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("left", type=Path)
    parser.add_argument("right", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = compare(args.left, args.right)
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
