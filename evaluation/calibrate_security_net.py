"""Calibrate the zero-token verifier on a labelled non-SVEN run."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from graph.security_net import zero_token_verify


def metrics(rows: list[dict], predictions: list[int]) -> dict:
    tp = fp = tn = fn = 0
    for row, pred in zip(rows, predictions):
        target = row["target"]
        if pred == target == 1:
            tp += 1
        elif pred == 1:
            fp += 1
        elif target == 0:
            tn += 1
        else:
            fn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "n": len(rows), "tn": tn, "fp": fp, "fn": fn, "tp": tp,
        "accuracy": (tp + tn) / len(rows) if rows else 0.0,
        "precision": precision, "recall": recall,
        "f1": 2 * precision * recall / (precision + recall)
        if precision + recall else 0.0,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("samples", type=Path)
    parser.add_argument("--result-key", default="results_b")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    payload = json.loads(args.report.read_text(encoding="utf-8"))
    rows = [row for row in payload[args.result_key]
            if row.get("prediction") in (0, 1)]
    base = metrics(rows, [row["prediction"] for row in rows])
    candidates = []
    for threshold in range(2, 11):
        predictions, flips = [], []
        for row in rows:
            source = args.samples / f"sample_{int(row['idx']):06d}.c"
            code = source.read_text(encoding="utf-8", errors="replace")
            pred, audit = zero_token_verify(row["prediction"], code, threshold)
            predictions.append(pred)
            if audit["flipped"]:
                flips.append({"idx": row["idx"], "target": row["target"],
                              "signal": audit["signal"]})
        score = metrics(rows, predictions)
        score.update({"threshold": threshold, "flips": len(flips),
                      "flip_tp": sum(f["target"] == 1 for f in flips),
                      "flip_fp": sum(f["target"] == 0 for f in flips)})
        candidates.append(score)
    result = {"base": base, "candidates": candidates}
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    print(rendered)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
