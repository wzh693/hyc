"""Build an exact report for a selective second-pass run from two evaluations."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evaluation.calibrate_security_net import metrics
from evaluation.evaluate_security_net import load_largest_fingerprint


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("single_pass", type=Path)
    parser.add_argument("routed_pass", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    single_fp, single = load_largest_fingerprint(args.single_pass)
    routed_fp, routed = load_largest_fingerprint(args.routed_pass)
    by_idx = {int(row["idx"]): row for row in single}
    replaced = []
    for row in routed:
        idx = int(row["idx"])
        if idx in by_idx:
            replaced.append({
                "idx": idx,
                "target": row["target"],
                "before": by_idx[idx]["prediction"],
                "after": row["prediction"],
                "token_delta": (row.get("tokens_used", 0) or 0)
                - (by_idx[idx].get("tokens_used", 0) or 0),
            })
            by_idx[idx] = row
    rows = list(by_idx.values())
    report = {
        "single_pass_fp": single_fp,
        "routed_pass_fp": routed_fp,
        "metrics": metrics(rows, [row["prediction"] for row in rows]),
        "mean_tokens": sum(row.get("tokens_used", 0) or 0 for row in rows) / len(rows),
        "routed_samples": len(replaced),
        "changed_predictions": [row for row in replaced
                                if row["before"] != row["after"]],
    }
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    print(rendered)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
