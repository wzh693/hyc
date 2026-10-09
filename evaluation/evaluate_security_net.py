"""Evaluate a frozen zero-token verifier on append-only JSONL predictions."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evaluation.calibrate_security_net import metrics
from graph.security_net import zero_token_verify


def load_largest_fingerprint(path: Path) -> tuple[str, list[dict]]:
    groups: dict[str, dict[int, dict]] = defaultdict(dict)
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("prediction") in (0, 1):
            groups[row.get("pipeline_fp", "legacy")][int(row["idx"])] = row
    fp, rows = max(groups.items(), key=lambda item: len(item[1]))
    return fp, list(rows.values())


def source_path(source_dir: Path, row: dict) -> Path:
    candidates = [
        source_dir / f"{int(row['idx']):04d}_{row.get('file_name', '')}",
        source_dir / f"sample_{int(row['idx']):06d}.c",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"source not found for idx={row['idx']}")


def evaluate(rows: list[dict], source_dir: Path, threshold: int,
             use_main_prediction: bool) -> dict:
    before, after, flips = [], [], []
    tokens = 0
    for row in rows:
        audit = row.get("arbitrate") or {}
        pred = audit.get("main_pred", row["prediction"]) \
            if use_main_prediction else row["prediction"]
        code = source_path(source_dir, row).read_text(
            encoding="utf-8", errors="replace"
        )
        verified, record = zero_token_verify(pred, code, threshold)
        before.append(pred)
        after.append(verified)
        if record["flipped"]:
            flips.append({"idx": row["idx"], "target": row["target"],
                          "cwe": row.get("cwe"), "signal": record["signal"]})
        value = row.get("tokens_used", 0) or 0
        if use_main_prediction:
            value -= audit.get("audit_tokens", 0) or 0
        tokens += value
    return {
        "before": metrics(rows, before),
        "after": metrics(rows, after),
        "mean_tokens": tokens / len(rows) if rows else 0.0,
        "flips": flips,
        "flip_tp": sum(row["target"] == 1 for row in flips),
        "flip_fp": sum(row["target"] == 0 for row in flips),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("results", type=Path)
    parser.add_argument("sources", type=Path)
    parser.add_argument("--threshold", type=int, default=4)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    fp, rows = load_largest_fingerprint(args.results)
    report = {
        "pipeline_fp": fp,
        "threshold": args.threshold,
        "with_existing_arbitration": evaluate(
            rows, args.sources, args.threshold, False
        ),
        "replace_arbitration": evaluate(rows, args.sources, args.threshold, True),
    }
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    print(rendered)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
