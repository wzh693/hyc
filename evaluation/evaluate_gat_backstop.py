"""Evaluate the frozen GAT bag classifier as a zero-token FN backstop."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evaluation.calibrate_security_net import metrics
from evaluation.evaluate_security_net import load_largest_fingerprint
from graph.load_graph import load_graph
from learning.gat_model import GATMIL, graph_to_arrays


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("results", type=Path)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("cpg_cache", type=Path)
    parser.add_argument("--checkpoint", type=Path,
                        default=Path("learning/model/gat_mil.pt"))
    parser.add_argument("--calibration", type=Path,
                        default=Path("learning/model/gat_calibration.json"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    calibration = json.loads(args.calibration.read_text(encoding="utf-8"))
    chosen = calibration.get("chosen")
    if not chosen:
        raise ValueError("GAT calibration did not produce a safe threshold")
    threshold = float(chosen["threshold"])
    checkpoint = torch.load(args.checkpoint, map_location="cpu")
    model = GATMIL(**checkpoint["config"])
    model.load_state_dict(checkpoint["state_dict"])
    model.eval()

    samples = json.loads(args.dataset.read_text(encoding="utf-8"))
    fp, rows = load_largest_fingerprint(args.results)
    predictions, flips, probabilities = [], [], {}
    for row in rows:
        pred = row["prediction"]
        if pred == 0:
            idx = int(row["idx"])
            stem = Path(row["file_name"]).stem
            dot = args.cpg_cache / f"{idx:04d}_{stem}" / "export" / "export.dot"
            graph = load_graph(str(dot), str(dot))
            arrays = graph_to_arrays(graph, samples[idx]["input"])
            with torch.no_grad():
                logit, _ = model(
                    torch.from_numpy(arrays["x"]),
                    torch.from_numpy(arrays["tok_flat"]),
                    torch.from_numpy(arrays["tok_offsets"]),
                    torch.from_numpy(arrays["edge_index"]),
                    torch.from_numpy(arrays["edge_type"]),
                )
            probability = torch.sigmoid(logit).item()
            probabilities[str(idx)] = probability
            if probability >= threshold:
                pred = 1
                flips.append({"idx": idx, "target": row["target"],
                              "cwe": row.get("cwe"), "probability": probability})
        predictions.append(pred)

    report = {
        "pipeline_fp": fp,
        "threshold": threshold,
        "calibration": chosen,
        "before": metrics(rows, [row["prediction"] for row in rows]),
        "after": metrics(rows, predictions),
        "flips": flips,
        "flip_tp": sum(row["target"] == 1 for row in flips),
        "flip_fp": sum(row["target"] == 0 for row in flips),
        "probabilities": probabilities,
    }
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    print(rendered)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
