"""Read-only offline counterexamples for the research/code review. No API calls."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import networkx as nx
from graph.security_net import zero_token_verify
from graph.graph_engine import GraphEngine
from graph.summarize_graph import _adjust_threshold_for_budget, NODE_TOKEN_ESTIMATE
from retrieval.candidate_paths import extract_candidate_paths_from_node
from reasoning.reasoning_loop import parse_binary_verdict
from evaluation.audit_state_confirmation import audit


def main():
    examples = {
        "mutually_exclusive_free": "void f(int c, void *p) { if (c) free(p); else free(p); }",
        "free_then_return": "void f(int c, struct S *p) { if(c) { free(p); return; } p->x=1; }",
        "unrelated_input_constant_command": 'void f(int fd) { char b[8]; read(fd,b,8); system("echo ok"); }',
        "safe_constant_copies": 'void f(void) { char a[100],b[100]; strcpy(a,"a"); strcpy(b,"b"); }',
        "av_freep_nulls_pointer": "void f(char *p) { av_freep(&p); av_freep(&p); }",
    }
    results = {name: dict(zip(("prediction", "audit"), zero_token_verify(0, code)))
               for name, code in examples.items()}
    g = nx.MultiDiGraph()
    for u, v in (("s", "a"), ("s", "b"), ("before", "s")):
        g.add_edge(u, v, edge_type="DFG")
    results["bidirectional_cap"] = GraphEngine(g).expand_dataflow("s", 1, 2)
    cycle = nx.MultiDiGraph()
    cycle.add_edge("a", "b", edge_type="DFG")
    cycle.add_edge("b", "a", edge_type="DFG")
    results["cycle_paths"] = GraphEngine(cycle).expand_dataflow("a", 3, 20)
    chain = nx.MultiDiGraph()
    chain.add_edge("a", "b", edge_type="DFG")
    chain.add_edge("b", "c", edge_type="DFG")
    results["max_hop_1"] = extract_candidate_paths_from_node(chain, "a", 1)
    budget_graph = nx.MultiDiGraph()
    budget_graph.add_nodes_from(map(str, range(100)))
    scores = {str(i): 1.5 + i * .035 for i in range(100)}
    budget = 10 * NODE_TOKEN_ESTIMATE
    threshold, forced = _adjust_threshold_for_budget(budget_graph, scores, set(), budget, verbose=False)
    retained = sum(score >= threshold or node in forced for node, score in scores.items())
    results["threshold_search"] = {"threshold": threshold, "retained": retained,
        "budget": budget, "returned_estimated_tokens": retained * NODE_TOKEN_ESTIMATE,
        "feasible_threshold": 4.7,
        "feasible_estimated_tokens": sum(s >= 4.7 for s in scores.values()) * NODE_TOKEN_ESTIMATE}
    results["ambiguous_binary_verdict"] = parse_binary_verdict("The code is vulnerable, but the buffer copy is safe.")
    state = audit(ROOT / "output/devign_state_eval60_20261007")
    results["state_audit"] = {key: state[key] for key in
        ("scheduled_rows", "actual_invocations", "failed_invocations", "api_calls_by_audit", "prediction_changes")}
    results["state_input_checks"] = {key: {k: v for k, v in value.items() if k != "rows"}
                                    for key, value in state["actual_input_checks"].items()}
    from evaluation.metrics import compute_metrics
    history = {}
    for fold, filename in ((0, "devign_comparison/results/evaluation_results_v20_full_fold0.json"),
                           (1, "devign_comparison_fold1/results/evaluation_results.json")):
        rows = json.loads((ROOT / "output" / filename).read_text(encoding="utf-8"))
        raw_count = len(rows)
        # Historical resume files append rows. Existing formal analyses use the
        # last row per mode/index; do not weight repeated samples twice.
        rows = list({(r["mode"], r["idx"]): r for r in rows}.values())
        modes = sorted({r["mode"] for r in rows})
        per_mode = {}
        for mode in modes:
            batch = [r for r in rows if r["mode"] == mode]
            metrics = compute_metrics([r["target"] for r in batch], [r.get("prediction") for r in batch])
            valid = [r for r in batch if r.get("prediction") in (0, 1)]
            per_mode[mode] = {**metrics, "scheduled_rows_present": len(batch),
                "success_only_tokens": sum(r.get("tokens_used", 0) for r in valid) / len(valid)}
        common = set.intersection(*(set(r["idx"] for r in rows if r["mode"] == mode
                                      and r.get("prediction") in (0, 1)) for mode in modes))
        paired = {}
        for mode in modes:
            batch = [r for r in rows if r["mode"] == mode and r["idx"] in common]
            paired[mode] = compute_metrics([r["target"] for r in batch], [r["prediction"] for r in batch])
        history[f"fold{fold}"] = {"raw_rows": raw_count, "unique_mode_index_rows": len(rows),
                                  "per_mode": per_mode, "success_paired": paired}
    results["history_recomputed"] = history
    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
