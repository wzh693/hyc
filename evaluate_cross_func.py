"""
HGL-Vul 跨函数数据集评测脚本。

在 vuln-dataset-main 的真实 CVE 数据上运行完整 Pipeline，
验证：
  1. 图压缩在大规模 CPG（1 万+节点）上的效果
  2. 路径检索在跨函数场景下的精度
  3. 层次化上下文的质量
  4. 缩减率统计

用法:
  python evaluate_cross_func.py [dataset_dir] [max_samples] [max_nodes_per_sample]
"""

import os
import sys
import json
import time

sys.path.insert(0, os.path.dirname(__file__))

import networkx as nx

from data.vuln_dataset_loader import VulnDatasetLoader, VulnSample
from graph.summarize_graph import summarize_graph, estimate_token_usage
from retrieval.candidate_paths import extract_all_candidate_paths
from retrieval.retrieve_topk import retrieve_topk
from linearization.typed_paths import typed_dependency_path, build_hierarchical_context
from linearization.function_summary import summarize_function
from linearization.block_summary import summarize_block
from planning.state_memory import ProgramState
from config import TOP_K_PATHS


def run_evaluation(
    dataset_dir: str,
    max_samples: int = 10,
    max_nodes_per_sample: int = 3000,
    token_budget: int = 4096,
    verbose: bool = True,
) -> dict:
    """
    在跨函数数据集上运行 HGL-Vul 评测。

    参数:
        dataset_dir: vuln-dataset-main 目录
        max_samples: 最大样本数
        max_nodes_per_sample: 单样本最大节点数（过滤超大图）
        token_budget: LLM token 预算
        verbose: 是否输出详细日志

    返回:
        评测结果字典
    """
    print("=" * 70)
    print("  HGL-Vul Cross-Function Evaluation (No LLM)")
    print("=" * 70)
    print(f"  Dataset: {dataset_dir}")
    print(f"  Max Samples: {max_samples}")
    print(f"  Max Nodes/Sample: {max_nodes_per_sample}")
    print(f"  Token Budget: {token_budget}")

    # Step 1: 加载数据集
    print(f"\n{'='*70}")
    print("  [Step 1] Loading Dataset...")
    print(f"{'='*70}")
    loader = VulnDatasetLoader(dataset_dir)
    manifest = loader.load_manifest()
    print(f"  Manifest: processed={manifest.get('totals', {}).get('processed')}, "
          f"nodes={manifest.get('totals', {}).get('nodes')}, "
          f"positives={manifest.get('totals', {}).get('positives')}")

    all_samples = loader.load(max_samples=max_samples * 3)  # 多加载一些用于过滤

    # 按节点数过滤：只保留中等大小的图（过大则跳过）
    filtered = []
    for s in all_samples:
        if s.num_nodes <= max_nodes_per_sample:
            filtered.append(s)
        if len(filtered) >= max_samples:
            break

    samples = filtered[:max_samples]
    print(f"  Filtered: {len(samples)} samples "
          f"(excluded {len(all_samples) - len(filtered)} oversized)")

    # Step 2-5: 逐样本处理
    results = []
    for i, sample in enumerate(samples):
        print(f"\n{'='*70}")
        print(f"  [Sample {i+1}/{len(samples)}] {sample.sample_id}")
        print(f"  Label={sample.label}, Type={sample.vul_type}, "
              f"Nodes={sample.num_nodes}, Edges={sample.num_edges}, "
              f"Hops={sample.hop_distance}")
        print(f"{'='*70}")

        try:
            result = process_sample(sample, loader, token_budget, verbose)
            results.append(result)
        except Exception as e:
            print(f"  [ERROR] {e}")
            import traceback
            traceback.print_exc()
            results.append({
                "sample_id": sample.sample_id,
                "label": sample.label,
                "error": str(e),
            })

    # Step 6: 汇总报告
    print(f"\n{'='*70}")
    print("  [Summary] Cross-Function Evaluation Results")
    print(f"{'='*70}")
    report = generate_report(results)
    print(report)

    return {
        "config": {
            "dataset_dir": dataset_dir,
            "max_samples": max_samples,
            "max_nodes_per_sample": max_nodes_per_sample,
            "token_budget": token_budget,
        },
        "manifest": manifest,
        "results": results,
        "report": report,
    }


def process_sample(
    sample: VulnSample,
    loader: VulnDatasetLoader,
    token_budget: int,
    verbose: bool,
) -> dict:
    """处理单个跨函数样本的完整 HGL-Vul Pipeline。"""
    t0 = time.time()

    # Phase 1: 构建 CPG 图
    t1 = time.time()
    G = loader.build_graph(sample)
    t_build = time.time() - t1
    orig_nodes = G.number_of_nodes()
    orig_edges = G.number_of_edges()
    if verbose:
        print(f"  [P1] CPG: {orig_nodes} nodes, {orig_edges} edges "
              f"({t_build*1000:.0f}ms) [memory-assembled from pre-parsed JSONL]")

    # Phase 2: 图压缩（核心！大规模 CPG 必须压缩）
    t2 = time.time()
    SG = summarize_graph(G, token_budget=token_budget, verbose=verbose)
    t_summarize = time.time() - t2
    reduction_stats = SG.graph.get("reduction_stats", {})
    node_reduction = reduction_stats.get("node_reduction_pct", 0)
    edge_reduction = reduction_stats.get("edge_reduction_pct", 0)
    orig_tokens = estimate_token_usage(G)
    comp_tokens = estimate_token_usage(SG)
    if verbose:
        print(f"  [P2] Summarize: {SG.number_of_nodes()} nodes, "
              f"{SG.number_of_edges()} edges "
              f"(node={node_reduction:.1f}%, edge={edge_reduction:.1f}%, "
              f"token={orig_tokens:.0f}->{comp_tokens:.0f}, "
              f"{t_summarize:.1f}s)")

    # Phase 3: 路径检索
    t3 = time.time()
    candidate_paths = extract_all_candidate_paths(SG)
    if not candidate_paths:
        candidate_paths = extract_all_candidate_paths(G)
    topk_paths = retrieve_topk(
        SG if candidate_paths else G,
        candidate_paths,
        k=min(TOP_K_PATHS, 10),
    )
    t_retrieve = time.time() - t3
    if verbose:
        print(f"  [P3] Retrieve: {len(candidate_paths)} candidates "
              f"-> top-{len(topk_paths)} ({t_retrieve:.1f}s)")

    # Phase 4: 层次化线性化
    t4 = time.time()
    func_summary = summarize_function(sample.source_code)

    # 按函数拆分基本块
    blocks = sample.source_code.split("\n\n") if sample.source_code else []
    block_summaries = {}
    for j, block in enumerate(blocks[:20]):  # 最多 20 个块
        if block.strip():
            block_summaries[j] = summarize_block(block)

    # 类型化依赖路径
    graph_for_paths = SG if SG.number_of_nodes() > 10 else G
    paths_context = []
    for path in topk_paths[:5]:
        try:
            path_str = typed_dependency_path(graph_for_paths, path)
            if path_str:
                paths_context.append(path_str)
        except Exception:
            continue

    # 程序状态记忆
    state = ProgramState()
    state.track_vars(sample.source_code)
    state_str = state.serialize()

    # 构建层次化上下文
    hierarchical_context = build_hierarchical_context(
        func_summary, block_summaries, paths_context, state_str
    )
    t_linearize = time.time() - t4
    context_len = len(hierarchical_context)
    context_lines = hierarchical_context.count("\n")
    if verbose:
        print(f"  [P4] Linearize: {context_len} chars, {context_lines} lines "
              f"({t_linearize:.2f}s)")

    total_time = time.time() - t0

    return {
        "sample_id": sample.sample_id,
        "cve_id": sample.cve_id,
        "label": sample.label,
        "vul_type": sample.vul_type,
        "hop_distance": sample.hop_distance,
        "orig_nodes": orig_nodes,
        "orig_edges": orig_edges,
        "comp_nodes": SG.number_of_nodes(),
        "comp_edges": SG.number_of_edges(),
        "node_reduction_pct": node_reduction,
        "edge_reduction_pct": edge_reduction,
        "orig_tokens_est": int(orig_tokens),
        "comp_tokens_est": int(comp_tokens),
        "num_candidates": len(candidate_paths),
        "num_topk": len(topk_paths),
        "context_chars": context_len,
        "context_lines": context_lines,
        "num_paths": len(paths_context),
        "time_build": round(t_build, 2),
        "time_summarize": round(t_summarize, 2),
        "time_retrieve": round(t_retrieve, 2),
        "time_linearize": round(t_linearize, 2),
        "time_total": round(total_time, 2),
        "error": None,
    }


def generate_report(results: list) -> str:
    """生成评测报告。"""
    valid = [r for r in results if r.get("error") is None]
    errors = [r for r in results if r.get("error") is not None]

    lines = []
    lines.append("")
    lines.append("=" * 70)
    lines.append("  HGL-Vul Cross-Function Evaluation Report")
    lines.append("=" * 70)

    # 成功率
    success_rate = len(valid) / max(len(results), 1) * 100
    lines.append(f"\n  Success Rate: {success_rate:.1f}% ({len(valid)}/{len(results)})")
    if errors:
        lines.append(f"  Errors: {len(errors)}")
        for e in errors:
            lines.append(f"    - {e['sample_id']}: {e['error']}")

    if not valid:
        return "\n".join(lines)

    # 缩减率统计
    node_reductions = [r["node_reduction_pct"] for r in valid]
    edge_reductions = [r["edge_reduction_pct"] for r in valid]
    token_reductions = [
        (1 - r["comp_tokens_est"] / max(r["orig_tokens_est"], 1)) * 100
        for r in valid
    ]

    lines.append(f"\n  [Graph Compression]")
    lines.append(f"    Avg Node Reduction:  {sum(node_reductions)/len(node_reductions):.1f}%")
    lines.append(f"    Avg Edge Reduction:  {sum(edge_reductions)/len(edge_reductions):.1f}%")
    lines.append(f"    Avg Token Reduction: {sum(token_reductions)/len(token_reductions):.1f}%")
    lines.append(f"    Min Reduction:       {min(node_reductions):.1f}%")
    lines.append(f"    Max Reduction:       {max(node_reductions):.1f}%")

    # 上下文统计
    lines.append(f"\n  [Context Quality]")
    lines.append(f"    Avg Context Size: {sum(r['context_chars'] for r in valid)/len(valid):.0f} chars")
    lines.append(f"    Avg Context Lines: {sum(r['context_lines'] for r in valid)/len(valid):.0f}")
    lines.append(f"    Avg Paths: {sum(r['num_paths'] for r in valid)/len(valid):.1f}")
    lines.append(f"    Avg Candidates: {sum(r['num_candidates'] for r in valid)/len(valid):.0f}")

    # 耗时统计
    lines.append(f"\n  [Timing (avg per sample)]")
    lines.append(f"    CPG Build:   {sum(r['time_build'] for r in valid)/len(valid)*1000:.0f}ms")
    lines.append(f"    Summarize:   {sum(r['time_summarize'] for r in valid)/len(valid):.2f}s")
    lines.append(f"    Retrieve:    {sum(r['time_retrieve'] for r in valid)/len(valid):.2f}s")
    lines.append(f"    Linearize:   {sum(r['time_linearize'] for r in valid)/len(valid):.2f}s")
    lines.append(f"    Total:       {sum(r['time_total'] for r in valid)/len(valid):.2f}s")

    # 逐样本详情
    lines.append(f"\n  [Per-Sample Details]")
    lines.append(f"    {'Sample':<30s} {'Orig':>6s} {'Comp':>6s} "
                 f"{'Red%':>6s} {'Token%':>7s} {'Paths':>5s} {'Time':>6s}")
    lines.append(f"    {'-'*30} {'-'*6} {'-'*6} {'-'*6} {'-'*7} {'-'*5} {'-'*6}")
    for r in valid:
        name = r["sample_id"][:28]
        token_red = (1 - r["comp_tokens_est"] / max(r["orig_tokens_est"], 1)) * 100
        lines.append(
            f"    {name:<30s} {r['orig_nodes']:>5d}N {r['comp_nodes']:>5d}N "
            f"{r['node_reduction_pct']:>5.1f}% {token_red:>6.1f}% "
            f"{r['num_paths']:>4d}  {r['time_total']:>5.2f}s"
        )

    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    dataset_dir = sys.argv[1] if len(sys.argv) > 1 else \
        r"C:\Users\wzh13\Desktop\Network Security Research\vuln-dataset-main"
    max_samples = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    max_nodes = int(sys.argv[3]) if len(sys.argv) > 3 else 3000

    results = run_evaluation(dataset_dir, max_samples, max_nodes)
    print(f"\n  [Done] Processed {len(results['results'])} cross-function samples")