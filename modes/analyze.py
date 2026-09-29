"""
Mode 1: 单文件漏洞分析（v2.0 支持动态预算感知）
"""
import os
import sys
import json

from config import LLM_API_KEY, LLM_BASE_URL, LLM_MODEL
from graph.build_cpg import build_cpg, find_export_files
from graph.load_graph import load_graph
from graph.summarize_graph import summarize_graph
from retrieval.candidate_paths import extract_all_candidate_paths
from retrieval.retrieve_topk import retrieve_topk
from linearization.function_summary import summarize_function
from linearization.block_summary import summarize_block
from linearization.typed_paths import typed_dependency_path, build_hierarchical_context, extract_api_hints
from reasoning.llm_api import create_client
from reasoning.reasoning_loop import run_vuln_detection, reasoning_loop
from planning.state_memory import ProgramState

DEFAULT_TOKEN_BUDGET = 4096


def mode_analyze(code_path: str, output_dir: str, token_budget: int = DEFAULT_TOKEN_BUDGET):
    """单文件漏洞分析。"""
    if not os.path.exists(code_path):
        print(f"[Error] 文件不存在: {code_path}")
        sys.exit(1)

    print("=" * 60)
    print("  HGL-Vul: Hierarchical Graph Linearization for")
    print("           Vulnerability Reasoning")
    print("=" * 60)
    print(f"[Main] 源代码: {code_path}")
    print(f"[Main] 输出目录: {output_dir}")
    print(f"[Main] Token Budget: {token_budget}")

    # Phase 1: CPG 构建
    print("\n" + "=" * 60)
    print("Phase 1: CPG Construction (Joern)")
    print("=" * 60)
    try:
        export_dir = build_cpg(code_path, output_dir)
        nodes_file, edges_file = find_export_files(export_dir)
    except Exception as e:
        print(f"[Warning] Joern 构建失败: {e}")
        print("[Main] 尝试使用已有的 nodes.json / edges.json...")
        nodes_file = os.path.join(output_dir, "nodes.json")
        edges_file = os.path.join(output_dir, "edges.json")
        if not os.path.exists(nodes_file) or not os.path.exists(edges_file):
            print(
                "[Error] 未找到 nodes.json/edges.json。\n"
                "  请先安装 Joern (https://joern.io/) 并运行:\n"
                f"    joern-parse {code_path}\n"
                f"    joern-export --repr all --out {output_dir}"
            )
            sys.exit(1)

    # Phase 2: 图加载
    print("\n" + "=" * 60)
    print("Phase 2: Graph Loading")
    print("=" * 60)
    G = load_graph(nodes_file, edges_file)

    # Phase 3: 漏洞感知图压缩（v2.0 动态预算感知）
    print("\n" + "=" * 60)
    print("Phase 3: Vulnerability-Aware Graph Summarization (v2.0)")
    print("=" * 60)
    SG = summarize_graph(G, token_budget=token_budget)
    reduction_stats = SG.graph.get("reduction_stats", {})

    # Phase 4: 候选路径提取 & Top-K 检索
    print("\n" + "=" * 60)
    print("Phase 4: Intelligent Path Retrieval")
    print("=" * 60)
    with open(code_path, "r", encoding="utf-8", errors="ignore") as f:
        function_code = f.read()

    candidate_paths = extract_all_candidate_paths(SG, source_code=function_code)
    if not candidate_paths:
        print("[Warning] 未提取到候选路径，尝试放宽条件...")
        candidate_paths = extract_all_candidate_paths(G, source_code=function_code)
    topk_paths = retrieve_topk(SG if candidate_paths else G, candidate_paths)

    # Phase 5: 层次化线性化
    print("\n" + "=" * 60)
    print("Phase 5: Hierarchical Linearization")
    print("=" * 60)

    func_summary = summarize_function(function_code)
    print(f"[FunctionSummary]\n{func_summary}")

    blocks = function_code.split("\n\n")
    block_summaries = {}
    for i, block in enumerate(blocks):
        if block.strip():
            block_summ = summarize_block(block)
            block_summaries[i] = block_summ

    api_hints = extract_api_hints(function_code)

    # 构建路径上下文（供 reasoning_loop 内部使用）
    paths_context = []
    for path in topk_paths[:5]:
        path_str = typed_dependency_path(SG, path, api_hints=api_hints)
        if path_str:
            paths_context.append(path_str)

    state = ProgramState()
    state.track_vars(function_code)

    # Phase 6: 受限漏洞推理
    print("\n" + "=" * 60)
    print("Phase 6: Constrained Vulnerability Reasoning")
    print("=" * 60)
    llm_client = create_client()
    reasoning_result = reasoning_loop(
        SG, topk_paths, function_code, func_summary, block_summaries,
        client=llm_client,
    )
    conclusion = reasoning_result.get("conclusion", "")
    prediction = 1 if reasoning_result.get("vulnerability_type", "Unknown") != "Unknown" else 0

    # Phase 7: 漏洞报告输出
    print("\n" + "=" * 60)
    print("Phase 7: Vulnerability Report")
    print("=" * 60)
    report = {
        "source_file": code_path,
        "prediction": "VULNERABLE" if prediction == 1 else "BENIGN",
        "confidence": "high" if prediction == 1 else "low",
        "reduction_stats": reduction_stats,
        "paths_analyzed": len(topk_paths),
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    report_path = os.path.join(output_dir, "vulnerability_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"[Report] 已保存至: {report_path}")