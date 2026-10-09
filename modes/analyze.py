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
from reasoning.llm_api import create_client
from reasoning.reasoning_loop import reasoning_loop

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

    from graph.pipeline import run_hgl_pipeline
    with open(code_path, "r", encoding="utf-8", errors="ignore") as f:
        function_code = f.read()
    details = run_hgl_pipeline(code_path, function_code, os.path.basename(code_path),
                               output_dir, create_client(), token_budget, return_details=True)
    prediction = details["prediction"]
    reduction_stats = details["reduction_stats"]

    # Phase 7: 漏洞报告输出
    print("\n" + "=" * 60)
    print("Phase 7: Vulnerability Report")
    print("=" * 60)
    report = {
        "source_file": code_path,
        "prediction": "UNCERTAIN" if prediction is None else ("VULNERABLE" if prediction == 1 else "BENIGN"),
        "confidence": "uncalibrated",
        "reduction_stats": reduction_stats,
        "paths_analyzed": details["paths_analyzed"],
        "tokens_used": details["tokens_used"],
        "module_audit": details["module_audit"],
        "arbitrate": details["arbitrate"],
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    report_path = os.path.join(output_dir, "vulnerability_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"[Report] 已保存至: {report_path}")
