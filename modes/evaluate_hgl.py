"""
Mode 3: HGL-Vul + LLM 完整评测（v2.0 跳数分层评测 + 缩减率统计）

支持合成数据集和跨函数数据集的评测。
输出跳数分层指标（short/medium/long/very_long）。
"""
import os
import json

from config import LLM_MODEL
from graph.build_cpg import build_cpg, find_export_files
from graph.load_graph import load_graph
from graph.summarize_graph import summarize_graph
from retrieval.candidate_paths import extract_all_candidate_paths
from retrieval.retrieve_topk import retrieve_topk
from linearization.function_summary import summarize_function
from linearization.block_summary import summarize_block
from reasoning.llm_api import create_client
from reasoning.reasoning_loop import reasoning_loop
from evaluation.metrics import (
    compute_detailed_report, compute_long_range_metrics,
    compute_code_reduction_metrics,
)

DEFAULT_TOKEN_BUDGET = 4096


def mode_evaluate_hgl(data_dir: str = None, max_samples: int = 50,
                      token_budget: int = DEFAULT_TOKEN_BUDGET):
    """HGL-Vul + LLM 完整评测。"""
    if data_dir is None:
        from config import SYNTHETIC_DIR
        data_dir = SYNTHETIC_DIR

    print("=" * 60)
    print("  Mode 3: HGL-Vul Full Evaluation")
    print("=" * 60)
    print(f"  Dataset: {data_dir}")
    print(f"  Max Samples: {max_samples}")
    print(f"  Token Budget: {token_budget}")

    # 加载数据集
    all_samples = []

    # 优先从 data_dir 加载已有 .c 文件
    c_files = sorted(
        f for f in os.listdir(data_dir)
        if f.endswith(".c") or f.endswith(".cpp")
    ) if os.path.isdir(data_dir) else []

    if c_files:
        print(f"  从 {data_dir} 加载 {len(c_files)} 个源文件")
        metadata_path = os.path.join(data_dir, "metadata.json")
        metadata = {}
        if os.path.exists(metadata_path):
            with open(metadata_path, "r", encoding="utf-8") as f:
                metadata = json.load(f)
            print(f"  Dataset metadata: {metadata}")

        metadata_samples = metadata.get("samples", [])
        meta_map = {}
        if isinstance(metadata_samples, list):
            for item in metadata_samples:
                if item.get("filename"):
                    meta_map[item["filename"]] = item
                if item.get("id") is not None:
                    meta_map[str(item["id"])] = item
            listed_files = {s.get("filename") for s in metadata_samples if s.get("filename")}
            if listed_files:
                c_files = [f for f in c_files if f in listed_files]

        for idx, fname in enumerate(c_files):
            fpath = os.path.join(data_dir, fname)
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
            meta = meta_map.get(fname, {})
            sample_id = meta.get("id", idx + 1)
            label = meta.get("label", -1)
            vul_type = meta.get("vul_type", "unknown")
            hop_count = meta.get("hop_count", 0)
            if label == -1:
                label = 1 if any(kw in fname.lower() for kw in ["uaf", "overflow", "double_free", "taint", "leak", "null"]) else 0
            all_samples.append({
                "id": sample_id, "code": code, "label": label,
                "vul_type": vul_type, "hop_count": hop_count,
            })
    else:
        from data.synthetic_generator import SyntheticDatasetGenerator
        generator = SyntheticDatasetGenerator()
        all_samples = generator.generate()

    samples = all_samples[:max_samples]
    print(f"  Loaded {len(samples)} samples")

    # 初始化 LLM 客户端
    llm_client = create_client()

    # 逐样本处理
    results = []
    for i, sample in enumerate(samples):
        code = sample["code"]
        label = sample["label"]
        sample_id = sample["id"]
        hop_count = sample.get("hop_count", 0)
        vul_type = sample.get("vul_type", "unknown")

        print(f"\n[{i+1}/{len(samples)}] sample_id={sample_id}, "
              f"type={vul_type}, hop={hop_count}, label={'VUL' if label else 'BEN'}")

        sample_dir = os.path.join("output", f"sample_{sample_id}")
        os.makedirs(sample_dir, exist_ok=True)
        code_path = os.path.join(sample_dir, "source.c")
        with open(code_path, "w", encoding="utf-8") as f:
            f.write(code)

        result = {
            "sample_id": sample_id,
            "label": label,
            "hop_count": hop_count,
            "vul_type": vul_type,
        }

        try:
            from graph.pipeline import run_hgl_pipeline
            details = run_hgl_pipeline(code_path, code, sample_id, sample_dir, llm_client,
                                       token_budget, return_details=True)
            result.update(details)
            result["node_reduction_pct"] = details["reduction_stats"].get("node_reduction_pct", 0)
            result["error"] = None
        except Exception as e:
            print(f"  [Error] 管线失败: {e}")
            result["prediction"] = None
            result["error"] = str(e)

        # 记录结果
        is_correct = result.get("prediction") == label
        print(f"  --> prediction={result.get('prediction')}, "
              f"correct={'✓' if is_correct else '✗'}")
        results.append(result)

    # 计算指标（v2.0 跳数分层）
    print("\n" + "=" * 60)
    print("  Evaluation Results (v2.0 Hop-Stratified)")
    print("=" * 60)
    report = compute_detailed_report(results)
    print(report)

    # 保存结果
    output_path = os.path.join("output", "evaluation_results_v2.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({
            "config": {
                "mode": "evaluate",
                "data_dir": data_dir,
                "max_samples": max_samples,
                "token_budget": token_budget,
                "model": LLM_MODEL,
            },
            "results": results,
            "metrics": compute_long_range_metrics(results),
            "reduction_metrics": compute_code_reduction_metrics(results),
        }, f, indent=2, ensure_ascii=False)
    print(f"\n[Saved] {output_path}")
