"""
Mode 5: 鲁棒性评估

对代码进行语义等价变换，测试模型稳定性。
"""
import os
import json
import tempfile
import shutil

from config import LLM_MODEL, SYNTHETIC_DIR
from graph.build_cpg import build_cpg, find_export_files
from graph.load_graph import load_graph
from graph.summarize_graph import summarize_graph
from retrieval.candidate_paths import extract_all_candidate_paths
from retrieval.retrieve_topk import retrieve_topk
from linearization.function_summary import summarize_function
from linearization.block_summary import summarize_block
from reasoning.llm_api import create_client
from reasoning.reasoning_loop import reasoning_loop
from evaluation.robustness import (
    evaluate_robustness, generate_robustness_report,
)


def mode_robustness_eval(data_dir: str = None, max_samples: int = 30):
    """鲁棒性评估。"""
    print("=" * 60)
    print("  Mode 5: Robustness Evaluation")
    print("=" * 60)

    if data_dir is None:
        data_dir = SYNTHETIC_DIR

    # 加载数据集
    all_samples = []
    c_files = sorted(
        f for f in os.listdir(data_dir)
        if f.endswith(".c") or f.endswith(".cpp")
    ) if os.path.isdir(data_dir) else []

    if c_files:
        print(f"  从 {data_dir} 加载 {len(c_files)} 个源文件")
        metadata = {}
        metadata_path = os.path.join(data_dir, "metadata.json")
        if os.path.exists(metadata_path):
            with open(metadata_path, encoding="utf-8") as f:
                metadata = json.load(f)
        meta_map = {s.get("filename"): s for s in metadata.get("samples", [])
                    if s.get("filename")}
        if meta_map:
            c_files = [f for f in c_files if f in meta_map]
        for idx, fname in enumerate(c_files):
            fpath = os.path.join(data_dir, fname)
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
            meta = meta_map.get(fname, {})
            label = meta.get("label")
            if label is None:
                label = 1 if any(kw in fname.lower() for kw in [
                    "uaf", "overflow", "double_free", "taint", "leak", "null"
                ]) else 0
            all_samples.append({
                "id": meta.get("id", idx + 1), "code": code, "label": label,
            })
    else:
        from data.synthetic_generator import SyntheticDatasetGenerator
        generator = SyntheticDatasetGenerator()
        all_samples = generator.generate()

    samples = all_samples[:max_samples]
    print(f"  Dataset: {len(samples)} samples")

    # 定义预测函数
    llm_client = create_client()

    def predictor_fn(code: str) -> int:
        """预测给定代码是否有漏洞。"""
        tmpdir = tempfile.mkdtemp()
        code_path = os.path.join(tmpdir, "source.c")
        with open(code_path, "w", encoding="utf-8") as f:
            f.write(code)

        try:
            from graph.pipeline import run_hgl_pipeline
            prediction, _, _, _ = run_hgl_pipeline(code_path, code, "robustness",
                                                   tmpdir, llm_client)
            return prediction
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    # 运行鲁棒性评估
    output_dir = os.path.join("output", "robustness")
    results = evaluate_robustness(
        dataset=samples,
        predictor_fn=predictor_fn,
        output_dir=output_dir,
        max_samples=max_samples,
    )

    # 生成报告
    report = generate_robustness_report(results)
    print(report)

    # 保存报告
    report_path = os.path.join(output_dir, "robustness_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"\n[Saved] {report_path}")
