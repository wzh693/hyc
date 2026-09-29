"""
Mode 5: 鲁棒性评估

对代码进行语义等价变换，测试模型稳定性。
"""
import os
import tempfile

from config import LLM_MODEL, SYNTHETIC_DIR
from graph.build_cpg import build_cpg, find_export_files
from graph.load_graph import load_graph
from graph.summarize_graph import summarize_graph
from retrieval.candidate_paths import extract_all_candidate_paths
from retrieval.retrieve_topk import retrieve_topk
from linearization.function_summary import summarize_function
from linearization.block_summary import summarize_block
from linearization.typed_paths import typed_dependency_path, build_hierarchical_context, extract_api_hints
from reasoning.llm_api import create_client
from reasoning.reasoning_loop import reasoning_loop
from planning.state_memory import ProgramState
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
        for idx, fname in enumerate(c_files):
            fpath = os.path.join(data_dir, fname)
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
            label = 1 if any(kw in fname.lower() for kw in ["uaf", "overflow", "double_free", "taint", "leak", "null"]) else 0
            all_samples.append({"id": idx + 1, "code": code, "label": label})
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
            export_dir = build_cpg(code_path, tmpdir)
            nodes_file, edges_file = find_export_files(export_dir)
            G = load_graph(nodes_file, edges_file)
            SG = summarize_graph(G, verbose=False)
            paths = extract_all_candidate_paths(SG, source_code=code)
            if not paths:
                paths = extract_all_candidate_paths(G, source_code=code)
            topk = retrieve_topk(SG, paths)

            # 完整 HGL-Vul 管线：层次化线性化 + 程序状态记忆 + 受限推理
            func_summary = summarize_function(code)
            api_hints = extract_api_hints(code)
            blocks = code.split("\n\n")
            block_summaries = {}
            for j, block in enumerate(blocks):
                if block.strip():
                    block_summaries[j] = summarize_block(block) or block.strip()[:80]

            paths_context = []
            for path in topk[:5]:
                path_str = typed_dependency_path(SG, path, api_hints=api_hints)
                if path_str:
                    paths_context.append(path_str)

            state = ProgramState()
            state.track_vars(code)

            loop_result = reasoning_loop(
                SG, topk, code, func_summary, block_summaries,
                client=llm_client,
            )
            conclusion = loop_result.get("conclusion", "").lower()
            return 1 if "vulnerable" in conclusion else 0
        except Exception:
            return 0

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