"""
Mode 4: 消融实验

运行所有消融配置，量化每个模块的贡献。
"""
import os
from config import LLM_MODEL, SYNTHETIC_DIR
from reasoning.llm_api import create_client
from evaluation.ablation import run_ablation_study, generate_ablation_report


def mode_ablation(data_dir: str = None, max_samples: int = 30):
    """消融实验。"""
    print("=" * 60)
    print("  Mode 4: Ablation Study")
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

    # 运行消融实验
    output_dir = os.path.join("output", "ablation")
    llm_client = create_client()

    results = run_ablation_study(
        dataset=samples,
        output_dir=output_dir,
        llm_client=llm_client,
        model=LLM_MODEL,
        max_samples=max_samples,
    )

    # 生成报告
    report = generate_ablation_report(results)
    print(report)

    # 保存报告
    report_path = os.path.join(output_dir, "ablation_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"\n[Saved] {report_path}")