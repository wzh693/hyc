"""
HGL-Vul: Hierarchical Graph Linearization for Vulnerability Reasoning
==========================================================================
面向长距离漏洞推理的分层图线性化框架 v2.0

运行模式:
  analyze <file> [output_dir]                   单文件漏洞分析
  generate-synthetic [output_dir]               生成合成数据集
  evaluate <data_dir> [max_samples]             HGL-Vul 完整评测（LLM）
  ablation <data_dir> [max_samples]             消融实验
  robustness-eval <data_dir> [max_samples]      鲁棒性评估
  evaluate-devign                               在 Devign 数据集上评测
  direct-llm [fold] [max_samples]               Direct LLM 基线
  compare [fold] [max_samples]                  三组对比实验
  help                                          显示帮助

v2.0 新增:
  - 动态 Token 预算感知图压缩
  - 跳数分层评测（short/medium/long/very_long）
  - 消融实验框架（量化各模块贡献）
  - 代码变换鲁棒性评估
  - 缩减率统计报告
  - Devign 标准数据集评测（与 VulnSC 共享 4 折划分）

控制变量:
  - 4 折划分与 VulnSC 完全一致（从增强数据提取 fold indices）
  - LLM temperature=0（确定性输出）
  - 默认评测原始代码 func（非增强 func_en），测量纯图推理能力
  - 使用 --use-enhanced 可启用增强代码测试联合效果
"""

import sys
import os

# 从 config.py 读取 LLM 配置（也支持环境变量覆盖）
from config import LLM_API_KEY, LLM_BASE_URL, LLM_MODEL
os.environ.setdefault("OPENAI_API_KEY", LLM_API_KEY)
os.environ.setdefault("OPENAI_BASE_URL", LLM_BASE_URL)
os.environ.setdefault("LLM_MODEL", LLM_MODEL)

from modes.analyze import mode_analyze, DEFAULT_TOKEN_BUDGET
from modes.generate_synthetic import mode_generate_synthetic
from modes.evaluate_hgl import mode_evaluate_hgl
from modes.evaluate_devign import mode_evaluate_devign
from modes.evaluate_direct_llm import mode_evaluate_direct_llm
from modes.compare_devign import mode_compare_devign
from modes.ablation import mode_ablation
from modes.robustness_eval import mode_robustness_eval


def print_usage():
    """打印使用说明。"""
    print("""
HGL-Vul: Hierarchical Graph Linearization for Vulnerability Reasoning
==========================================================================

Usage:
  python main.py <mode> [args]

Modes:
  analyze <file> [output_dir] [token_budget]
                        单文件漏洞分析
    Example:
      python main.py analyze test.c ./cpg_output 4096

  generate-synthetic [output_dir]
                        生成合成数据集
    Example:
      python main.py generate-synthetic ./data/synthetic

  evaluate [data_dir] [max_samples] [token_budget]
                        HGL-Vul 完整评测（跳数分层 + 缩减率统计）
    Example:
      python main.py evaluate ./data/synthetic 50 4096

  evaluate-devign [fold] [max_samples]
                        在 Devign 标准数据集上评测 HGL-Vul
                        控制变量与 VulnSC 保持一致
    Example:
      python main.py evaluate-devign 0 200

  evaluate-devign-full [fold] [token_budget]
                        在 Devign 上全量评测（使用全部 test 样本）
                        支持 --use-enhanced 使用 VulnSC 增强代码
    Example:
      python main.py evaluate-devign-full 0 4096

  direct-llm [fold] [max_samples]
                        Direct LLM 基线（裸代码→DeepSeek，无图处理）
    Example:
      python main.py direct-llm 0 200

  compare [fold] [max_samples]
                        三组对比实验：Direct LLM vs HGL-Vul vs VulnSC(DeepSeek)
    Example:
      python main.py compare 0 50

  ablation [data_dir] [max_samples]
                        消融实验（量化各模块贡献）
    Example:
      python main.py ablation ./data/synthetic 30

  robustness-eval [data_dir] [max_samples]
                        鲁棒性评估（代码变换稳定性测试）
    Example:
      python main.py robustness-eval ./data/synthetic 20

  help                 显示帮助
""")


def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(0)

    mode = sys.argv[1].lower()

    if mode == "analyze":
        if len(sys.argv) < 3:
            print("[Error] 缺少文件路径\n用法: python main.py analyze <file> [output_dir] [token_budget]")
            sys.exit(1)
        code_path = sys.argv[2]
        output_dir = sys.argv[3] if len(sys.argv) > 3 else "./cpg_output"
        token_budget = int(sys.argv[4]) if len(sys.argv) > 4 else DEFAULT_TOKEN_BUDGET
        mode_analyze(code_path, output_dir, token_budget)

    elif mode == "generate-synthetic":
        output_dir = sys.argv[2] if len(sys.argv) > 2 else None
        mode_generate_synthetic(output_dir)

    elif mode == "evaluate":
        data_dir = sys.argv[2] if len(sys.argv) > 2 else None
        max_samples = int(sys.argv[3]) if len(sys.argv) > 3 else 50
        token_budget = int(sys.argv[4]) if len(sys.argv) > 4 else DEFAULT_TOKEN_BUDGET
        mode_evaluate_hgl(data_dir, max_samples, token_budget)

    elif mode == "evaluate-devign":
        fold = int(sys.argv[2]) if len(sys.argv) > 2 else 0
        max_samples = int(sys.argv[3]) if len(sys.argv) > 3 else 200
        use_enhanced = "--use-enhanced" in sys.argv
        mode_evaluate_devign(
            fold=fold,
            max_samples=max_samples,
            use_enhanced=use_enhanced,
        )

    elif mode == "evaluate-devign-full":
        fold = int(sys.argv[2]) if len(sys.argv) > 2 else 0
        token_budget = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_TOKEN_BUDGET
        use_enhanced = "--use-enhanced" in sys.argv
        print("\n⚠️  全量评测模式: 使用全部 test 样本 (~1975/折)")
        print("   预计耗时: ~16 小时 (1975 samples × ~30s)")
        print("   建议先运行 evaluate-devign 0 50 测试管线\n")
        mode_evaluate_devign(
            fold=fold,
            max_samples=-1,
            token_budget=token_budget,
            use_enhanced=use_enhanced,
        )

    elif mode == "direct-llm":
        fold = int(sys.argv[2]) if len(sys.argv) > 2 else 0
        max_samples = int(sys.argv[3]) if len(sys.argv) > 3 else 200
        mode_evaluate_direct_llm(fold=fold, max_samples=max_samples)

    elif mode == "compare":
        fold = int(sys.argv[2]) if len(sys.argv) > 2 else 0
        max_samples = int(sys.argv[3]) if len(sys.argv) > 3 else 50
        min_func_bytes = int(sys.argv[4]) if len(sys.argv) > 4 else 0
        mode_compare_devign(fold=fold, max_samples=max_samples, min_func_bytes=min_func_bytes)

    elif mode == "ablation":
        data_dir = sys.argv[2] if len(sys.argv) > 2 else None
        max_samples = int(sys.argv[3]) if len(sys.argv) > 3 else 30
        mode_ablation(data_dir, max_samples)

    elif mode == "robustness-eval":
        data_dir = sys.argv[2] if len(sys.argv) > 2 else None
        max_samples = int(sys.argv[3]) if len(sys.argv) > 3 else 20
        mode_robustness_eval(data_dir, max_samples)

    elif mode == "help":
        print_usage()

    else:
        print(f"[Error] 未知模式: {mode}")
        print_usage()
        sys.exit(1)


if __name__ == "__main__":
    main()