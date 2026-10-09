"""
代码变换鲁棒性评估 (Code Transformation Robustness Evaluation)。

验证 HGL-Vul 对语义等价代码变换的稳定性：
  1. 变量重命名（identifier renaming）
  2. 死代码插入（dead code insertion）
  3. 控制流等价变换（control-flow equivalent transformation）
  4. 函数分裂/内联（function splitting/inlining）

每个变换保持程序语义不变但改变其语法表示，
评估模型在原始代码和变换后代码之间的一致性。
"""

import os
import re
import sys
import json
import random
import copy
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from evaluation.metrics import compute_metrics


# ===========================================================================
# 代码变换器
# ===========================================================================

class CodeTransformer:
    """
    代码变换基类。
    对输入的 C 代码应用语义等价的语法变换。
    """

    def __init__(self, seed: int = 42):
        self.random = random.Random(seed)

    def transform(self, code: str) -> str:
        """对代码应用变换，返回变换后的代码。"""
        raise NotImplementedError

    @property
    def name(self) -> str:
        """变换名称，用于报告。"""
        return self.__class__.__name__


class VariableRenamer(CodeTransformer):
    """变量重命名变换：将所有局部变量名替换为同义不同名的标识符。"""

    def transform(self, code: str) -> str:
        # 识别 C 语言中的变量声明和使用的模式
        # 不重命名函数名和库函数
        reserved = {
            "int", "char", "void", "float", "double", "long", "short",
            "unsigned", "signed", "const", "static", "struct", "typedef",
            "if", "else", "for", "while", "do", "switch", "case", "break",
            "continue", "return", "goto", "sizeof", "NULL", "main",
            "malloc", "free", "calloc", "realloc", "memcpy", "memset",
            "strcpy", "strncpy", "strlen", "strcmp", "printf", "fprintf",
            "sprintf", "snprintf", "recv", "send", "open", "read", "write",
            "close", "exit", "assert", "FILE", "size_t", "ssize_t",
        }

        # 提取所有标识符
        identifiers = set(re.findall(r'\b([a-zA-Z_]\w*)\b', code))
        identifiers -= reserved

        # 过滤掉看起来像函数名的（后面跟 '(' 的）
        func_names = set(re.findall(r'\b([a-zA-Z_]\w*)\s*\(', code))
        identifiers -= func_names

        # 生成重命名映射
        rename_map = {}
        counter = 0
        for ident in sorted(identifiers):
            if ident in reserved:
                continue
            new_name = f"v{counter}"
            rename_map[ident] = new_name
            counter += 1

        # 逐个替换标识符（仅替换完整单词）
        result = code
        for old, new in rename_map.items():
            result = re.sub(r'\b' + re.escape(old) + r'\b', new, result)

        return result


class DeadCodeInserter(CodeTransformer):
    """死代码插入变换：在函数体中插入语义无关的死代码。"""

    def transform(self, code: str) -> str:
        lines = code.split("\n")
        result = []

        dead_code_templates = [
            "    int dead_var_{idx} = 0;",
            "    dead_var_{idx}++;",
            "    if (dead_var_{idx} > 1000) {{ }}",  # 注意花括号转义
            "    int unused_{idx} = dead_var_{idx} * 2;",
            "    for(int i_{idx}=0; i_{idx}<5; i_{idx}++) {{ }}",
            "    while(0) {{ break; }}",
            "    {{ int x_{idx} = 42; }}",
        ]

        idx = 0
        for line in lines:
            result.append(line)
            # 在函数体内的行后插入死代码
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and \
               not stripped.startswith("//") and not stripped.startswith("/*") and \
               not stripped.startswith("*"):
                if self.random.random() < 0.1:  # 10% 概率插入
                    template = self.random.choice(dead_code_templates)
                    # 处理花括号转义问题
                    t = template.replace("{{", "{").replace("}}", "}")
                    result.append(t.format(idx=idx))
                    idx += 1

        return "\n".join(result)


class ControlFlowTransformer(CodeTransformer):
    """
    控制流等价变换：
      - if-else → switch（简单的 pattern）
      - while → for
      - 单层 if 条件取反
    """

    def transform(self, code: str) -> str:
        result = code

        # 变换1: if(x) { A } else { B } → if(!x) { B } else { A }（条件取反交换分支）
        # 简单的单行情况
        result = re.sub(
            r'if\s*\((\w+)\s*(!=\s*0)?\)\s*{([^}]*?)}\s*else\s*{([^}]*?)}',
            lambda m: f"if(!{m.group(1)}){{{m.group(4)}}}else{{{m.group(3)}}}",
            result
        )

        # 变换2: while(x) 不变但加一个复合条件（语义等价）
        # 实际上 while(x) 等价于 while((x) != 0)，保持语义不变
        result = re.sub(
            r'\bwhile\s*\((\w+)\)\s*{',
            lambda m: f"while(({m.group(1)}) != 0){{\n    /* transformed */",
            result
        )

        return result


class FunctionSplitter(CodeTransformer):
    """函数分裂变换：将单一函数中的逻辑拆分到辅助函数中。"""

    def transform(self, code: str) -> str:
        # 识别函数定义
        func_pattern = re.compile(
            r'(void|int|char|float|double|char\s*\*|int\s*\*|void\s*\*)\s+'
            r'(\w+)\s*\(([^)]*)\)\s*{'
        )

        result = code
        # 简单变换：将函数体中的 if 条件内的代码提取为辅助函数
        # 仅当被测函数有适当的 if 块时做变换
        # 这里只做轻量级变换，不对复杂嵌套做深度处理
        # 将单层 if 分支中的代码包装成辅助函数调用

        matches = list(func_pattern.finditer(code))
        if not matches:
            return code

        # 对每个函数尝试分裂
        for m in reversed(matches):  # 从后往前替换避免偏移问题
            func_name = m.group(2)
            params = m.group(3)

            # 找到函数体开始位置
            start = m.end()
            # 扫描平衡花括号找到函数体结束
            depth = 1
            pos = start
            while pos < len(result) and depth > 0:
                if result[pos] == '{':
                    depth += 1
                elif result[pos] == '}':
                    depth -= 1
                pos += 1
            body_end = pos - 1  # 函数体的结束 } 位置

            # 只在函数体足够大时做分裂
            body = result[start:body_end]
            if len(body) < 100:
                continue

            # 查找 if(p) { cleanup(x); } 之类的模式
            # 简化处理：不做太复杂的分裂变换，避免引入错误
            # 只重命名函数为 original_func_wrapper，添加辅助函数声明
            pass  # 保留扩展性

        return result


# ===========================================================================
# 鲁棒性评测引擎
# ===========================================================================

TRANSFORMATIONS = [
    VariableRenamer,
    DeadCodeInserter,
    ControlFlowTransformer,
    # FunctionSplitter,  # 较复杂，默认不启用
]


def apply_transformations(code: str, seed: int = 42) -> dict:
    """
    对代码应用所有变换。
    返回 {transform_name: transformed_code} 字典。
    """
    results = {"original": code}
    for T in TRANSFORMATIONS:
        try:
            t = T(seed=seed)
            results[t.name] = t.transform(code)
        except Exception as e:
            results[t.name] = f"/* 变换失败: {e} */\n{code}"
    return results


def evaluate_robustness(
    dataset: list,
    predictor_fn,
    output_dir: str,
    max_samples: int = 30,
    seed: int = 42,
) -> dict:
    """
    鲁棒性评估主函数。

    参数:
        dataset: 样本列表
        predictor_fn: 预测函数，签名 fn(code: str) -> int（返回 0/1）
        output_dir: 输出目录
        max_samples: 最多评估样本数
        seed: 随机种子

    返回:
        results: {
            "summary": {
                "original_f1": ...,
                "VariableRenamer_f1": ...,
                "DeadCodeInserter_f1": ...,
                "avg_agreement": ...
            },
            "details": {
                "VariableRenamer": {
                    "per_sample": [...],
                    "metrics": {...},
                    "agreement_with_original": 0.85,
                },
                ...
            }
        }
    """
    samples = dataset[:max_samples]
    os.makedirs(output_dir, exist_ok=True)

    # 1. 预测原始代码
    print("\n" + "=" * 60)
    print("  [Robustness] 原始代码预测")
    print("=" * 60)
    original_predictions = []
    for i, sample in enumerate(samples):
        print(f"  [{i+1}/{len(samples)}] sample_id={sample['id']}...", end=" ")
        try:
            pred = predictor_fn(sample["code"])
            original_predictions.append(pred)
            print("✓")
        except Exception as e:
            print(f"✗ ({e})")
            original_predictions.append(None)

    original_metrics = compute_metrics(
        [s["label"] for s in samples],
        original_predictions,
    )
    print(f"  Original F1: {original_metrics['f1']:.4f}")

    # 2. 对每种变换运行预测
    results = {
        "summary": {
            "original_f1": original_metrics["f1"],
            "original_precision": original_metrics["precision"],
            "original_recall": original_metrics["recall"],
            "original_accuracy": original_metrics["accuracy"],
        },
        "details": {},
        "n_samples": len(samples),
    }

    transform_names = [T.__name__ for T in TRANSFORMATIONS]

    for transform_name in transform_names:
        print(f"\n  [Robustness] 变换: {transform_name}")
        transform_predictions = []

        for i, sample in enumerate(samples):
            print(f"    [{i+1}/{len(samples)}] sample_id={sample['id']}...", end=" ")

            # 应用变换
            transformed_variants = apply_transformations(sample["code"], seed=seed + i)
            transformed_code = transformed_variants.get(transform_name, sample["code"])

            if transformed_code.startswith("/* 变换失败"):
                print(f"✗ (变换失败)")
                # 变换没有真正执行，不能复制原预测来虚增一致率。
                transform_predictions.append(None)
                continue

            try:
                pred = predictor_fn(transformed_code)
                transform_predictions.append(pred)
                # 检查是否与原始预测一致
                agreement = "✓" if pred == original_predictions[i] else "✗"
                label = sample["label"]
                correct = "✓" if pred == label else "✗"
                print(f"{agreement} (pred={pred}, label={label}{correct})")
            except Exception as e:
                print(f"✗ ({e})")
                transform_predictions.append(None)

        # 计算指标
        metrics = compute_metrics(
            [s["label"] for s in samples],
            transform_predictions,
        )

        # 计算与原始预测的一致性
        comparable = [(a, b) for a, b in zip(original_predictions, transform_predictions)
                      if a in (0, 1) and b in (0, 1)]
        agreement = (sum(1 for a, b in comparable if a == b) / len(comparable)
                     if comparable else 0.0)

        per_sample = [
            {
                "sample_id": samples[i]["id"],
                "label": samples[i]["label"],
                "original_pred": original_predictions[i],
                "transformed_pred": transform_predictions[i],
                "consistent": (original_predictions[i] in (0, 1)
                               and transform_predictions[i] in (0, 1)
                               and original_predictions[i] == transform_predictions[i]),
                "correct": (transform_predictions[i] in (0, 1)
                            and transform_predictions[i] == samples[i]["label"]),
            }
            for i in range(len(samples))
        ]

        results["details"][transform_name] = {
            "metrics": metrics,
            "agreement_with_original": agreement,
            "per_sample": per_sample,
        }

        # 保存中间结果
        result_path = os.path.join(output_dir, f"{transform_name}_results.json")
        with open(result_path, "w", encoding="utf-8") as f:
            json.dump({
                "metrics": metrics,
                "agreement": agreement,
                "per_sample": per_sample,
            }, f, indent=2, ensure_ascii=False)

    # 计算摘要统计
    avg_agreement = 0
    avg_f1 = 0
    for transform_name in transform_names:
        detail = results["details"].get(transform_name, {})
        avg_agreement += detail.get("agreement_with_original", 0)
        avg_f1 += detail.get("metrics", {}).get("f1", 0)
    n = len(transform_names)
    results["summary"]["avg_agreement"] = avg_agreement / n if n > 0 else 1.0
    results["summary"]["avg_transformed_f1"] = avg_f1 / n if n > 0 else 0

    # 保存完整结果
    summary_path = os.path.join(output_dir, "robustness_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        summary_data = {
            "summary": results["summary"],
            "details": {
                k: {
                    "metrics": v["metrics"],
                    "agreement_with_original": v["agreement_with_original"],
                }
                for k, v in results["details"].items()
            },
        }
        json.dump(summary_data, f, indent=2, ensure_ascii=False)

    return results


def generate_robustness_report(results: dict) -> str:
    """
    生成鲁棒性评估报告（Markdown 格式）。
    """
    lines = []
    lines.append("=" * 70)
    lines.append("ROBUSTNESS EVALUATION REPORT")
    lines.append("=" * 70)

    lines.append(f"\n样本数: {results.get('n_samples', 'N/A')}")
    lines.append(f"原始代码 F1: {results['summary']['original_f1']:.4f}")
    lines.append(f"原始代码 Accuracy: {results['summary']['original_accuracy']:.4f}")

    lines.append(f"\n{'Transformation':<35} {'F1':<10} {'Agreement':<12}")
    lines.append(f"{'-'*35} {'-'*10} {'-'*12}")

    for transform_name, detail in results["details"].items():
        metrics = detail.get("metrics", {})
        agreement = detail.get("agreement_with_original", 0)
        lines.append(
            f"  {transform_name:<35} "
            f"{metrics.get('f1', 0):<10.4f} "
            f"{agreement:<12.2%}"
        )

    lines.append(f"\n{'Average (transformed)':<35} {results['summary']['avg_transformed_f1']:<10.4f} {results['summary']['avg_agreement']:<12.2%}")

    lines.append("\n\n[Per-Sample Consistency Details]")
    for transform_name, detail in results["details"].items():
        per_sample = detail.get("per_sample", [])
        n_consistent = sum(1 for s in per_sample if s.get("consistent"))
        lines.append(f"\n  {transform_name}: {n_consistent}/{len(per_sample)} 一致")

    lines.append("\n" + "=" * 70)
    return "\n".join(lines)
