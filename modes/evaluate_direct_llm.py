"""
Mode 7: Direct LLM 基线——不经过 HGL-Vul 管线，直接将代码发给 LLM

对比目的：
  - Direct LLM: 裸代码 → LLM（测量 LLM 自身漏洞检测能力）
  - HGL-Vul:   代码 → 图压缩 → 层次化线性化 → LLM（测量框架增益）
  - VulnSC:    代码 → 语义注释增强 → CodeBERT（测量语义补全效果）

控制变量（与 HGL-Vul 评测保持一致）：
  - 相同 LLM (DeepSeek)、相同 temperature=0
  - 完全相同的数据集和折分
  - 相同 prompt 风格（仅描述结果格式）
"""
import os
import sys
import json
import time
import random

from config import LLM_MODEL, SEED
from reasoning.llm_api import create_client


def mode_evaluate_direct_llm(
    devign_json: str = None,
    enhance_dir: str = None,
    fold: int = 0,
    max_samples: int = 200,
    output_dir: str = "output/direct_llm_eval",
    resume: bool = True,
):
    """Direct LLM 基线——裸代码直送 LLM。"""
    from data.devign_loader import DevignLoader, DevignBatchProcessor

    print("=" * 70)
    print("  Mode 7: Direct LLM Baseline")
    print("  (裸代码直送 LLM，无图结构处理)")
    print("=" * 70)

    print(f"\n[控制变量]")
    print(f"  LLM Model:      {LLM_MODEL}")
    print(f"  Temperature:    0.0")
    print(f"  Fold:           {fold}")
    print(f"  Max Samples:    {max_samples}")
    print(f"  Seed:           {SEED}")

    # ---- 路径解析 ----
    if devign_json is None:
        candidate = r"C:\Users\wzh13\Desktop\Network Security Research\Enhancing Vulnerability Detection via Inter-procedural Semantic CompletionEnhancing Vulnerability Detection via Inter-procedural Semantic Completion\data\origin-20260913T072238Z-1-001\origin\devign.json"
        if os.path.exists(candidate):
            devign_json = candidate
        else:
            print("[Error] 未指定 devign_json 路径，请通过参数传入")
            sys.exit(1)

    if enhance_dir is None:
        candidate = r"C:\Users\wzh13\Desktop\Network Security Research\Enhancing Vulnerability Detection via Inter-procedural Semantic CompletionEnhancing Vulnerability Detection via Inter-procedural Semantic Completion\data\enhance-20260913T072240Z-1-001\enhance\devign"
        if os.path.exists(candidate):
            enhance_dir = candidate
        else:
            enhance_dir = None

    # ---- Step 1: 加载数据 ----
    print(f"\n[Step 1/5] 加载 Devign 数据集")
    loader = DevignLoader(devign_json)

    fold_indices = None
    if enhance_dir:
        try:
            fold_indices = loader.extract_fold_indices_from_enhanced(enhance_dir, model="gpt4o")
        except Exception:
            pass

    loader.load(fold_indices=fold_indices)
    test_samples = loader.get_fold(fold=fold, split="test")
    print(f"  Test set: {len(test_samples)} 样本 (fold={fold})")

    if max_samples > 0:
        vuln_samples = [s for s in test_samples if s.target == 1]
        benign_samples = [s for s in test_samples if s.target == 0]
        n_vuln = min(len(vuln_samples), max_samples // 2)
        n_benign = min(len(benign_samples), max_samples - n_vuln)
        random.seed(SEED)
        selected = random.sample(vuln_samples, n_vuln) + random.sample(benign_samples, n_benign)
        random.shuffle(selected)
        test_samples = selected
        print(f"  Sampled: {len(test_samples)} ({n_vuln} vuln + {n_benign} benign)")

    # ---- Step 2: 准备样本 ----
    print(f"\n[Step 2/5] 准备样本")
    processor = DevignBatchProcessor(output_dir=output_dir)
    metadata_list = processor.prepare_samples(test_samples, use_enhanced=False)

    # ---- Step 3: 初始化 LLM ----
    print(f"\n[Step 3/5] 初始化 LLM 客户端")
    llm_client = create_client()

    # 恢复已有结果
    existing_results = processor.load_results() if resume else []
    completed_indices = {r.get("idx") for r in existing_results}
    print(f"  已有结果: {len(completed_indices)} 个样本")

    # ---- Step 4: Direct LLM 推理 ----
    print(f"\n[Step 4/5] Direct LLM 推理（无图结构）")

    results = list(existing_results)
    pending = [m for m in metadata_list if m["idx"] not in completed_indices]
    print(f"  待评测: {len(pending)} 个样本")

    # Direct LLM 的 prompt — 简洁、公平
    DIRECT_PROMPT_TEMPLATE = """You are a C/C++ security expert. Analyze the following code and determine if it contains a vulnerability.

Code:
```c
{code}
```

Is this code vulnerable? Answer with exactly one word: "vulnerable" or "benign".
"""

    if not pending:
        print("  全部已完成，跳过评测。")
    else:
        start_time = time.time()
        for i, meta in enumerate(pending):
            idx = meta["idx"]
            file_path = meta["file_path"]
            target = meta["target"]
            sample_id = meta["sample_id"]

            print(f"\n  [{i+1}/{len(pending)}] idx={idx}, target={'VUL' if target else 'BEN'}")

            sample_start = time.time()
            result = {
                "idx": idx,
                "sample_id": sample_id,
                "target": target,
                "fold": meta["fold"],
                "project": meta["project"],
                "mode": "direct_llm",
                "error": None,
                "prediction": 0,
            }

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    code = f.read()

                # 截断过长代码（防止超出 context）
                max_code_len = 6000
                if len(code) > max_code_len:
                    code = code[:max_code_len] + "\n// ... (truncated)"

                prompt = DIRECT_PROMPT_TEMPLATE.format(code=code)

                response = llm_client.chat.completions.create(
                    model=LLM_MODEL,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.0,
                    max_tokens=16,
                )
                answer = response.choices[0].message.content.strip().lower()
                result["raw_answer"] = answer
                result["prediction"] = 1 if "vulnerable" in answer else 0
                result["error"] = None

            except Exception as e:
                print(f"    [Error] {e}")
                result["prediction"] = 0
                result["error"] = str(e)

            is_correct = result["prediction"] == target
            elapsed = time.time() - sample_start
            print(f"    --> prediction={result['prediction']} ({result.get('raw_answer','?')}), "
                  f"correct={'✓' if is_correct else '✗'}, time={elapsed:.1f}s")

            results.append(result)
            processor.save_intermediate(result)

        total_time = time.time() - start_time
        print(f"\n  评测完成: {len(pending)} 样本, 耗时 {total_time:.1f}s")

    # ---- Step 5: 计算指标 ----
    valid_results = [r for r in results if r.get("prediction") is not None]
    y_true = [r["target"] for r in valid_results]
    y_pred = [r["prediction"] for r in valid_results]

    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    metrics = {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "total_samples": len(valid_results),
        "vulnerable": sum(y_true),
        "benign": len(y_true) - sum(y_true),
        "mode": "direct_llm",
    }

    print(f"\n  {'='*50}")
    print(f"  Direct LLM on Devign (Fold {fold}) — Results")
    print(f"  {'='*50}")
    print(f"  Accuracy:  {metrics['accuracy']:.4f}  ({metrics['accuracy']*100:.2f}%)")
    print(f"  Precision: {metrics['precision']:.4f}  ({metrics['precision']*100:.2f}%)")
    print(f"  Recall:    {metrics['recall']:.4f}  ({metrics['recall']*100:.2f}%)")
    print(f"  F1-Score:  {metrics['f1']:.4f}  ({metrics['f1']*100:.2f}%)")
    print(f"  {'='*50}")

    output_path = os.path.join(output_dir, "direct_llm_results.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({"config": {
            "mode": "direct_llm",
            "fold": fold,
            "max_samples": max_samples,
            "llm_model": LLM_MODEL,
        }, "metrics": metrics, "results": valid_results}, f, indent=2, ensure_ascii=False)
    print(f"\n[Saved] {output_path}")

    return metrics