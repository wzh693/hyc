"""
Mode 6: 在 Devign 标准数据集上评测 HGL-Vul

控制变量说明:
  - 使用与 VulnSC 完全一致的 4 折划分（从增强数据提取）
  - LLM temperature=0 确保确定性输出
  - 默认使用原始代码 func（非增强），评测纯图推理
  - 使用 --use-enhanced 可启用 func_en 测试联合效果
"""
import os
import sys
import json
import time
import random

from config import LLM_MODEL, SEED
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


def mode_evaluate_devign(
    devign_json: str = None,
    enhance_dir: str = None,
    fold: int = 0,
    max_samples: int = 200,
    token_budget: int = DEFAULT_TOKEN_BUDGET,
    use_enhanced: bool = False,
    enhance_model: str = "gpt4o",
    output_dir: str = "output/devign_eval",
    resume: bool = True,
):
    """在 Devign 标准数据集上评测 HGL-Vul。"""
    from data.devign_loader import DevignLoader, DevignBatchProcessor

    print("=" * 70)
    print("  Mode 6: HGL-Vul Evaluation on Devign Benchmark")
    print("  (与 VulnSC 共享 4 折划分，控制变量确保可比性)")
    print("=" * 70)

    # ---- 控制变量确认 ----
    print(f"\n[控制变量]")
    print(f"  LLM Model:      {LLM_MODEL}")
    print(f"  Temperature:    0.0 (确定性)")
    print(f"  Token Budget:   {token_budget}")
    print(f"  Fold:           {fold}")
    print(f"  Use Enhanced:   {use_enhanced} ({enhance_model})")
    print(f"  Max Samples:    {'全部' if max_samples < 0 else max_samples}")
    print(f"  Seed:           {SEED}")
    print(f"  Output Dir:     {output_dir}")
    print(f"  Resume:         {resume}")

    # ---- 路径解析 ----
    if devign_json is None:
        candidate = r"C:\Users\wzh13\Desktop\Network Security Research\Enhancing Vulnerability Detection via Inter-procedural Semantic CompletionEnhancing Vulnerability Detection via Inter-procedural Semantic Completion\data\origin-20260913T072238Z-1-001\origin\devign.json"
        if os.path.exists(candidate):
            devign_json = candidate
        else:
            print("[Error] 未指定 devign_json 路径，请通过 --devign-json 参数传入")
            print("  用法: python main.py evaluate-devign --devign-json <path>")
            sys.exit(1)

    if enhance_dir is None:
        candidate = r"C:\Users\wzh13\Desktop\Network Security Research\Enhancing Vulnerability Detection via Inter-procedural Semantic CompletionEnhancing Vulnerability Detection via Inter-procedural Semantic Completion\data\enhance-20260913T072240Z-1-001\enhance\devign"
        if os.path.exists(candidate):
            enhance_dir = candidate
        else:
            print("[Warning] 未找到增强数据目录，将使用随机 4 折划分（可通过 --enhance-dir 指定）")
            enhance_dir = None

    # ---- Step 1: 加载 Devign 数据集 ----
    print(f"\n[Step 1/6] 加载 Devign 数据集")
    loader = DevignLoader(devign_json)

    # 从增强数据提取折分（确保与 VulnSC 一致）
    fold_indices = None
    if enhance_dir:
        try:
            fold_indices = loader.extract_fold_indices_from_enhanced(
                enhance_dir, model=enhance_model
            )
            print(f"  [控制变量] 已加载 VulnSC 4 折划分")
        except Exception as e:
            print(f"  [Warning] 折分提取失败: {e}，使用随机 4 折")

    loader.load(fold_indices=fold_indices)

    # 如果提供了增强代码，加载 func_en
    if use_enhanced and enhance_dir:
        loader.load_enhanced(enhance_dir, model=enhance_model, fold=fold)

    # 获取指定折的测试集
    test_samples = loader.get_fold(fold=fold, split="test")
    print(f"  Test set: {len(test_samples)} 样本 (fold={fold})")

    if max_samples > 0:
        # 尽量保持正负样本比例
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
    print(f"\n[Step 2/6] 准备样本文件")
    processor = DevignBatchProcessor(output_dir=output_dir)
    metadata_list = processor.prepare_samples(test_samples, use_enhanced=use_enhanced)

    # ---- Step 3: 初始化 LLM ----
    print(f"\n[Step 3/6] 初始化 LLM 客户端")
    llm_client = create_client()

    # ---- Step 4: 恢复已有结果（支持断点续评） ----
    existing_results = processor.load_results() if resume else []
    completed_indices = {r.get("idx") for r in existing_results}
    print(f"  已有结果: {len(completed_indices)} 个样本")

    # ---- Step 5: 逐样本评测 ----
    print(f"\n[Step 4/6] 运行 HGL-Vul 漏洞检测")
    print(f"  {'='*50}")

    results = list(existing_results)
    pending = [m for m in metadata_list if m["idx"] not in completed_indices]
    print(f"  待评测: {len(pending)} 个样本")

    if not pending:
        print("  全部已完成，跳过评测。")
    else:
        start_time = time.time()
        for i, meta in enumerate(pending):
            idx = meta["idx"]
            file_path = meta["file_path"]
            target = meta["target"]
            sample_id = meta["sample_id"]

            print(f"\n  [{i+1}/{len(pending)}] idx={idx}, "
                  f"target={'VUL' if target else 'BEN'}, "
                  f"project={meta['project']}")

            sample_start = time.time()
            result = {
                "idx": idx,
                "sample_id": sample_id,
                "target": target,
                "fold": meta["fold"],
                "project": meta["project"],
                "commit_id": meta["commit_id"],
                "use_enhanced": use_enhanced,
                "hop_count": 0,
                "error": None,
                "prediction": 0,
            }

            try:
                # Phase 1: CPG 构建
                sample_dir = os.path.join(output_dir, "cpg", sample_id)
                os.makedirs(sample_dir, exist_ok=True)

                try:
                    export_dir = build_cpg(file_path, sample_dir)
                    nodes_file, edges_file = find_export_files(export_dir)
                except Exception:
                    # 回退：尝试已有文件
                    nodes_file = os.path.join(sample_dir, "nodes.json")
                    edges_file = os.path.join(sample_dir, "edges.json")
                    if not os.path.exists(nodes_file) or not os.path.exists(edges_file):
                        raise

                # Phase 2: 图加载
                G = load_graph(nodes_file, edges_file)

                # Phase 3: 图压缩
                SG = summarize_graph(G, token_budget=token_budget)
                reduction_stats = SG.graph.get("reduction_stats", {})
                result["orig_nodes"] = reduction_stats.get("orig_nodes", G.number_of_nodes())
                result["compressed_nodes"] = reduction_stats.get("compressed_nodes", SG.number_of_nodes())
                result["node_reduction_pct"] = reduction_stats.get("node_reduction_pct", 0)

                # Phase 4: 路径检索
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    code = f.read()

                candidate_paths = extract_all_candidate_paths(SG, source_code=code)
                if not candidate_paths:
                    candidate_paths = extract_all_candidate_paths(G, source_code=code)
                topk_paths = retrieve_topk(SG if candidate_paths else G, candidate_paths)

                # Phase 5: 层次化线性化
                func_summary = summarize_function(code)
                api_hints = extract_api_hints(code)
                blocks = code.split("\n\n")
                block_summaries = {}
                for j, block in enumerate(blocks):
                    if block.strip():
                        block_summaries[j] = summarize_block(block) or block.strip()[:80]

                # Phase 6: 受限推理循环
                reasoning_result = reasoning_loop(
                    SG, topk_paths, code, func_summary, block_summaries,
                    client=llm_client,
                )
                llm_prediction = 1 if reasoning_result.get("vulnerability_type", "Unknown") != "Unknown" else 0
                result["prediction"] = llm_prediction
                result["vulnerability_type"] = reasoning_result.get("vulnerability_type", "Unknown")
                result["reasoning_steps"] = reasoning_result.get("steps", 0)
                result["error"] = None

            except Exception as e:
                print(f"    [Error] {e}")
                result["prediction"] = 0
                result["error"] = str(e)

            # 记录
            is_correct = result.get("prediction") == target
            elapsed = time.time() - sample_start
            print(f"    --> prediction={result['prediction']}, "
                  f"correct={'✓' if is_correct else '✗'}, "
                  f"time={elapsed:.1f}s")

            # 增量保存
            results.append(result)
            processor.save_intermediate(result)

        total_time = time.time() - start_time
        print(f"\n  评测完成: {len(pending)} 样本, 耗时 {total_time:.1f}s "
              f"({total_time/60:.1f}min)")

    # ---- Step 6: 计算指标 ----
    print(f"\n[Step 5/6] 计算评测指标")

    # 过滤有结果的样本
    valid_results = [r for r in results if r.get("prediction") is not None]
    y_true = [r["target"] for r in valid_results]
    y_pred = [r["prediction"] for r in valid_results]

    # 计算指标
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, matthews_corrcoef
    metrics = {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "mcc": matthews_corrcoef(y_true, y_pred),
        "total_samples": len(valid_results),
        "vulnerable": sum(y_true),
        "benign": len(y_true) - sum(y_true),
    }

    # 按项目分层
    from collections import defaultdict
    project_metrics = defaultdict(list)
    for r in valid_results:
        project_metrics[r.get("project", "unknown")].append(r)

    print(f"\n  {'='*50}")
    print(f"  HGL-Vul on Devign (Fold {fold}) — Results")
    print(f"  {'='*50}")
    print(f"  Accuracy:  {metrics['accuracy']:.4f}  ({metrics['accuracy']*100:.2f}%)")
    print(f"  Precision: {metrics['precision']:.4f}  ({metrics['precision']*100:.2f}%)")
    print(f"  Recall:    {metrics['recall']:.4f}  ({metrics['recall']*100:.2f}%)")
    print(f"  F1-Score:  {metrics['f1']:.4f}  ({metrics['f1']*100:.2f}%)")
    print(f"  MCC:       {metrics['mcc']:.4f}")
    print(f"  Samples:   {metrics['total_samples']} "
          f"(vuln={metrics['vulnerable']}, benign={metrics['benign']})")
    print(f"  {'='*50}")

    # 保存全部结果
    final_output = {
        "config": {
            "mode": "evaluate-devign",
            "devign_json": devign_json,
            "enhance_dir": enhance_dir,
            "fold": fold,
            "max_samples": max_samples,
            "token_budget": token_budget,
            "use_enhanced": use_enhanced,
            "enhance_model": enhance_model,
            "llm_model": LLM_MODEL,
            "temperature": 0.0,
            "seed": SEED,
        },
        "metrics": metrics,
        "project_breakdown": {
            proj: {
                "count": len(samples),
                "accuracy": accuracy_score(
                    [r["target"] for r in samples],
                    [r["prediction"] for r in samples]
                ),
                "vuln": sum(1 for r in samples if r["target"] == 1),
            }
            for proj, samples in sorted(project_metrics.items())
        },
        "results": valid_results,
    }

    output_path = os.path.join(output_dir, "devign_evaluation_results.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(final_output, f, indent=2, ensure_ascii=False)
    print(f"\n[Saved] {output_path}")

    # 与 VulnSC Table4 对比摘要
    print(f"\n[对比] 与 VulnSC Table4 基线对比 (Devign Acc%)")
    print(f"  {'Method':<30} {'Acc%':>8}")
    print(f"  {'-'*40}")
    print(f"  {'HGL-Vul (Ours)':<30} {metrics['accuracy']*100:>8.2f}")
    print(f"  {'CodeBERT (original)':<30} {'58.16':>8}")
    print(f"  {'GraphCodeBERT (original)':<30} {'58.86':>8}")
    print(f"  {'UniXcoder (original)':<30} {'60.57':>8}")
    print(f"  {'LineVul (original)':<30} {'61.48':>8}")
    print(f"  {'VulnSC-CodeBERT (best)':<30} {'62.89':>8}")
    print(f"  {'VulnSC-GraphCodeBERT (best)':<30} {'62.69':>8}")
    print(f"  {'VulnSC-UniXcoder (best)':<30} {'63.85':>8}")
    print(f"  {'VulnSC-LineVul (best)':<30} {'63.54':>8}")
    print(f"  {'GRACE':<30} {'59.78':>8}")
    print(f"  {'LLM4Vuln (GPT-4 raw)':<30} {'52.37':>8}")
    print(f"  {'Avishree (GPT-4 basic)':<30} {'52.22':>8}")

    return final_output