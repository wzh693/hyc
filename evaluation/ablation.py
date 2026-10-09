"""
消融实验框架 (Ablation Study Framework)。

用于量化 HGL-Vul 各核心模块的独立贡献。
每个消融配置关掉一个核心模块，观察性能变化。

消融配置：
  - full:         完整 HGL-Vul 系统（基准）
  - no_graph_sum: 跳过图压缩，使用原始 CPG
  - no_hier_lin:  跳过层次化线性化，使用扁平路径表示
  - no_prog_state:移除程序状态记忆，LLM 无状态推理
  - no_adapt_plan:固定调度顺序，移除自适应检索规划
  - no_constr_reason:跳过受限推理循环，直接单次 LLM 判断
"""

import os
import sys
import json
import time
import copy
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from graph.build_cpg import build_cpg, find_export_files
from graph.load_graph import load_graph
from graph.summarize_graph import summarize_graph, estimate_token_usage
from retrieval.candidate_paths import extract_all_candidate_paths
from retrieval.retrieve_topk import retrieve_topk
from linearization.function_summary import summarize_function
from linearization.block_summary import summarize_block
from linearization.typed_paths import typed_dependency_path, build_hierarchical_context, extract_api_hints
from reasoning.llm_api import create_client
from reasoning.reasoning_loop import run_vuln_detection, reasoning_loop, parse_binary_verdict
from reasoning.prompts import build_prompt_vuln_check_flat
from evaluation.metrics import compute_metrics, compute_long_range_metrics


# ===========================================================================
# 消融配置
# ===========================================================================

ABLATION_CONFIGS = {
    "full": {
        "name": "Full HGL-Vul",
        "use_graph_sum": True,
        "use_hier_lin": True,
        "use_prog_state": True,
        "use_adapt_plan": True,
        "use_constr_reason": True,
        "description": "完整系统（基准）",
    },
    "no_graph_sum": {
        "name": "w/o Graph Summarization",
        "use_graph_sum": False,
        "use_hier_lin": True,
        "use_prog_state": True,
        "use_adapt_plan": True,
        "use_constr_reason": True,
        "description": "跳过图压缩，使用原始 CPG",
    },
    "no_hier_lin": {
        "name": "w/o Hierarchical Linearization",
        "use_graph_sum": True,
        "use_hier_lin": False,
        "use_prog_state": True,
        "use_adapt_plan": True,
        "use_constr_reason": True,
        "description": "用扁平路径表示替代层次化线性化",
    },
    "no_prog_state": {
        "name": "w/o Program State Memory",
        "use_graph_sum": True,
        "use_hier_lin": True,
        "use_prog_state": False,
        "use_adapt_plan": True,
        "use_constr_reason": True,
        "description": "移除程序状态记忆模块",
    },
    "no_adapt_plan": {
        "name": "w/o Adaptive Planning",
        "use_graph_sum": True,
        "use_hier_lin": True,
        "use_prog_state": True,
        "use_adapt_plan": False,
        "use_constr_reason": True,
        "description": "固定调度顺序：CFG→DFG→CALL",
    },
    "no_constr_reason": {
        "name": "w/o Constrained Reasoning",
        "use_graph_sum": True,
        "use_hier_lin": True,
        "use_prog_state": True,
        "use_adapt_plan": True,
        "use_constr_reason": False,
        "description": "跳过受限推理循环，单次 LLM 判断",
    },
}


for _name in ('no_slice', 'no_output_contract', 'no_expansion', 'no_safety_net', 'no_topk', 'single_step'):
    ABLATION_CONFIGS[_name] = dict(ABLATION_CONFIGS['full'], name=_name,
                                  description='Single-module removal from the configured production profile',
                                  pipeline_ablation=_name)


def _process_sample(
    sample: dict,
    config: dict,
    llm_client,
    model: str,
    output_dir: str,
) -> dict:
    """
    在给定消融配置下处理单个样本。
    返回该样本的评测结果。
    """
    code = sample["code"]
    label = sample["label"]
    sample_id = sample["id"]
    hop_count = sample.get("hop_count", 0)
    vul_type = sample.get("vul_type", "unknown")

    result = {
        "sample_id": sample_id,
        "label": label,
        "hop_count": hop_count,
        "vul_type": vul_type,
    }

    # === Phase 1: CPG 构建 ===
    sample_dir = os.path.join(output_dir, f"sample_{sample_id}")
    os.makedirs(sample_dir, exist_ok=True)
    code_path = os.path.join(sample_dir, "source.c")
    with open(code_path, "w", encoding="utf-8") as f:
        f.write(code)

    try:
        if config['use_constr_reason']:
            from graph.pipeline import run_hgl_pipeline
            ablation = config.get('pipeline_ablation', '')
            if not ablation:
                ablation = next((name for key, name in (
                    ('use_graph_sum', 'no_compression'), ('use_hier_lin', 'no_hier_lin'),
                    ('use_prog_state', 'no_state'), ('use_adapt_plan', 'no_planning'))
                    if not config[key]), '')
            details = run_hgl_pipeline(code_path, code, sample_id, sample_dir, llm_client,
                                       ablation=ablation, return_details=True)
            result.update(details)
            result['node_reduction_pct'] = details['reduction_stats'].get('node_reduction_pct', 0)
            result['error'] = None
            return result
        export_dir = build_cpg(code_path, sample_dir)
        nodes_file, edges_file = find_export_files(export_dir)
    except Exception as e:
        result["prediction"] = None
        result["error"] = f"CPG构建失败: {e}"
        return result

    if not os.path.exists(nodes_file):
        result["prediction"] = None
        result["error"] = f"nodes.json 不存在"
        return result

    # === Phase 2: 图加载 ===
    G = load_graph(nodes_file, edges_file)

    # === Phase 3: 图压缩（可消融）===
    if config["use_graph_sum"]:
        SG = summarize_graph(G, verbose=False)
    else:
        SG = G  # 跳过压缩，使用原始 CPG

    result["orig_nodes"] = G.number_of_nodes()
    result["compressed_nodes"] = SG.number_of_nodes()
    result["node_reduction_pct"] = SG.graph.get("reduction_stats", {}).get(
        "node_reduction_pct", 0
    )

    # === Phase 4-6: 路径检索 + 线性化 + 推理 ===
    # 候选路径（所有消融配置共用，避免重复计算）
    try:
        candidate_paths = extract_all_candidate_paths(SG, source_code=code)
        path_graph = SG
        if not candidate_paths:
            candidate_paths = extract_all_candidate_paths(G, source_code=code)
            path_graph = G
        topk_paths = retrieve_topk(path_graph, candidate_paths)

        func_summary = summarize_function(code)
        blocks = code.split("\n\n")
        block_summ = {}
        for i, block in enumerate(blocks):
            if block.strip():
                block_summ[i] = summarize_block(block)

        if config["use_constr_reason"]:
            # 受限推理循环（full / no_graph_sum / no_hier_lin /
            # no_prog_state / no_adapt_plan 都走此分支，由开关区分）
            reasoning_result = reasoning_loop(
                path_graph, topk_paths, code, func_summary, block_summ,
                client=llm_client,
                use_prog_state=config["use_prog_state"],
                use_adapt_plan=config["use_adapt_plan"],
                use_hier_lin=config["use_hier_lin"],
            )
            llm_prediction = 1 if reasoning_result.get(
                "vulnerability_type", "Unknown"
            ) != "Unknown" else 0
        else:
            # 消融 no_constr_reason：跳过受限推理循环，直接单次 LLM 判断。
            # 与 no_hier_lin 的区别：no_hier_lin 仍走多步受限推理循环
            # （仅把层次化上下文换成扁平路径），no_constr_reason 完全
            # 不走推理循环，只用扁平路径 + 单次 LLM 调用。
            flat_context = ""
            for path in topk_paths[:10]:
                segs = []
                for nid in path:
                    segs.append(G.nodes[nid].get("code", ""))
                flat_context += " -> ".join(segs) + "\n"

            prompt = build_prompt_vuln_check_flat(flat_context)
            response = llm_client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=64,
            )
            answer = response.choices[0].message.content.strip().lower()
            llm_prediction = parse_binary_verdict(answer)
            if llm_prediction is None:
                raise ValueError(f"Ambiguous verdict: {answer[:120]!r}")

        result["prediction"] = llm_prediction
        result["error"] = None

    except Exception as e:
        result["prediction"] = None
        result["error"] = str(e)

    return result


def run_ablation_study(
    dataset: list,
    output_dir: str,
    configs: list = None,
    llm_client=None,
    model: str = "gpt-4o",
    max_samples: int = 50,
) -> dict:
    """
    运行消融实验。

    参数:
        dataset: 样本列表（每个样本包含 code, label, hop_count, vul_type）
        output_dir: 输出目录
        configs: 要运行的消融配置列表（默认全部运行）
        llm_client: LLM 客户端实例
        model: 模型名称
        max_samples: 每种配置最多处理的样本数

    返回:
        results: {
            "full": {"metrics": {...}, "samples": [...]},
            "no_graph_sum": {"metrics": {...}, "samples": [...]},
            ...
        }
    """
    if configs is None:
        configs = list(ABLATION_CONFIGS.keys())

    if llm_client is None:
        llm_client = create_client()

    results = {}
    samples = dataset[:max_samples]

    for config_key in configs:
        if config_key not in ABLATION_CONFIGS:
            print(f"[Ablation] 未知配置: {config_key}，跳过")
            continue

        config = ABLATION_CONFIGS[config_key]
        config_dir = os.path.join(output_dir, config_key)
        os.makedirs(config_dir, exist_ok=True)

        print(f"\n{'='*60}")
        print(f"  消融实验: {config['name']}")
        print(f"  说明: {config['description']}")
        print(f"{'='*60}")

        sample_results = []
        for i, sample in enumerate(samples):
            print(f"  [{i+1}/{len(samples)}] sample_id={sample['id']}...", end=" ")
            try:
                sr = _process_sample(sample, config, llm_client, model, config_dir)
                sample_results.append(sr)
                status = "✓" if sr.get("prediction") == sr.get("label") else "✗"
                err = f" ({sr.get('error')})" if sr.get("error") else ""
                print(f"{status}{err}")
            except Exception as e:
                print(f"✗ 异常: {e}")
                sample_results.append({
                    "sample_id": sample["id"],
                    "label": sample["label"],
                    "prediction": None,
                    "error": str(e),
                })

        # 计算指标
        metrics = compute_long_range_metrics(sample_results)
        from evaluation.metrics import compute_token_efficiency
        token_metrics = compute_token_efficiency(sample_results)
        hop_split = {}
        for split_name in ["short", "medium", "long", "very_long"]:
            split_samples = [r for r in sample_results
                             if r.get("hop_count", 0) in range(
                                 {"short": (1, 2), "medium": (3, 4),
                                  "long": (5, 7), "very_long": (8, 100)}[split_name][0],
                                 {"short": (1, 2), "medium": (3, 4),
                                  "long": (5, 7), "very_long": (8, 100)}[split_name][1] + 1)]
            if split_samples:
                hop_split[split_name] = compute_metrics(
                    [r["label"] for r in split_samples],
                    [r["prediction"] for r in split_samples],
                )

        results[config_key] = {
            "config": config,
            "metrics": metrics,
            "token_metrics": token_metrics,
            "hop_split_metrics": hop_split,
            "samples": sample_results,
            "n_samples": len(sample_results),
            "n_correct": sum(1 for r in sample_results if r.get("prediction") == r.get("label")),
        }

        # 保存中间结果
        result_path = os.path.join(config_dir, "ablation_results.json")
        with open(result_path, "w", encoding="utf-8") as f:
            json.dump({
                "config": config,
                "metrics": {k: {kk: vv for kk, vv in v.items() if isinstance(vv, (int, float))}
                           for k, v in metrics.items()},
                "sample_results": sample_results,
            }, f, indent=2, ensure_ascii=False)
        print(f"  [Saved] {result_path}")

    return results


def generate_ablation_report(results: dict) -> str:
    """
    生成消融实验报告（Markdown 格式）。
    适用于论文中的 Ablation Study 表格。
    """
    lines = []
    lines.append("=" * 70)
    lines.append("ABLATION STUDY REPORT")
    lines.append("=" * 70)

    lines.append('\nF1/Accuracy below count abstentions as errors; Precision/Recall are on valid predictions.')
    # 表头
    lines.append(f"\n{'Configuration':<30} {'F1':<10} {'Precision':<12} {'Recall':<10} {'Accuracy':<10} {'Correct':<10}")
    lines.append(f"{'-'*30} {'-'*10} {'-'*12} {'-'*10} {'-'*10} {'-'*10}")

    base_f1 = None
    for config_key in ABLATION_CONFIGS:
        if config_key not in results:
            continue
        r = results[config_key]
        overall = r["metrics"].get("overall", {})
        f1 = overall.get("f1_conservative", overall.get("f1", 0))
        if base_f1 is None:
            base_f1 = f1

        delta = f1 - base_f1 if base_f1 else 0
        delta_str = f" ({delta:+.2f})" if abs(delta) > 0.001 else ""

        lines.append(
            f"  {ABLATION_CONFIGS[config_key]['name']:<30} "
            f"{f1:<10.4f}{delta_str:<12} "
            f"{overall.get('precision', 0):<12.4f} "
            f"{overall.get('recall', 0):<10.4f} "
            f"{overall.get('accuracy_all', overall.get('accuracy', 0)):<10.4f} "
            f"{r['n_correct']}/{r['n_samples']:<5}"
        )

    # 跳数分层对比
    lines.append("\n\n[Per-Hop F1 Comparison]")
    lines.append(f"\n{'Configuration':<30} {'Short(1-2)':<12} {'Medium(3-4)':<12} {'Long(5-7)':<12} {'V.Long(8+)':<12}")
    lines.append(f"{'-'*30} {'-'*12} {'-'*12} {'-'*12} {'-'*12}")

    for config_key in ABLATION_CONFIGS:
        if config_key not in results:
            continue
        r = results[config_key]
        parts = []
        for split_name in ["short", "medium", "long", "very_long"]:
            m = r.get("hop_split_metrics", {}).get(split_name, {})
            parts.append(f"{m.get('f1_conservative', m.get('f1', 0)):.4f}")
        lines.append(
            f"  {ABLATION_CONFIGS[config_key]['name']:<30} "
            f"{parts[0]:<12} {parts[1]:<12} {parts[2]:<12} {parts[3]:<12}"
        )

    # Token 缩减率对比
    lines.append("\n\n[Code Reduction Comparison]")
    lines.append(f"\n{'Configuration':<30} {'Node Red.%':<12}")
    lines.append(f"{'-'*30} {'-'*12}")

    for config_key in ABLATION_CONFIGS:
        if config_key not in results:
            continue
        r = results[config_key]
        avg_reduction = 0
        samples_with_reduction = 0
        for s in r.get("samples", []):
            if "node_reduction_pct" in s:
                avg_reduction += s["node_reduction_pct"]
                samples_with_reduction += 1
        avg = avg_reduction / samples_with_reduction if samples_with_reduction else 0
        lines.append(
            f"  {ABLATION_CONFIGS[config_key]['name']:<30} "
            f"{avg:<12.1f}%"
        )

    lines.append("\n" + "=" * 70)
    return "\n".join(lines)
