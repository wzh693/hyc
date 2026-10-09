"""
直接 LLM vs HGL-Vul 对比评测。

核心实验：验证 HGL-Vul 框架在以下方面的提升：
  1. 准确率（尤其是长距离漏洞）
  2. Token 效率（大代码上 HGL-Vul 的压缩优势）
  3. 跨跳数分层性能

运行方式:
  # 合成数据集（小规模）
  python -m evaluation.compare_direct_vs_hgl [num_samples]

  # 跨函数 CVE 数据集（大规模，体现压缩优势）
  python -m evaluation.compare_direct_vs_hgl --cross-func <dataset_dir> [max_samples]
"""

import os
import sys
import json
import time
import argparse
import shutil
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config import (
    LLM_API_KEY, LLM_BASE_URL, LLM_MODEL, TOP_K_PATHS,
    SYNTHETIC_DIR, SYNTHETIC_CONFIG,
)
from reasoning.reasoning_loop import parse_binary_verdict

DEFAULT_TOKEN_BUDGET = 4096
MAX_DIRECT_CODE_CHARS = 0  # 0 = 不截断，让 Direct LLM 看到全部代码

DIRECT_SYSTEM_PROMPT = """You are a C/C++ vulnerability detection expert.
Analyze the given source code and determine if it contains a security vulnerability.

Vulnerability types: Use-After-Free, Double Free, Buffer Overflow, Taint-style,
Memory Leak, Null Pointer Dereference.

Output format:
VULNERABILITY: <yes/no>
TYPE: <vulnerability type, or NONE>
REASONING: <brief explanation>
"""

HGL_SYSTEM_PROMPT = """You are a C/C++ vulnerability detection expert.
Analyze the hierarchical dependency context (derived from a Code Property Graph) 
and determine if the code contains a security vulnerability.

Vulnerability types: Use-After-Free, Double Free, Buffer Overflow, Taint-style,
Memory Leak, Null Pointer Dereference.

Output format:
VULNERABILITY: <yes/no>
TYPE: <vulnerability type, or NONE>
REASONING: <brief explanation>
"""


def run_direct_llm(code: str, client, model: str) -> dict:
    """模式A：直接将源代码发给 LLM 做漏洞检测。"""
    # 超过上限的代码截断并警告（0 表示不截断）
    truncated = False
    if MAX_DIRECT_CODE_CHARS > 0 and len(code) > MAX_DIRECT_CODE_CHARS:
        code = code[:MAX_DIRECT_CODE_CHARS] + "\n// ... [CODE TRUNCATED]"
        truncated = True

    prompt = f"""## Source Code
```c
{code}
```

Analyze the above C code for vulnerabilities. Respond in this format:
VULNERABILITY: <yes/no>
TYPE: <type or NONE>
REASONING: <explanation>
"""
    t0 = time.time()
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": DIRECT_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
            max_tokens=512,
        )
        output = response.choices[0].message.content
        tokens = response.usage.total_tokens if response.usage else 0
        elapsed = time.time() - t0
    except Exception as e:
        return {
            "error": str(e), "prediction": None, "tokens": 0,
            "time_s": 0, "output": "", "truncated": False,
        }

    pred = parse_binary_verdict(output)
    error = None if pred is not None else "Ambiguous LLM verdict"
    return {
        "prediction": pred,
        "tokens": tokens,
        "time_s": round(elapsed, 2),
        "output": output[:500],
        "error": error,
        "truncated": truncated,
    }


def run_hgl_pipeline_cross_func(
    code: str, sample, client, model: str,
    token_budget: int = DEFAULT_TOKEN_BUDGET, verbose: bool = True,
) -> dict:
    """
    跨函数 CVE 数据集专用 HGL-Vul 管线。

    与普通管线 (run_hgl_pipeline) 的关键区别：
      - 仍然通过 Joern 构建 CPG（保留完整的 REACHING_DEF/CFG/DOMINATE 图结构）
      - 但在候选路径提取阶段使用两阶段匹配：
        阶段1: 从原始 C 源码中正则提取 API 调用名 (malloc/free/strcpy...)
        阶段2: 将提取的 API 名映射到 Joern DOT 的 POST_DOMINATE/BINDS 节点
      - 解决了 Joern 4.x DOT 节点不直接携带 API 名称的问题
    """
    import tempfile
    from graph.build_cpg import build_cpg, find_export_files
    from graph.load_graph import load_graph
    from graph.summarize_graph import summarize_graph
    from retrieval.candidate_paths import extract_all_candidate_paths
    from linearization.function_summary import summarize_function
    from linearization.block_summary import summarize_block
    from linearization.typed_paths import (
        typed_dependency_path, build_hierarchical_context, select_vuln_aware_topk, extract_api_hints
    )
    from planning.state_memory import ProgramState

    tmpdir = tempfile.mkdtemp()
    code_path = os.path.join(tmpdir, "source.c")
    with open(code_path, "w", encoding="utf-8") as f:
        f.write(code)

    t0 = time.time()
    timings = {}

    try:
        # P1: Joern CPG 构建
        t1 = time.time()
        export_dir = build_cpg(code_path, tmpdir)
        nodes_file, edges_file = find_export_files(export_dir)
        G = load_graph(nodes_file, edges_file)
        timings["cpg_build"] = round(time.time() - t1, 3)

        # P2: 漏洞相关图压缩
        t2 = time.time()
        SG = summarize_graph(G, token_budget=token_budget, source_code=code, verbose=False)
        timings["summarize"] = round(time.time() - t2, 3)
        reduction = SG.graph.get("reduction_stats", {})

        # P3: 候选路径提取（两阶段：源码API提取 → DOT节点映射）
        t3 = time.time()
        candidate_paths = extract_all_candidate_paths(
            G, source_code=code, verbose=verbose
        )
        timings["retrieve"] = round(time.time() - t3, 3)

        # 从源码提取安全 API 分类（用于路径级标注，弥补 DOT 不保留 API 名的问题）
        from retrieval.candidate_paths import _extract_api_calls_from_source
        from config import DANGEROUS_APIS, TAINT_SOURCES
        src_apis = _extract_api_calls_from_source(code)
        sink_apis = DANGEROUS_APIS & src_apis
        source_apis = TAINT_SOURCES & src_apis
        alloc_apis = {"malloc", "calloc", "realloc", "alloca", "mmap",
                      "av_malloc", "av_calloc", "av_realloc", "av_mallocz",
                      "kmalloc", "kzalloc", "kcalloc"} & src_apis
        free_apis = {"free", "munmap", "av_free", "av_freep", "kfree"} & src_apis
        api_hints = {
            "sink_apis": sink_apis, "source_apis": source_apis,
            "alloc_apis": alloc_apis, "free_apis": free_apis,
        }

        # P4: 漏洞感知路径选择 + 层次化线性化
        t4 = time.time()
        path_graph = G
        vuln_topk = select_vuln_aware_topk(path_graph, candidate_paths, k=10)
        if not vuln_topk:
            from retrieval.retrieve_topk import retrieve_topk
            vuln_topk = retrieve_topk(path_graph, candidate_paths)

        func_summary = summarize_function(code)
        blocks = code.split("\n\n")
        block_summaries = {}
        for j, block in enumerate(blocks[:20]):
            if block.strip():
                summary = summarize_block(block)
                if summary:
                    block_summaries[j] = summary

        paths_context = []
        for path in (vuln_topk[:5] or []):
            ps = typed_dependency_path(path_graph, path, api_hints=api_hints)
            if ps:
                paths_context.append(ps)

        state = ProgramState()
        state.track_vars(code)
        state_str = state.serialize()

        hierarchical_context = build_hierarchical_context(
            func_summary, block_summaries, paths_context, state_str,
            api_hints=api_hints,
        )
        timings["linearize"] = round(time.time() - t4, 3)

        # P5: LLM 推理
        t5 = time.time()
        vuln_prompt = f"""### Hierarchical Dependency Context
{hierarchical_context}

Analyze the above dependency context for vulnerabilities. Respond in this format:
VULNERABILITY: <yes/no>
TYPE: <type or NONE>
REASONING: <explanation>
"""
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": HGL_SYSTEM_PROMPT},
                {"role": "user", "content": vuln_prompt},
            ],
            temperature=0.0,
            max_tokens=512,
        )
        llm_output = response.choices[0].message.content.strip().lower()
        api_tokens = response.usage.total_tokens if response.usage else 0
        timings["llm"] = round(time.time() - t5, 3)

        pred = parse_binary_verdict(llm_output)
        if pred is None:
            raise ValueError(f"Ambiguous LLM verdict: {llm_output[:120]!r}")

        return {
            "prediction": pred,
            "time_s": round(time.time() - t0, 3),
            "timings": timings,
            "orig_nodes": G.number_of_nodes(),
            "comp_nodes": SG.number_of_nodes(),
            "node_reduction_pct": reduction.get("node_reduction_pct", 0),
            "edge_reduction_pct": reduction.get("edge_reduction_pct", 0),
            "num_candidates": len(candidate_paths),
            "num_topk": len(vuln_topk),
            "context_chars": len(hierarchical_context),
            "llm_tokens": api_tokens,
            "error": None,
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        return {
            "prediction": None, "time_s": 0, "timings": timings,
            "llm_tokens": 0, "context_chars": 0, "error": str(e),
        }
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def run_hgl_pipeline(
    code: str, client, model: str,
    token_budget: int = DEFAULT_TOKEN_BUDGET,
) -> dict:
    """合成数据使用与跨函数评测一致的完整 HGL 管线。"""
    return run_hgl_pipeline_cross_func(
        code, sample=None, client=client, model=model,
        token_budget=token_budget, verbose=False,
    )


def run_comparison(
    num_samples: int = 30,
    output_dir: Optional[str] = None,
    hop_splits: Optional[list] = None,
) -> dict:
    """
    运行完整对比实验。

    参数:
        num_samples: 样本数
        output_dir: 输出目录
        hop_splits: 要测试的跳数范围列表 [(min, max), ...]，None 表示不限制
    返回:
        对比结果字典
    """
    from openai import OpenAI
    from data.synthetic_generator import SyntheticDatasetGenerator

    if output_dir is None:
        output_dir = os.path.join("output", "direct_vs_hgl_comparison")
    os.makedirs(output_dir, exist_ok=True)

    print("=" * 70)
    print("  Direct LLM vs HGL-Vul Pipeline Comparison")
    print("=" * 70)
    print(f"  Samples: {num_samples}")
    print(f"  Model: {LLM_MODEL}")
    print(f"  Token Budget (HGL-Vul): {DEFAULT_TOKEN_BUDGET}")

    # 生成样本
    print("\n[Loading] 生成合成数据集...")
    generator = SyntheticDatasetGenerator()
    all_samples = generator.generate()

    # 按跳数分层采样
    samples_by_hop = {"short": [], "medium": [], "long": [], "very_long": []}
    for s in all_samples:
        hop = s.get("hop_count", 0)
        if 1 <= hop <= 2:
            samples_by_hop["short"].append(s)
        elif 3 <= hop <= 4:
            samples_by_hop["medium"].append(s)
        elif 5 <= hop <= 7:
            samples_by_hop["long"].append(s)
        elif hop >= 8:
            samples_by_hop["very_long"].append(s)

    # 等比例采样
    per_split = max(1, num_samples // 4)
    selected = []
    for split_name in ["short", "medium", "long", "very_long"]:
        pool = samples_by_hop[split_name]
        selected.extend(pool[:per_split])
    selected = selected[:num_samples]

    print(f"  Selected: {len(selected)} samples "
          f"(short={len(samples_by_hop['short'][:per_split])}, "
          f"medium={len(samples_by_hop['medium'][:per_split])}, "
          f"long={len(samples_by_hop['long'][:per_split])}, "
          f"very_long={len(samples_by_hop['very_long'][:per_split])})")

    # 初始化 LLM 客户端
    client = OpenAI(api_key=LLM_API_KEY, base_url=LLM_BASE_URL)

    # 逐样本对比
    results = []
    direct_correct = 0
    hgl_correct = 0
    direct_tokens_total = 0
    hgl_tokens_total = 0

    for i, sample in enumerate(selected):
        code = sample["code"]
        label = sample["label"]
        sid = sample["id"]
        hops = sample.get("hop_count", 0)
        vul_type = sample.get("vul_type", "unknown")

        print(f"\n{'='*70}")
        print(f"  [{i+1}/{len(selected)}] ID={sid}, hops={hops}, "
              f"type={vul_type}, label={'VUL' if label else 'BEN'}")
        print(f"  Code length: {len(code)} chars")
        print(f"{'='*70}")

        row = {
            "sample_id": sid,
            "label": label,
            "hop_count": hops,
            "vul_type": vul_type,
            "code_length": len(code),
        }

        # ── 模式A：Direct LLM ──
        print("  [Direct LLM] 推理中...")
        direct_result = run_direct_llm(code, client, LLM_MODEL)
        row["direct"] = direct_result
        direct_tokens_total += direct_result.get("tokens", 0)
        if direct_result.get("prediction") == label:
            direct_correct += 1
        print(f"  [Direct LLM] pred={direct_result.get('prediction')}, "
              f"tokens={direct_result.get('tokens')}, "
              f"correct={'✓' if direct_result.get('prediction') == label else '✗'} "
              f"({direct_result['time_s']:.1f}s)")

        # ── 模式B：HGL-Vul Pipeline ──
        print("  [HGL-Vul] Pipeline 处理中...")
        hgl_result = run_hgl_pipeline(code, client, LLM_MODEL, DEFAULT_TOKEN_BUDGET)
        row["hgl"] = hgl_result
        # HGL-Vul 使用 API 真实 token 消耗
        hgl_tokens = hgl_result.get("llm_tokens", 0)
        hgl_tokens_total += hgl_tokens
        if hgl_result.get("prediction") == label:
            hgl_correct += 1
        timings = hgl_result.get("timings", {})
        print(f"  [HGL-Vul] pred={hgl_result.get('prediction')}, "
              f"nodes={hgl_result.get('orig_nodes', '?')}→{hgl_result.get('comp_nodes', '?')}, "
              f"ctx={hgl_result.get('context_chars', 0)}chars, "
              f"correct={'✓' if hgl_result.get('prediction') == label else '✗'} "
              f"({hgl_result['time_s']:.1f}s)")

        results.append(row)

    # ── 汇总报告 ──
    n = len(results)
    direct_n = sum(r["direct"].get("prediction") in (0, 1) for r in results)
    hgl_n = sum(r["hgl"].get("prediction") in (0, 1) for r in results)
    direct_acc = direct_correct / direct_n * 100 if direct_n else 0
    hgl_acc = hgl_correct / hgl_n * 100 if hgl_n else 0
    direct_avg_tokens = direct_tokens_total / direct_n if direct_n else 0
    hgl_avg_tokens = hgl_tokens_total / hgl_n if hgl_n else 0

    # 按跳数分层统计
    hop_results = {"short": [], "medium": [], "long": [], "very_long": []}
    for r in results:
        hop = r["hop_count"]
        if hop <= 2:
            hop_results["short"].append(r)
        elif hop <= 4:
            hop_results["medium"].append(r)
        elif hop <= 7:
            hop_results["long"].append(r)
        else:
            hop_results["very_long"].append(r)

    def calc_split_stats(rows):
        n_s = len(rows)
        if n_s == 0:
            return {"count": 0, "direct_acc": 0, "hgl_acc": 0}
        d_valid = [r for r in rows if r["direct"].get("prediction") in (0, 1)]
        h_valid = [r for r in rows if r["hgl"].get("prediction") in (0, 1)]
        d_corr = sum(1 for r in rows if r["direct"].get("prediction") == r["label"])
        h_corr = sum(1 for r in rows if r["hgl"].get("prediction") == r["label"])
        return {
            "count": n_s,
            "direct_valid": len(d_valid),
            "hgl_valid": len(h_valid),
            "direct_acc": round(d_corr / len(d_valid) * 100, 1) if d_valid else 0,
            "hgl_acc": round(h_corr / len(h_valid) * 100, 1) if h_valid else 0,
        }

    split_stats = {k: calc_split_stats(v) for k, v in hop_results.items()}

    # 生成报告
    report_lines = [
        "=" * 70,
        "  Direct LLM vs HGL-Vul Pipeline — Comparison Report",
        "=" * 70,
        f"",
        f"  Model: {LLM_MODEL}",
        f"  Samples: {n}",
        f"  HGL-Vul Token Budget: {DEFAULT_TOKEN_BUDGET}",
        f"",
        f"  ── Overall Accuracy ──",
        f"  Direct LLM (raw code):        {direct_correct}/{direct_n} = {direct_acc:.1f}% "
        f"({n-direct_n} errors)",
        f"  HGL-Vul Pipeline (structured): {hgl_correct}/{hgl_n} = {hgl_acc:.1f}% "
        f"({n-hgl_n} errors)",
        f"  Delta:                        {hgl_acc - direct_acc:+.1f}%",
        f"",
        f"  ── Token Efficiency ──",
        f"  Direct LLM avg tokens:   {direct_avg_tokens:.0f}",
        f"  HGL-Vul avg tokens (API): {hgl_avg_tokens:.0f}",
        f"  Token reduction:          {hgl_avg_tokens - direct_avg_tokens:+.0f} "
        f"({(1 - hgl_avg_tokens/max(direct_avg_tokens, 1)) * 100:.1f}%)",
        f"",
        f"  ── Hop-Stratified Accuracy ──",
        f"  {'Split':<12s} {'Count':>6s} {'Direct':>8s} {'HGL-Vul':>8s} {'Delta':>8s}",
        f"  {'-'*12} {'-'*6} {'-'*8} {'-'*8} {'-'*8}",
    ]

    for split_name in ["short", "medium", "long", "very_long"]:
        ss = split_stats[split_name]
        if ss["count"] > 0:
            delta = ss["hgl_acc"] - ss["direct_acc"]
            report_lines.append(
                f"  {split_name:<12s} {ss['count']:>5d}  "
                f"{ss['direct_acc']:>6.1f}% {ss['hgl_acc']:>6.1f}% {delta:>+7.1f}%"
            )
        else:
            report_lines.append(f"  {split_name:<12s} {0:>5d}  {'N/A':>7s} {'N/A':>7s}")

    report_lines.append(f"")
    report_lines.append(f"  ── HGL-Vul Pipeline Timing (avg) ──")
    avg_timings = {}
    for r in results:
        for k, v in r["hgl"].get("timings", {}).items():
            avg_timings[k] = avg_timings.get(k, 0) + v
    for k in avg_timings:
        avg_timings[k] = round(avg_timings[k] / max(n, 1), 3)
        report_lines.append(f"  {k:<15s}: {avg_timings[k]:.3f}s")
    report_lines.append(f"  {'total':<15s}: {avg_timings.get('cpg_build', 0) + avg_timings.get('summarize', 0) + avg_timings.get('retrieve', 0) + avg_timings.get('linearize', 0) + avg_timings.get('llm', 0):.3f}s")

    report_lines.append(f"")
    report_lines.append(f"  ── Per-Sample Details ──")
    for r in results:
        d_pred = r["direct"].get("prediction", "?")
        h_pred = r["hgl"].get("prediction", "?")
        label = r["label"]
        d_ok = "✓" if d_pred == label else "✗"
        h_ok = "✓" if h_pred == label else "✗"
        d_tok = r["direct"].get("tokens", 0)
        h_ctx = r["hgl"].get("context_chars", 0)
        h_tok = r["hgl"].get("llm_tokens", 0)
        n_reduction = r["hgl"].get("node_reduction_pct", 0)
        report_lines.append(
            f"  ID={r['sample_id']:>3d} hops={r['hop_count']:>2d} "
            f"label={label} direct={d_pred}({d_ok}) hgl={h_pred}({h_ok}) "
            f"| dtok={d_tok} htok={h_tok} ctx={h_ctx}c nred={n_reduction:.0f}%"
        )

    report = "\n".join(report_lines)
    print("\n" + report)

    # 保存
    report_path = os.path.join(output_dir, "comparison_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"\n[Saved] {report_path}")

    json_path = os.path.join(output_dir, "comparison_results.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "config": {
                "model": LLM_MODEL,
                "num_samples": n,
                "token_budget": DEFAULT_TOKEN_BUDGET,
            },
            "summary": {
                "direct_accuracy": round(direct_acc, 1),
                "hgl_accuracy": round(hgl_acc, 1),
                "delta": round(hgl_acc - direct_acc, 1),
                "direct_avg_tokens": round(direct_avg_tokens, 0),
                "hgl_avg_tokens_est": round(hgl_avg_tokens, 0),
                "hop_split_stats": split_stats,
            },
            "timings": avg_timings,
            "results": results,
        }, f, indent=2, ensure_ascii=False)
    print(f"[Saved] {json_path}")

    return {
        "config": {
            "model": LLM_MODEL,
            "num_samples": n,
            "token_budget": DEFAULT_TOKEN_BUDGET,
        },
        "results": results,
        "report": report,
    }


def run_comparison_cross_func(
    dataset_dir: str,
    max_samples: int = 10,
    max_nodes_per_sample: int = 3000,
    output_dir: Optional[str] = None,
) -> dict:
    """
    在跨函数 CVE 数据集上对比 Direct LLM vs HGL-Vul。

    这是论文核心实验——HGL-Vul 的压缩优势在大规模真实 CVE 代码上最明显。
    """
    from openai import OpenAI
    from data.vuln_dataset_loader import VulnDatasetLoader

    if output_dir is None:
        output_dir = os.path.join("output", "direct_vs_hgl_cross_func")
    os.makedirs(output_dir, exist_ok=True)

    print("=" * 70)
    print("  Direct LLM vs HGL-Vul — Cross-Function CVE Dataset")
    print("=" * 70)
    print(f"  Dataset: {dataset_dir}")
    print(f"  Max Samples: {max_samples}")
    print(f"  Max Nodes/Sample: {max_nodes_per_sample}")
    print(f"  Model: {LLM_MODEL}")
    print(f"  Token Budget (HGL-Vul): {DEFAULT_TOKEN_BUDGET}")

    # 加载数据集
    print("\n[Step 1] Loading cross-function dataset...")
    loader = VulnDatasetLoader(dataset_dir)
    all_samples = loader.load(max_samples=max_samples * 3)

    # 按节点数过滤
    filtered = []
    for s in all_samples:
        if s.num_nodes <= max_nodes_per_sample:
            filtered.append(s)
        if len(filtered) >= max_samples:
            break
    samples = filtered[:max_samples]

    # 统计
    n_vul = sum(1 for s in samples if s.label == 1)
    n_ben = sum(1 for s in samples if s.label == 0)
    print(f"  Loaded: {len(samples)} samples (vul={n_vul}, ben={n_ben})")
    avg_code_len = sum(len(s.source_code) for s in samples if s.source_code) / max(len(samples), 1)
    print(f"  Avg code length: {avg_code_len:.0f} chars")

    # 初始化 LLM
    client = OpenAI(api_key=LLM_API_KEY, base_url=LLM_BASE_URL)

    # 逐样本对比
    results = []
    direct_correct = 0
    hgl_correct = 0
    direct_tokens_total = 0
    hgl_tokens_total = 0
    n_truncated = 0

    for i, sample in enumerate(samples):
        code = sample.source_code or ""
        label = sample.label
        sid = sample.sample_id
        hops = sample.hop_distance
        vul_type = sample.vul_type

        print(f"\n{'='*70}")
        print(f"  [{i+1}/{len(samples)}] {sid}")
        print(f"  Label={label}, type={vul_type}, hops={hops}, "
              f"code={len(code)}chars, nodes={sample.num_nodes}")
        print(f"{'='*70}")

        row = {
            "sample_id": sid,
            "label": label,
            "hop_count": hops,
            "vul_type": vul_type,
            "code_length": len(code),
            "num_nodes": sample.num_nodes,
            "num_edges": sample.num_edges,
        }

        # ── 模式A：Direct LLM ──
        print(f"  [Direct LLM] 推理中 (code={len(code)}chars)...")
        direct_result = run_direct_llm(code, client, LLM_MODEL)
        row["direct"] = direct_result
        direct_tokens_total += direct_result.get("tokens", 0)
        if direct_result.get("truncated"):
            n_truncated += 1
        if direct_result.get("prediction") == label:
            direct_correct += 1
        d_tok = direct_result.get("tokens", 0)
        print(f"  [Direct LLM] pred={direct_result.get('prediction')}, "
              f"tokens={d_tok}, "
              f"truncated={'⚠' if direct_result.get('truncated') else '✗'}, "
              f"correct={'✓' if direct_result.get('prediction') == label else '✗'} "
              f"({direct_result['time_s']:.1f}s)")

        # ── 模式B：HGL-Vul（Joern CPG → 压缩 → 检索 → 线性化）──
        print(f"  [HGL-Vul] Pipeline 处理中 ({sample.num_nodes} nodes)...")
        hgl_result = run_hgl_pipeline_cross_func(
            code, sample, client, LLM_MODEL, DEFAULT_TOKEN_BUDGET
        )
        row["hgl"] = hgl_result
        hgl_tokens = hgl_result.get("llm_tokens", 0)
        hgl_tokens_total += hgl_tokens
        if hgl_result.get("prediction") == label:
            hgl_correct += 1
        print(f"  [HGL-Vul] pred={hgl_result.get('prediction')}, "
              f"nodes={hgl_result.get('orig_nodes', '?')}→{hgl_result.get('comp_nodes', '?')} "
              f"({hgl_result.get('node_reduction_pct', 0):.0f}%), "
              f"tok={hgl_tokens}, "
              f"correct={'✓' if hgl_result.get('prediction') == label else '✗'} "
              f"({hgl_result['time_s']:.1f}s)")

        results.append(row)

    # ── 汇总报告 ──
    n = len(results)
    direct_n = sum(r["direct"].get("prediction") in (0, 1) for r in results)
    hgl_n = sum(r["hgl"].get("prediction") in (0, 1) for r in results)
    direct_acc = direct_correct / direct_n * 100 if direct_n else 0
    hgl_acc = hgl_correct / hgl_n * 100 if hgl_n else 0
    direct_avg_tokens = direct_tokens_total / direct_n if direct_n else 0
    hgl_avg_tokens = hgl_tokens_total / hgl_n if hgl_n else 0

    # 生成报告
    report_lines = [
        "=" * 70,
        "  Direct LLM vs HGL-Vul — Cross-Function CVE Comparison Report",
        "=" * 70,
        f"",
        f"  Dataset: {dataset_dir}",
        f"  Model: {LLM_MODEL}",
        f"  Samples: {n} (vul={n_vul}, ben={n_ben})",
        f"  HGL-Vul Token Budget: {DEFAULT_TOKEN_BUDGET}",
        f"  Avg Code Length: {avg_code_len:.0f} chars",
        f"  Direct LLM Truncated: {n_truncated}/{n}",
        f"",
        f"  ── Overall Accuracy ──",
        f"  Direct LLM (raw code):        {direct_correct}/{direct_n} = {direct_acc:.1f}% "
        f"({n-direct_n} errors)",
        f"  HGL-Vul (structured):         {hgl_correct}/{hgl_n} = {hgl_acc:.1f}% "
        f"({n-hgl_n} errors)",
        f"  Delta:                        {hgl_acc - direct_acc:+.1f}%",
        f"",
        f"  ── Token Efficiency ──",
        f"  Direct LLM avg tokens:   {direct_avg_tokens:.0f}",
        f"  HGL-Vul avg tokens (API): {hgl_avg_tokens:.0f}",
        f"  Token reduction:          {hgl_avg_tokens - direct_avg_tokens:+.0f} "
        f"({(1 - hgl_avg_tokens / max(direct_avg_tokens, 1)) * 100:.1f}%)",
        f"",
        f"  ── Code vs Context ──",
        f"  Avg Code Size:  {avg_code_len:.0f} chars",
    ]
    avg_ctx = sum(r["hgl"].get("context_chars", 0) for r in results) / max(n, 1)
    avg_red = sum(r["hgl"].get("node_reduction_pct", 0) for r in results) / max(n, 1)
    report_lines.extend([
        f"  Avg HGL Context: {avg_ctx:.0f} chars ({(1 - avg_ctx/max(avg_code_len, 1)) * 100:.1f}% reduction)",
        f"  Avg Node Reduction: {avg_red:.1f}%",
        f"",
        f"  ── Per-Sample Details ──",
    ])

    for r in results:
        d_pred = r["direct"].get("prediction", "?")
        h_pred = r["hgl"].get("prediction", "?")
        label = r["label"]
        d_ok = "✓" if d_pred == label else "✗"
        h_ok = "✓" if h_pred == label else "✗"
        d_tok = r["direct"].get("tokens", 0)
        h_tok = r["hgl"].get("llm_tokens", 0)
        n_red = r["hgl"].get("node_reduction_pct", 0)
        d_trunc = "⚠" if r["direct"].get("truncated") else ""
        report_lines.append(
            f"  {r['sample_id']:<25s} "
            f"code={r['code_length']:>5d}c "
            f"dtok={d_tok:>4d}{d_trunc} "
            f"htok={h_tok:>4d} "
            f"nred={n_red:>5.0f}% "
            f"d={d_pred}({d_ok}) h={h_pred}({h_ok})"
        )

    report = "\n".join(report_lines)
    print("\n" + report)

    # 保存
    report_path = os.path.join(output_dir, "comparison_cross_func_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"\n[Saved] {report_path}")

    json_path = os.path.join(output_dir, "comparison_cross_func_results.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "config": {
                "dataset_dir": dataset_dir,
                "model": LLM_MODEL,
                "num_samples": n,
                "token_budget": DEFAULT_TOKEN_BUDGET,
            },
            "summary": {
                "direct_accuracy": round(direct_acc, 1),
                "hgl_accuracy": round(hgl_acc, 1),
                "delta": round(hgl_acc - direct_acc, 1),
                "direct_avg_tokens": round(direct_avg_tokens, 0),
                "hgl_avg_tokens_api": round(hgl_avg_tokens, 0),
                "n_truncated": n_truncated,
                "avg_code_chars": round(avg_code_len, 0),
                "avg_hgl_context_chars": round(avg_ctx, 0),
                "avg_node_reduction_pct": round(avg_red, 1),
            },
            "results": results,
        }, f, indent=2, ensure_ascii=False)
    print(f"[Saved] {json_path}")

    return {
        "config": {
            "dataset_dir": dataset_dir,
            "model": LLM_MODEL,
            "num_samples": n,
        },
        "results": results,
        "report": report,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Direct LLM vs HGL-Vul Pipeline Comparison"
    )
    parser.add_argument("num_or_dir", nargs="?", default="12",
                        help="Number of samples (synthetic) or dataset dir (with --cross-func)")
    parser.add_argument("output_dir", nargs="?", default=None,
                        help="Output directory for reports")
    parser.add_argument("--cross-func", action="store_true",
                        help="Use cross-function CVE dataset instead of synthetic")
    args = parser.parse_args()

    if args.cross_func:
        max_samples = int(args.output_dir) if args.output_dir and args.output_dir.isdigit() else 10
        out_dir = None if (args.output_dir and args.output_dir.isdigit()) else args.output_dir
        run_comparison_cross_func(
            dataset_dir=args.num_or_dir,
            max_samples=max_samples,
            output_dir=out_dir,
        )
    else:
        num = int(args.num_or_dir) if args.num_or_dir.isdigit() else 12
        run_comparison(num_samples=num, output_dir=args.output_dir)
