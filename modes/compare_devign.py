"""
Mode 8: 三组对比实验 — Direct LLM vs HGL-Vul vs VulnSC(DeepSeek)

在同一批样本上运行 Direct LLM 和 HGL-Vul，然后与论文 Table5 的 DeepSeek 结果对比。
"""
import os
import sys
import json
import time
import random

from config import LLM_MODEL, SEED, DEVIGN_JSON_PATH, DEVIGN_ENHANCE_DIR
from graph.build_cpg import build_cpg, find_export_files
from graph.load_graph import load_graph
from graph.summarize_graph import summarize_graph
from retrieval.candidate_paths import extract_all_candidate_paths
from retrieval.retrieve_topk import retrieve_topk
from linearization.function_summary import summarize_function
from linearization.block_summary import summarize_block
from reasoning.llm_api import create_client
from reasoning.reasoning_loop import reasoning_loop
from reasoning.reasoning_loop import parse_binary_verdict

DEFAULT_TOKEN_BUDGET = 4096  # 恢复 4096，单独测随机抽样影响


def _calc_metrics(results):
    """Helper to compute classification metrics."""
    from evaluation.metrics import compute_metrics
    return compute_metrics([r['target'] for r in results],
                           [r.get('prediction') for r in results])


def _pipeline_fingerprint() -> str:
    """BUG-11（审查报告）：管线代码指纹。

    resume 复用预测前校验指纹——旧代码算出的 prediction 不并入本次指标
    （防止跨版本指标污染，单变量实验纪律被静默破坏）。样本批次的复用
    不受影响（done_idx 取全部条目），仅预测复用被隔离。
    """
    import hashlib
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    files = [os.path.join(root, "config.py"),
             os.path.join(os.path.dirname(os.path.abspath(__file__)), "compare_devign.py")]
    # Only prediction-path modules belong here. Dataset preparation/loaders do
    # not alter a prediction for an already identified sample; including them
    # invalidated costly LLM results after harmless cache-tool changes.
    for d in ("graph", "retrieval", "linearization", "reasoning",
              "learning", "planning"):
        p = os.path.join(root, d)
        if os.path.isdir(p):
            files.extend(os.path.join(p, fn) for fn in sorted(os.listdir(p))
                         if fn.endswith(".py"))
    h = hashlib.md5()
    # Model/provider changes must not silently reuse another model's predictions.
    import config as runtime_config
    h.update(json.dumps({'model': runtime_config.LLM_MODEL,
                         'base_url': runtime_config.LLM_BASE_URL},
                        sort_keys=True).encode())
    for f in sorted(files):
        try:
            with open(f, "rb") as fh:
                h.update(os.path.relpath(f, root).encode())
                h.update(fh.read())
        except OSError:
            pass
    # Every runtime switch that changes predictions must participate in resume
    # isolation.  In particular, baseline and learned/GAT SVEN runs otherwise
    # look identical to the old fingerprint and silently reuse one another.
    for name in (
        "HGL_ABL",
        "NODE_IMPORTANCE_BACKEND",
        "USE_LEARNED_NODE_IMPORTANCE",
        "USE_LEARNED_SUMMARIZE",
        "USE_LEARNED_PATH_RANK",
        "MAX_REASONING_STEPS",
        "STEP1_CONFIRM_STOP",
        "SOURCE_SLICE_ASSIGNMENT_FIX",
        "COMPACT_THREE_PART_CONTEXT",
        "USE_LLM_ARBITRATION",
        "SELECTIVE_SECOND_PASS",
        "F1_EVIDENCE_ROUTING",
        "STRUCTURED_PRIOR_SUMMARY",
        "COMPACT_VERDICT_PROMPT",
        "FOCUSED_GRAPH_ANCHORS",
        "TYPE_COVERAGE_PROMPT",
        "TYPE_COVERAGE_ROUTING",
        "USE_ZERO_TOKEN_SECURITY_NET",
        "SECURITY_NET_THRESHOLD",
        "GRAPH_SECURITY_NET",
        "USE_BACKWARD_SLICE", "BOUNDED_OUTPUT_CONTRACT", "EVIDENCE_EXPANSION",
        "STRICT_OPERATION_TAGS",
    ):
        h.update(f"{name}={os.environ.get(name, '')}".encode())

    checkpoint = os.environ.get(
        "GAT_MODEL_PATH", os.path.join(root, "learning", "model", "gat_mil.pt")
    )
    try:
        with open(checkpoint, "rb") as fh:
            h.update(b"GAT_MODEL=")
            h.update(hashlib.sha256(fh.read()).digest())
    except OSError:
        h.update(b"GAT_MODEL=missing")
    return h.hexdigest()


def _run_hgl_pipeline(code_path, code, sample_id, sample_dir, llm_client, token_budget):
    """Compatibility adapter; all entry points delegate to graph.pipeline."""
    from graph.pipeline import run_hgl_pipeline
    return run_hgl_pipeline(code_path, code, sample_id, sample_dir, llm_client, token_budget)




def mode_compare_devign(
    devign_json: str = None,
    enhance_dir: str = None,
    fold: int = 0,
    max_samples: int = 200,
    token_budget: int = DEFAULT_TOKEN_BUDGET,
    output_dir: str = "output/devign_comparison",
    resume: bool = True,
    min_func_bytes: int = 0,
    run_a: bool = True,
):
    """三组对比实验：Direct LLM vs HGL-Vul vs VulnSC(DeepSeek)。"""
    from data.devign_loader import DevignLoader, DevignBatchProcessor

    print("=" * 70)
    print("  Mode 8: 三组对比实验")
    print("  Direct LLM vs HGL-Vul vs VulnSC(DeepSeek)")
    print("=" * 70)

    print(f"\n[控制变量]")
    print(f"  LLM:           {LLM_MODEL} (与 VulnSC DeepSeek 一致)")
    print(f"  Temperature:   0.0")
    print(f"  Fold:          {fold}")
    print(f"  Max Samples:   {max_samples}")
    print(f"  Token Budget:  {token_budget}")
    _abl = os.environ.get("HGL_ABL", "")
    if _abl:
        print(f"  Ablation:      {_abl}")
        # Per-call max_steps is applied by the shared pipeline; no global mutation.

    # BUG-11：管线指纹（resume 预测复用校验用）
    pipeline_fp = _pipeline_fingerprint()
    print(f"  Pipeline FP:   {pipeline_fp[:16]}")

    # Step 1: 加载数据
    if devign_json is None:
        candidate = DEVIGN_JSON_PATH
        if os.path.exists(candidate):
            devign_json = candidate
        else:
            print("[Error] 未指定 devign_json 路径，请设置 DEVIGN_JSON_PATH 或调用参数")
            sys.exit(1)
    if enhance_dir is None:
        candidate = DEVIGN_ENHANCE_DIR
        if os.path.exists(candidate):
            enhance_dir = candidate
        else:
            enhance_dir = None

    loader = DevignLoader(devign_json)
    loader.load(fold_indices=None)
    test_samples = loader.get_fold(fold=fold, split="test")

    # 大函数筛选：实验目标是长上下文场景（完整源码难以直接输入 LLM）
    if min_func_bytes > 0:
        before = len(test_samples)
        test_samples = [s for s in test_samples if len(s.func) >= min_func_bytes]
        print(f"\n[大函数筛选] >= {min_func_bytes} 字节: {before} -> {len(test_samples)} "
              f"(漏洞={sum(1 for s in test_samples if s.target==1)}, "
              f"良性={sum(1 for s in test_samples if s.target==0)})")

    # 采样
    if max_samples > 0 and max_samples < len(test_samples):
        # 用 SystemRandom：与全局 random 状态解耦，杜绝任何 random.seed(...)
        # 残留固定批次（bug：devign_loader _create_random_folds 曾 seed(42)
        # 导致 v12c 起每次 resume=False 都抽到完全相同的 100 样本）。
        rng = random.SystemRandom()
        vuln = [s for s in test_samples if s.target == 1]
        ben = [s for s in test_samples if s.target == 0]
        # v12e+: resume 时复用已完成样本，保证跨版本同批样本可比（单变量纪律）
        done_idx = set()
        if resume:
            _probe = DevignBatchProcessor(output_dir=output_dir)
            done_idx = {r["idx"] for r in _probe.load_results()}
        if done_idx:
            reused = [s for s in test_samples if s.idx in done_idx]
            need = max_samples - len(reused)
            if need > 0:
                pool_v = [s for s in vuln if s.idx not in done_idx]
                pool_b = [s for s in ben if s.idx not in done_idx]
                add_v = rng.sample(pool_v, min(len(pool_v), need // 2))
                add_b = rng.sample(pool_b, min(len(pool_b), need - len(add_v)))
                reused = reused + add_v + add_b
            test_samples = reused
            rng.shuffle(test_samples)
            print(f"\n[样本复用] resume 复用 {len(done_idx)} 个已完成样本 idx")
        else:
            n_vuln = min(len(vuln), max_samples // 2)
            n_ben = min(len(ben), max_samples - n_vuln)
            # SystemRandom：每次运行抽取真正不同的随机样本（v12c+: 防过拟合）
            selected = rng.sample(vuln, n_vuln) + rng.sample(ben, n_ben)
            rng.shuffle(selected)
            test_samples = selected
    print(f"\n评测样本: {len(test_samples)} ({sum(1 for s in test_samples if s.target==1)} vuln + {sum(1 for s in test_samples if s.target==0)} benign)")

    # 准备公共样本
    processor = DevignBatchProcessor(output_dir=output_dir)
    metadata_list = processor.prepare_samples(test_samples, use_enhanced=False)

    # 初始化 LLM
    llm_client = create_client()

    # === 实验 A: Direct LLM ===
    if not run_a:
        # 消融 B-only（2026-09-23）：跳过实验 A——消融对照基线复用
        # fold1 全量已有 A/B 结果，重跑 A 仅浪费 ~6h/配置与 token。
        print(f"\n[消融] run_a=False: 跳过实验 A（B-only，基线复用 fold1 全量）")
    print(f"\n{'='*50}")
    print(f"实验 A: Direct LLM (裸代码→DeepSeek)")
    print(f"{'='*50}")

    # BUG-11：指纹不匹配的旧预测被隔离（不计指标），样本批次复用不受影响
    all_a = processor.load_results() if resume else []
    existing_a = [r for r in all_a if r.get("mode") == "direct_llm"
                  and r.get("pipeline_fp") == pipeline_fp]
    stale_a = [r for r in all_a if r.get("mode") == "direct_llm"
               and r.get("pipeline_fp") != pipeline_fp]
    if stale_a:
        print(f"[BUG-11] 实验 A: 隔离 {len(stale_a)} 条旧指纹预测（不计指标，仅样本批次复用）")
    completed_a = {r["idx"] for r in existing_a}

    results_a = list(existing_a)
    pending_a = [m for m in metadata_list if m["idx"] not in completed_a]

    DIRECT_PROMPT = """You are a C/C++ security expert. Analyze the following code and determine if it contains a vulnerability.

Code:
```c
{code}
```

Is this code vulnerable? Answer with exactly one word: "vulnerable" or "benign".
"""

    start_a = time.time()
    for i, meta in enumerate(pending_a if run_a else []):
        idx = meta["idx"]
        target = meta["target"]
        print(f"  [A {i+1}/{len(pending_a)}] idx={idx}, target={'VUL' if target else 'BEN'}", end=" ")

        result = {"idx": idx, "target": target, "fold": meta["fold"],
                  "project": meta["project"], "mode": "direct_llm",
                  "pipeline_fp": pipeline_fp, "prediction": None}
        try:
            with open(meta["file_path"], "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
            if len(code) > 6000:
                code = code[:6000] + "\n// ..."
            resp = llm_client.chat.completions.create(
                model=LLM_MODEL,
                messages=[{"role": "user", "content": DIRECT_PROMPT.format(code=code)}],
                temperature=0.0, max_tokens=16,
            )
            ans = resp.choices[0].message.content.strip().lower()
            # BUG-08 修复：子串匹配 "vulnerable" 会把 "not vulnerable"/"no
            # vulnerability" 误判为漏洞（基线 Direct LLM 虚高 FP）。先排除
            # 否定/良性表述，再判漏洞词。词级匹配避免 "unsafe" 命中 "safe"
            # （_SAFE_RE 同款教训）。
            result["prediction"] = parse_binary_verdict(ans)
            if result["prediction"] is None:
                raise ValueError(f"Ambiguous verdict: {ans[:120]!r}")
            result["raw_answer"] = ans
            result["tokens_used"] = resp.usage.total_tokens if resp.usage else 0
        except Exception as e:
            # Preserve abstentions/errors in the full scheduled denominator.
            result["error"] = str(e)
            result["prediction"] = None

        mark = "E" if result["prediction"] is None else ("✓" if result["prediction"] == target else "✗")
        print(f"→ {result['prediction']} {mark}")
        results_a.append(result)
        processor.save_intermediate(result)

    if run_a and pending_a:
        print(f"  实验 A 完成: {len(pending_a)} 样本, {time.time()-start_a:.1f}s")

    # === 实验 B: HGL-Vul ===
    print(f"\n{'='*50}")
    print(f"实验 B: HGL-Vul (图压缩→层次化线性化→DeepSeek)")
    print(f"{'='*50}")

    # BUG-11：同实验 A——指纹不匹配的旧预测隔离，样本批次复用不受影响
    all_b = processor.load_results() if resume else []
    existing_b = [r for r in all_b if r.get("mode") == "hgl_vul"
                  and r.get("pipeline_fp") == pipeline_fp]
    stale_b = [r for r in all_b if r.get("mode") == "hgl_vul"
               and r.get("pipeline_fp") != pipeline_fp]
    if stale_b:
        print(f"[BUG-11] 实验 B: 隔离 {len(stale_b)} 条旧指纹预测（不计指标，仅样本批次复用）")
    completed_b = {r["idx"] for r in existing_b}

    results_b = list(existing_b)
    pending_b = [m for m in metadata_list if m["idx"] not in completed_b]

    start_b = time.time()
    for i, meta in enumerate(pending_b):
        idx = meta["idx"]
        target = meta["target"]
        sample_id = meta["sample_id"]
        print(f"  [B {i+1}/{len(pending_b)}] idx={idx}, target={'VUL' if target else 'BEN'}", end=" ")

        result = {"idx": idx, "target": target, "fold": meta["fold"],
                  "project": meta["project"], "mode": "hgl_vul",
                  "pipeline_fp": pipeline_fp, "ablation": _abl,
                  "prediction": None}
        try:
            with open(meta["file_path"], "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
            sample_dir = os.path.join(output_dir, "cpg", sample_id)
            pred, raw_ans, tok, arb = _run_hgl_pipeline(meta["file_path"], code, sample_id, sample_dir, llm_client, token_budget)
            result["prediction"] = pred
            result["raw_answer"] = raw_ans
            result["tokens_used"] = tok
            result["arbitrate"] = arb
        except Exception as e:
            # Errors remain scheduled rows and count conservatively.
            result["error"] = str(e)
            result["prediction"] = None

        mark = "E" if result["prediction"] is None else ("✓" if result["prediction"] == target else "✗")
        print(f"→ {result['prediction']} {mark} ans='{result.get('raw_answer','')}'")
        results_b.append(result)
        processor.save_intermediate(result)

    if pending_b:
        print(f"  实验 B 完成: {len(pending_b)} 样本, {time.time()-start_b:.1f}s")

    # === 汇总对比 ===
    m_a = _calc_metrics(results_a)
    m_b = _calc_metrics(results_b)

    # Report errors explicitly; they are retained by _calc_metrics.
    err_a = sum(1 for r in results_a if r.get("error"))
    err_b = sum(1 for r in results_b if r.get("error"))
    if err_a or err_b:
        print(f"\n[异常样本] A: {err_a}/{len(results_a)} 错误 (n={m_a['n']} 计入指标) | "
              f"B: {err_b}/{len(results_b)} 错误 (n={m_b['n']} 计入指标)")

    # token 消耗统计（论文核心指标之一）
    tok_a = [r["tokens_used"] for r in results_a if r.get("tokens_used")]
    tok_b = [r["tokens_used"] for r in results_b if r.get("tokens_used")]
    avg_tok_a = sum(tok_a) / len(tok_a) if tok_a else 0
    avg_tok_b = sum(tok_b) / len(tok_b) if tok_b else 0

    delta_acc = m_b["accuracy"] * 100 - m_a["accuracy"] * 100
    delta_pre = m_b["precision"] * 100 - m_a["precision"] * 100
    delta_rec = m_b["recall"] * 100 - m_a["recall"] * 100
    delta_f1 = m_b["f1"] * 100 - m_a["f1"] * 100

    print(f"\n{'='*70}")
    print(f"  三组对比汇总 — Devign Fold {fold}")
    print(f"{'='*70}")
    print(f"  {'Method':<30} {'Acc%':>8} {'Pre%':>8} {'Rec%':>8} {'F1%':>8} {'N':>6} {'AvgTok':>10}")
    print(f"  {'-'*72}")
    print(f"  {'A) Direct LLM (ours)':<30} {m_a['accuracy']*100:>8.2f} {m_a['precision']*100:>8.2f} {m_a['recall']*100:>8.2f} {m_a['f1']*100:>8.2f} {m_a['n']:>6} {avg_tok_a:>10.0f}")
    print(f"  {'B) HGL-Vul (ours)':<30} {m_b['accuracy']*100:>8.2f} {m_b['precision']*100:>8.2f} {m_b['recall']*100:>8.2f} {m_b['f1']*100:>8.2f} {m_b['n']:>6} {avg_tok_b:>10.0f}")
    print(f"  {'B - A 提升':<30} {f'+{delta_acc:.2f}':>8} {f'+{delta_pre:.2f}':>8} {f'+{delta_rec:.2f}':>8} {f'+{delta_f1:.2f}':>8} {'':>6} {avg_tok_b-avg_tok_a:>+10.0f}")
    print(f"  {'-'*62}")
    print(f"  VulnSC 论文中 DeepSeek 结果 (basic 提示):")
    deepseek_results = {
        "VulnSC(CodeBERT)+DeepSeek": 62.18,
        "VulnSC(GraphCodeBERT)+DeepSeek": 61.52,
        "VulnSC(UniXcoder)+DeepSeek": 63.19,
        "VulnSC(LineVul)+DeepSeek": 63.59,
    }
    for method, acc in deepseek_results.items():
        print(f"  {method:<30} {acc:>8.2f}")
    print(f"  {'-'*62}")
    print(f"  LLM4Vuln (GPT-4 raw):          52.37")
    print(f"  GRACE:                         59.78")
    print(f"  LineVul (original):            61.48")
    print(f"{'='*70}")

    # 保存对比报告
    comparison = {
        "config": {
            "mode": "compare",
            "fold": fold,
            "max_samples": max_samples,
            "llm_model": LLM_MODEL,
            "token_budget": token_budget,
            "seed": SEED,
            "ablation": _abl,
        },
        "direct_llm": m_a,
        "hgl_vul": m_b,
        "token_usage": {
            "direct_llm_avg": round(avg_tok_a, 1),
            "hgl_vul_avg": round(avg_tok_b, 1),
            "hgl_vul_samples_with_tokens": len(tok_b),
            "direct_llm_samples_with_tokens": len(tok_a),
        },
        "improvement": {
            "accuracy_delta": round(m_b["accuracy"] - m_a["accuracy"], 4),
            "precision_delta": round(m_b["precision"] - m_a["precision"], 4),
            "recall_delta": round(m_b["recall"] - m_a["recall"], 4),
            "f1_delta": round(m_b["f1"] - m_a["f1"], 4),
        },
        "vulnsc_deepseek_baselines": deepseek_results,
        "results_a": results_a,
        "results_b": results_b,
    }
    comp_path = os.path.join(output_dir, "comparison_report.json")
    with open(comp_path, "w", encoding="utf-8") as f:
        json.dump(comparison, f, indent=2, ensure_ascii=False)
    print(f"\n[Saved] {comp_path}")

    return comparison
