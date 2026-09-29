"""
Mode 8: 三组对比实验 — Direct LLM vs HGL-Vul vs VulnSC(DeepSeek)

在同一批样本上运行 Direct LLM 和 HGL-Vul，然后与论文 Table5 的 DeepSeek 结果对比。
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
from reasoning.llm_api import create_client
from reasoning.reasoning_loop import reasoning_loop
from planning.state_memory import ProgramState

DEFAULT_TOKEN_BUDGET = 4096  # 恢复 4096，单独测随机抽样影响


def _calc_metrics(results):
    """Helper to compute classification metrics."""
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    valid = [r for r in results if r.get("prediction") is not None]
    if not valid:
        return {"accuracy": 0, "precision": 0, "recall": 0, "f1": 0, "n": 0}
    yt = [r["target"] for r in valid]
    yp = [r["prediction"] for r in valid]
    return {
        "accuracy": accuracy_score(yt, yp),
        "precision": precision_score(yt, yp, zero_division=0),
        "recall": recall_score(yt, yp, zero_division=0),
        "f1": f1_score(yt, yp, zero_division=0),
        "n": len(valid),
    }


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
    for d in ("graph", "retrieval", "linearization", "reasoning",
              "learning", "planning", "data"):
        p = os.path.join(root, d)
        if os.path.isdir(p):
            files.extend(os.path.join(p, fn) for fn in sorted(os.listdir(p))
                         if fn.endswith(".py"))
    h = hashlib.md5()
    for f in sorted(files):
        try:
            with open(f, "rb") as fh:
                h.update(os.path.relpath(f, root).encode())
                h.update(fh.read())
        except OSError:
            pass
    # 消融隔离（2026-09-23）：HGL_ABL 混入指纹——四个消融配置各自独立
    # 指纹，resume 预测复用自动隔离（防错误 env 续跑导致配置间结果串批）。
    h.update(("HGL_ABL=" + os.environ.get("HGL_ABL", "")).encode())
    return h.hexdigest()


def _run_hgl_pipeline(code_path, code, sample_id, sample_dir, llm_client, token_budget):
    """运行 HGL-Vul 管线。

    返回 (prediction, conclusion, tokens_used, arbitrate_record)；
    arbitrate_record 为 v19 仲裁层的结构化记录（triggered/verdict/
    flipped/note 等），由调用方写入结果 JSON。
    """
    os.makedirs(sample_dir, exist_ok=True)
    try:
        export_dir = build_cpg(code_path, sample_dir)
        nodes_file, edges_file = find_export_files(export_dir)
    except Exception:
        nodes_file = os.path.join(sample_dir, "nodes.json")
        edges_file = os.path.join(sample_dir, "edges.json")
        if not os.path.exists(nodes_file):
            raise
    G = load_graph(nodes_file, edges_file)

    # ── 技术点①②：学习式节点重要性（全图打分一次，两处复用）──
    from learning.scorer import score_nodes, summarize_enabled, path_rank_enabled
    learned = score_nodes(G, code)

    # ── 消融开关（2026-09-23，v22.1 冻结代码之上的运行时开关；HGL_ABL
    # 未设置时四条路径均与 v22.1 逐字节等价，默认行为零变化）──
    _abl = os.environ.get("HGL_ABL", "")
    if _abl == "no_compression":
        # ① 漏洞感知图压缩关闭：跳过 summarize_graph，路径检索/推理/
        # 仲裁直接在完整 CPG 上（上下文层 SRC/DEP 有硬预算上限，token
        # 不会失控，消融效应体现在证据质量与选择偏差上）
        SG = G
    else:
        # v17（BUG-10）：source_code 接线——激活 detect_vuln_type_hint +
        # VULN_CONDITIONAL_WEIGHTS（UAF/DoubleFree/Overflow/NullDeref/FmtStr
        # 六维差异化权重），此前主实验路径恒用 Generic 权重。仅影响图压缩
        # 节点选择（类型相关证据链存活率），不触碰 prompt/切片/标签——
        # 单变量纪律：与 v16 的唯一差异就是这一处接线。
        SG = summarize_graph(G, token_budget=token_budget, source_code=code,
                             learned_scores=learned if summarize_enabled() else None)
    # BUG-09 修复：回退路径来自 G 时 rank/序列化/兜底全用 SG 会取空节点。
    # 统一 path_graph，路径来源与打分/序列化用同一图对象。
    sg_paths = extract_all_candidate_paths(SG, source_code=code)
    if sg_paths:
        path_graph, candidate_paths = SG, sg_paths
    else:
        candidate_paths = extract_all_candidate_paths(G, source_code=code)
        path_graph = G
    if _abl == "no_topk":
        # ② 智能路径检索关闭：Top-K 启发式排序 → 等量随机替代（研究计划
        # 口径：随机替代而非删除，控制路径数量这一变量）。局部 Random 按
        # sample_id 种子——可复现且不污染全局随机源（random.seed 教训）。
        from config import TOP_K_PATHS
        _rng = random.Random(f"abl_topk:{sample_id}")
        _k = min(TOP_K_PATHS, len(candidate_paths))
        topk = _rng.sample(candidate_paths, _k) if _k else []
        print(f"[ABL:no_topk] 随机替代 Top-K: {len(topk)}/{len(candidate_paths)} 条")
    else:
        topk = retrieve_topk(path_graph, candidate_paths,
                             learned_scores=learned if path_rank_enabled() else None)

    # ── Fix 2: 保留所有块摘要 ──
    func_summary = summarize_function(code)
    blocks = code.split("\n\n")
    block_summaries = {}
    for j, blk in enumerate(blocks):
        stripped = blk.strip()
        if stripped:
            block_summaries[j] = summarize_block(stripped) or stripped[:80]

    # v15/v16（BUG-03/19）：原 Fix 1/Fix 5 在此构建 paths_context（多行详细
    # 序列化 + 函数级 api_hints 全局标注）但从未传入 reasoning_loop——
    # 死代码，已删。其意图（带安全标签的路径证据进入 LLM 上下文）改由
    # build_hierarchical_context Step1 DEP 层落地：_labeled_compact_path
    # 节点级标签 + path_evidence_tags 路径级证据头（仅本路径实际命中的
    # API；函数级全局标注会放大良性样本的危险信号，见 BUG-19）。
    # v16 回退 v15 的 SAFE 缓解层（安全锚点双刃剑：TP→FN 12 崩 Rec）。

    # ── Fix 3: 程序状态 ──
    state = ProgramState()
    state.track_vars(code)

    # BUG-09 修复：reasoning_loop 的图序列化同样使用路径同源图
    reasoning_result = reasoning_loop(
        path_graph, topk, code, func_summary, block_summaries,
        client=llm_client,
    )
    conclusion = reasoning_result.get("conclusion", "").lower()
    vul_type = reasoning_result.get("vulnerability_type", "Unknown")
    tokens_used = reasoning_result.get("tokens_used", 0)
    result = 1 if vul_type != "Unknown" else 0

    # v19（图特征仲裁层）：主推理（自由形式）出预测后，图结构事实
    # （guard_dom_pairs：sink + 对齐守卫）经受限二元精审仲裁——分歧时
    # 信精审（试点：分歧区精审 83% vs 主判断 17%，两批一致 +4 Acc，
    # 触发 6%/批 × 118 tok）。图不进 Step1 上下文（v18 三次双刃剑教训）。
    # 消融 no_arbitrate（2026-09-23）：仲裁层关闭，直接采用主推理预测。
    main_pred = result
    if _abl == "no_arbitrate":
        audit_tok, audit_note, audit_info = 0, "", {"triggered": False, "verdict": None}
    else:
        from graph.arbitrate import arbitrate
        result, audit_tok, audit_note, audit_info = arbitrate(path_graph, topk, result,
                                                              client=llm_client)
    tokens_used += audit_tok
    if audit_note:
        print(f"  {audit_note}")
        conclusion = (conclusion + " " + audit_note) if conclusion else audit_note
    # v20（持久化缺陷修复）：仲裁记录结构化落盘——v19 时 FLIP 信息只混在
    # raw_answer 自由文本 + print 日志里，归因需日志对齐还原；全集规模的
    # 归因必须由结果 JSON 自带结构化字段。
    # v21：补记 vulnerability_type（v20 归因时发现未持久化，兜底/具体类型
    # 归属只能靠 raw_answer 重放解析器）。
    arb_record = dict(audit_info)
    arb_record.update({"main_pred": main_pred, "final_pred": result,
                       "flipped": result != main_pred,
                       "audit_tokens": audit_tok, "note": audit_note,
                       "vulnerability_type": vul_type})
    print(f"  [DEBUG] vul_type={vul_type} tokens={tokens_used} conclusion_preview={conclusion[:100]}")
    return (result, conclusion, tokens_used, arb_record)


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
        # 消融 single_step（2026-09-23）：③ 自适应多步推理关闭——步数 2→1。
        # patch 模块级常量（reasoning_loop 以模块全局引用 MAX_REASONING_STEPS，
        # 运行期替换对循环边界与 is_final 判定同时生效）。
        # 注意：必须经 sys.modules 取模块——reasoning/__init__.py 的
        # `from reasoning.reasoning_loop import reasoning_loop` 把**函数**
        # 绑到包属性 reasoning.reasoning_loop 上遮蔽了子模块，Py3.13 的
        # `import reasoning.reasoning_loop as x` 经 getattr 会拿到函数，
        # 在函数对象上挂属性静默无效（冒烟实测 Step 1/2 复现）。
        if _abl == "single_step":
            sys.modules["reasoning.reasoning_loop"].MAX_REASONING_STEPS = 1
            print(f"  [ABL] MAX_REASONING_STEPS -> 1 "
                  f"(now={sys.modules['reasoning.reasoning_loop'].MAX_REASONING_STEPS})")

    # BUG-11：管线指纹（resume 预测复用校验用）
    pipeline_fp = _pipeline_fingerprint()
    print(f"  Pipeline FP:   {pipeline_fp[:16]}")

    # Step 1: 加载数据
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
            words = set(ans.replace(".", " ").replace(",", " ").split())
            is_safe = ("benign" in words or "safe" in words
                       or "not" in words or "no" in words)
            result["prediction"] = 0 if is_safe else (1 if "vulnerable" in ans else 0)
            result["raw_answer"] = ans
            result["tokens_used"] = resp.usage.total_tokens if resp.usage else 0
        except Exception as e:
            # BUG-12：异常样本不计入指标（None 会被 _calc_metrics 过滤），
            # 不再静默落成 prediction=0 压低 Rec
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
            # BUG-12：异常样本不计入指标
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

    # BUG-12：异常样本显式统计（None 已被 _calc_metrics 剔除，此处报告口径）
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