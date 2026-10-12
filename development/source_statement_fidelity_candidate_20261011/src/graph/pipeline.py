"""Single production HGL pipeline shared by analysis and dataset entry points."""
import os
import random
from graph.build_cpg import build_cpg, find_export_files
from graph.load_graph import load_graph
from graph.summarize_graph import summarize_graph
from retrieval.candidate_paths import extract_all_candidate_paths
from retrieval.retrieve_topk import retrieve_topk
from linearization.function_summary import summarize_function
from linearization.block_summary import summarize_block
from reasoning.reasoning_loop import reasoning_loop

def run_hgl_pipeline(code_path, code, sample_id, sample_dir, llm_client, token_budget=4096,
                     *, ablation=None, return_details=False):
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
    learned = score_nodes(G, code) if (summarize_enabled() or path_rank_enabled()) else None

    # ── 消融开关（2026-09-23，v22.1 冻结代码之上的运行时开关；HGL_ABL
    # 未设置时四条路径均与 v22.1 逐字节等价，默认行为零变化）──
    _abl = os.environ.get("HGL_ABL", "") if ablation is None else ablation
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
    from config import COMPACT_THREE_PART_CONTEXT
    func_summary, block_summaries = "", {}
    if not COMPACT_THREE_PART_CONTEXT:
        func_summary = summarize_function(code)
        for j, blk in enumerate(code.split("\n\n")):
            if blk.strip():
                block_summaries[j] = summarize_block(blk.strip()) or blk.strip()[:80]

    # v15/v16（BUG-03/19）：原 Fix 1/Fix 5 在此构建 paths_context（多行详细
    # 序列化 + 函数级 api_hints 全局标注）但从未传入 reasoning_loop——
    # 死代码，已删。其意图（带安全标签的路径证据进入 LLM 上下文）改由
    # build_hierarchical_context Step1 DEP 层落地：_labeled_compact_path
    # 节点级标签 + path_evidence_tags 路径级证据头（仅本路径实际命中的
    # API；函数级全局标注会放大良性样本的危险信号，见 BUG-19）。
    # v16 回退 v15 的 SAFE 缓解层（安全锚点双刃剑：TP→FN 12 崩 Rec）。

    # BUG-09 修复：reasoning_loop 的图序列化同样使用路径同源图
    # Joern sees wrapped source in some dataset adapters. Only accept an exact,
    # unambiguous mapping; otherwise slicing falls back with a visible receipt.
    with open(code_path, encoding='utf-8', errors='ignore') as source_file:
        joern_source = source_file.read()
    from linearization.source_mapping import source_line_offset as map_source_lines
    source_line_offset = map_source_lines(code, joern_source)
    reasoning_result = reasoning_loop(
        path_graph, topk, code, func_summary, block_summaries,
        client=llm_client, full_graph=G,
        source_line_offset=source_line_offset,
        use_prog_state=(_abl != 'no_state'),
        use_adapt_plan=(_abl != 'no_planning'),
        use_hier_lin=(_abl != 'no_hier_lin'),
        max_steps=1 if _abl == 'single_step' else None,
        use_slice=False if _abl == 'no_slice' else None,
        use_output_contract=False if _abl == 'no_output_contract' else None,
        use_expansion=False if _abl == 'no_expansion' else None,
    )
    conclusion = reasoning_result.get("conclusion", "").lower()
    vul_type = reasoning_result.get("vulnerability_type", "Unknown")
    tokens_used = reasoning_result.get("tokens_used", 0)
    result = 1 if vul_type != "Unknown" else 0
    if reasoning_result.get('decision_status') == 'Uncertain':
        result = None

    # 零-token安全网：仅用高置信生命周期/危险链证据做 0→1 单向恢复。
    # 阈值在非 SVEN 的 Devign 校准集冻结；不调用 LLM，不做 1→0 翻转。
    main_pred = result
    from config import USE_ZERO_TOKEN_SECURITY_NET, SECURITY_NET_THRESHOLD, GRAPH_SECURITY_NET
    if USE_ZERO_TOKEN_SECURITY_NET and _abl != 'no_safety_net':
        from graph.security_net import zero_token_verify
        if GRAPH_SECURITY_NET:
            from graph.security_net_graph import zero_token_graph_verify
            result, security_net_info = zero_token_graph_verify(
                result, G, topk, threshold=SECURITY_NET_THRESHOLD)
        else:
            result, security_net_info = zero_token_verify(
                result, code, threshold=SECURITY_NET_THRESHOLD)
    else:
        security_net_info = {
            "triggered": False, "flipped": False, "audit_tokens": 0
        }

    # v19（图特征仲裁层）：主推理（自由形式）出预测后，图结构事实
    # （guard_dom_pairs：sink + 对齐守卫）经受限二元精审仲裁——分歧时
    # 信精审（试点：分歧区精审 83% vs 主判断 17%，两批一致 +4 Acc，
    # 触发 6%/批 × 118 tok）。图不进 Step1 上下文（v18 三次双刃剑教训）。
    # 消融 no_arbitrate（2026-09-23）：仲裁层关闭，直接采用主推理预测。
    from config import USE_LLM_ARBITRATION
    if result is None or _abl == "no_arbitrate" or not USE_LLM_ARBITRATION:
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
                       "vulnerability_type": vul_type,
                       "reasoning_steps": reasoning_result.get("steps"),
                       "reasoning_trace": reasoning_result.get("trace", []),
                       "security_net": security_net_info})
    arb_record['module_audit'] = reasoning_result.get('module_audit', {})
    arb_record['decision_status'] = reasoning_result.get('decision_status')
    arb_record['module_audit'].update({
        'ablation': _abl or 'full', 'learned_scoring': learned is not None,
        'graph_security_net': bool(GRAPH_SECURITY_NET and USE_ZERO_TOKEN_SECURITY_NET and _abl != 'no_safety_net'),
        'source_security_net': bool(not GRAPH_SECURITY_NET and USE_ZERO_TOKEN_SECURITY_NET and _abl != 'no_safety_net'),
        'compact_context': bool(COMPACT_THREE_PART_CONTEXT),
        'compression': _abl != 'no_compression', 'topk': _abl != 'no_topk'})
    print(f"  [DEBUG] vul_type={vul_type} tokens={tokens_used} conclusion_preview={conclusion[:100]}")
    if return_details:
        return {"prediction": result, "conclusion": conclusion, "tokens_used": tokens_used,
                "arbitrate": arb_record, "vulnerability_type": vul_type,
                "reasoning_steps": reasoning_result.get("steps"),
                "reduction_stats": SG.graph.get("reduction_stats", {}),
                "orig_nodes": len(G), "compressed_nodes": len(SG),
                "paths_analyzed": len(topk),
                "module_audit": reasoning_result.get("module_audit", {})}
    return (result, conclusion, tokens_used, arb_record)
