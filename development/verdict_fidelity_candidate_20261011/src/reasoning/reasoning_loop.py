"""
受限漏洞推理主循环 (Constraint-Guided Vulnerability Reasoning Loop)。

五阶段状态机:
  阶段1: 漏洞类型假设
  阶段2: 数据传播分析 (ExpandDFG)
  阶段3: 控制流可达性验证 (ExpandCFG)
  阶段4: 危险操作关联分析 (ExpandCALL / RetrieveAlias)
  阶段5: 漏洞结论生成 (SummarizeEvidence)

核心创新: LLM 不直接执行图遍历，而是通过预定义动作集合
与底层 GraphEngine 交互，实现稳定且可解释的多跳漏洞分析。
"""

import re
import networkx as nx
from config import MAX_REASONING_STEPS, DANGEROUS_APIS, BACKSTOP_SINK_APIS
from graph.graph_engine import GraphEngine
from linearization.typed_paths import build_hierarchical_context
from planning.state_memory import ProgramState
from planning.planner import RetrievalPlanner
from reasoning.llm_api import query_llm_with_retry
from reasoning.prompts import build_user_prompt
from reasoning.explanation import generate_explanation

# v10: 兜底信号专用"写型 sink"调用模式（语义分层）
# 完整 DANGEROUS_APIS 中的 free/alloc 族、转换、污点源不参与信号判定
# （离线验证：弱信号兜底样本 5 FP + 1 TP，写型 sink 组 7 TP + 2 FP）
_SINK_CALL_RE = re.compile(
    r"\b(" + "|".join(sorted(BACKSTOP_SINK_APIS, key=len, reverse=True)) + r")\s*\("
)

# 'safe' 词边界 + 排除 'not safe'：子串匹配会把 "no clear unsafe sink"
# （unsafe 含 safe）/ "not safe" 误判良性（v7 教训）。模块级供
# _extract_vulnerability_type 与 run_vuln_detection 共用（BUG-07）。
_SAFE_RE = re.compile(r'(?<!not )\bsafe\b')

# BUG-18（审查报告）：'correct'/'properly' 同样需词边界 + 否定前缀排除
# ——"incorrectly validated" 含 "correct"、"improperly" 含 "properly"，
# 子串匹配会把真实漏洞表述误判良性
_BENIGN_WORD_RES = (
    re.compile(r'(?<!in)\bcorrect(?:ly)?\b'),
    re.compile(r'(?<!im)\bproperly\b'),
)


def parse_binary_verdict(answer: str):
    """Parse an explicit binary LLM verdict. Return 0/1, or None if ambiguous."""
    raw = (answer or "").strip().lower()
    explicit = re.search(r'\bvulnerability\s*:\s*(yes|no)\b', raw)
    if explicit:
        return 1 if explicit.group(1) == "yes" else 0
    if raw in {"yes", "vulnerable"}:
        return 1
    if raw in {"no", "benign", "safe"}:
        return 0
    # BUG-C 修复(20261011 审查): 良性短语表与 _BENIGN_DEFINITE 对齐,
    # 补齐 "no security"/"no exploit"/"no risk"(此前仅 "no security issue")
    benign = any(p in raw for p in (
        "not vulnerable", "no vulnerability", "benign", "does not contain",
        "no security issue", "no issue", "no bug", "no security",
        "no exploit", "no risk",
    )) or _SAFE_RE.search(raw)
    vulnerable = bool(re.search(r'\bvulnerable\b', raw)) or any(
        p in raw for p in (
            "use-after-free", "use after free", "double free", "buffer overflow",
            "out-of-bounds", "out of bounds", "oob read", "oob write",
            "buffer over-read", "buffer overread", "integer overflow",
            "arithmetic overflow", "signed overflow", "null pointer dereference",
            "null deref", "memory leak",
        )
    ) or bool(re.search(r'\buaf\b', raw))
    if benign:
        return 0
    if vulnerable:
        return 1
    return None


def _has_benign_word(text: str) -> bool:
    return any(rx.search(text) for rx in _BENIGN_WORD_RES)


def _graph_danger_signal(G: nx.MultiDiGraph, paths: list) -> bool:
    """Top-K 证据路径上是否存在写型危险 sink 调用节点（图结构安全网）。

    v10 语义分层：仅写型 sink（memcpy/memset/strcpy/fprintf 等）触发；
    free/alloc 族、转换、污点源不再触发（离线交叉表验证：弱信号组
    兜底 FP:TP = 5:1，写型组 2:7）。
    """
    for path in (paths or []):
        for nid in path:
            code = G.nodes.get(nid, {}).get("code") or ""
            if _SINK_CALL_RE.search(code):
                return True
    return False


def _needs_evidence_expansion(output: str, action: str) -> bool:
    """Permit a bounded second pass only for a requested evidence gap."""
    if action not in {'ExpandDFG', 'ExpandCFG', 'ExpandCALL', 'RetrieveAlias', 'CheckReachability'}:
        return False
    return bool(re.search(
        r'error[- ]path|insufficient|incomplete|truncated|omitted|unclear|unknown|'
        r'not (?:shown|visible|established)|missing|need(?:s)? (?:more|to|additional)|cannot confirm|'
        r'no [^\n.;]{0,40}(?:shown|visible)|need(?:s)? (?:the )?(?:exit|free|allocation|alias|data|control|bounds|guard|ownership)\b',
        # Specific exit/free/guard evidence requests are also bounded gaps.
        output, re.I))


def reasoning_loop(
    G: nx.MultiDiGraph,
    initial_paths: list,
    function_code: str,
    function_summary: str,
    block_summaries: dict,
    client=None,
    use_prog_state: bool = True,
    use_adapt_plan: bool = True,
    use_hier_lin: bool = True,
    *, full_graph=None, max_steps=None, use_slice=None,
    use_output_contract=None, use_expansion=None, source_line_offset=0,
) -> dict:
    """
    受限漏洞推理主循环。

    参数:
        G: 压缩后的代码属性图
        initial_paths: Top-K 初始路径
        function_code: 源代码
        function_summary: 函数级摘要
        block_summaries: 基本块级摘要
        client: OpenAI 客户端
        use_prog_state: 是否注入程序状态记忆到 prompt（消融用）
        use_adapt_plan: 是否使用自适应规划（False=固定 CFG→DFG→CALL 顺序）
        use_hier_lin: 是否使用层次化线性化（False=扁平路径表示）
    返回:
        {
            "vulnerability_type": str,
            "conclusion": str,
            "evidence_paths": list,
            "program_state": ProgramState,
            "explanation": str,
            "steps": int,
        }
    """
    expansion_disabled = use_expansion is False
    from config import USE_BACKWARD_SLICE, BOUNDED_OUTPUT_CONTRACT, EVIDENCE_EXPANSION
    use_slice = USE_BACKWARD_SLICE if use_slice is None else use_slice
    use_output_contract = BOUNDED_OUTPUT_CONTRACT if use_output_contract is None else use_output_contract
    use_expansion = EVIDENCE_EXPANSION if use_expansion is None else use_expansion
    limit = MAX_REASONING_STEPS if max_steps is None else max_steps
    if not isinstance(limit, int) or not 1 <= limit <= 3:
        raise ValueError('max_steps must be between 1 and 3')
    context_graph = G
    evidence_graph = full_graph if full_graph is not None else G
    if use_expansion:
        G = evidence_graph
    engine = GraphEngine(G)
    audit = {'backward_slice': {'enabled': False}, 'output_contract': bool(use_output_contract),
             'expansion': {'enabled': bool(use_expansion), 'events': []},
             'stop_reason': 'step_limit', 'output_incomplete': False}
    source_evidence = None
    if use_slice and use_hier_lin:
        from linearization.backward_slice import backward_evidence_slice
        sliced, audit['backward_slice'] = backward_evidence_slice(
            evidence_graph, initial_paths, function_code, line_offset=source_line_offset,
            max_chars=min(1100, max(600, len(function_code) // 8)))
        source_evidence = sliced or None
    state = ProgramState()
    if use_prog_state:
        state.track_vars(function_code)
    planner = RetrievalPlanner()
    current_paths = list(initial_paths)
    all_evidence_paths = list(initial_paths)
    conclusion = ""
    latest_output = ""  # 最近一轮 LLM 输出（供增量 prompt 引用）
    vulnerability_type = "Unknown"
    total_tokens = 0
    trace = []
    step = 0
    no_vuln_streak = 0
    confirm_streak = 0
    last_vul_type = ""

    # 消融：层次化线性化 vs 扁平路径
    if use_hier_lin:
        initial_hierarchical_context = build_hierarchical_context(
            context_graph, function_code, function_summary, block_summaries, current_paths,
            include_state=use_prog_state,
            **({'source_evidence': source_evidence} if source_evidence is not None else {}),
        )
    else:
        # no_hier_lin：用扁平路径替代层次化上下文（仍走受限推理循环，
        # 与 no_constr_reason 的单次 LLM 调用形成对照）
        from linearization.typed_paths import _compact_path
        flat_parts = ["FLAT PATHS:"]
        for i, path in enumerate(current_paths[:5]):
            ps = _compact_path(G, path)
            if ps:
                flat_parts.append(f"P{i+1}: {ps}")
        flat_parts.append(f"\nFUNC SUMMARY: {function_summary}")
        initial_hierarchical_context = "\n".join(flat_parts)
    for step in range(1, limit + 1):
        print(f"\n{'='*50}")
        print(f"  Reasoning Step {step}/{limit}")
        print(f"{'='*50}")

        if step == 1:
            hierarchical_context = initial_hierarchical_context
        else:
            hierarchical_context = _build_incremental_context(
                G, current_paths, all_evidence_paths, step,
                **({'path_limit': 5} if use_expansion else {}),
            )
        # 消融 no_prog_state：不注入程序状态记忆到 prompt
        state_dump = state.dump() if use_prog_state else "(state memory disabled)"

        exploration_state = planner.get_exploration_state()
        evidence_summary = _summarize_evidence(all_evidence_paths, G)
        prompt = build_user_prompt(
            function_summary, hierarchical_context, state_dump, step,
            exploration_state=exploration_state,
            evidence_summary=evidence_summary,
            prev_conclusion=latest_output,
        )

        print("[LLM] 推理中...")
        from reasoning.llm_api import reset_call_metadata, get_call_metadata
        from reasoning.prompts import get_system_prompt
        from config import RECORD_REASONING_TRACE
        reset_call_metadata()
        result, step_tokens = (query_llm_with_retry(prompt, client, bounded_output=True)
                              if use_output_contract else query_llm_with_retry(prompt, client))
        receipt = {"step": step, "tokens_used": step_tokens, **get_call_metadata()}
        if RECORD_REASONING_TRACE:
            receipt.update({"system_prompt": get_system_prompt(prompt, bounded_output=use_output_contract),
                            "user_prompt": prompt, "answer": result})
        trace.append(receipt)
        fields_ok = bool(re.search(r'^\s*HYPOTHESIS:\s*\S', result, re.M | re.I)) and bool(
            re.search(r'ACTION:\s*\{[^}]*"action"\s*:\s*"[^"]+"[^}]*\}', result, re.I))
        if use_output_contract:
            import json
            action_match = re.search(r'ACTION:\s*(\{[^}]*\})', result, re.I)
            try:
                action_data = json.loads(action_match.group(1)) if action_match else {}
            except (ValueError, TypeError):
                action_data = {}
            fields_ok = fields_ok and bool(re.search(r'^\s*REASONING:\s*\S', result, re.M | re.I)) and (
                action_data.get('action') in {'Stop', 'ExpandDFG', 'ExpandCFG', 'ExpandCALL',
                                             'RetrieveAlias', 'CheckReachability'})
        receipt['output_fields_complete'] = fields_ok
        receipt['output_truncated'] = receipt.get('finish_reason') == 'length'
        incomplete = use_output_contract and not fields_ok
        audit['output_incomplete'] = audit['output_incomplete'] or incomplete
        total_tokens += step_tokens
        latest_output = result
        print(f"[LLM] 输出:\n{result[:500]}...")

        vul_type = 'Unknown' if incomplete else _extract_vulnerability_type(result, is_final=(step == limit))
        proposed_action = planner.decide_action(result) if use_adapt_plan else _fixed_plan_action(step)
        requested_gap = use_expansion and not incomplete and _needs_evidence_expansion(result, proposed_action)
        if requested_gap and use_adapt_plan:
            # Candidate routing requires an explicit, complete model request;
            # planner keyword fallback on a truncated answer is not authorization.
            import json
            explicit = re.search(r'ACTION:\s*(\{[^}]*\})', result, re.I)
            try:
                requested_action = json.loads(explicit.group(1)).get('action') if explicit else None
            except (ValueError, TypeError, AttributeError):
                requested_action = None
            requested_gap = requested_action == proposed_action
        if vul_type != "Unknown":
            vulnerability_type = vul_type
            no_vuln_streak = 0
            # 收敛检测：同一具体漏洞类型连续出现，视为结论已收敛
            if vul_type == last_vul_type and vul_type != "Generic Vulnerability":
                confirm_streak += 1
            else:
                confirm_streak = 1 if vul_type != "Generic Vulnerability" else 0
            last_vul_type = vul_type
        else:
            no_vuln_streak += 1
            confirm_streak = 0

        _update_program_state(state, result, G, current_paths, step)
        if incomplete:
            conclusion = result
            audit['stop_reason'] = 'incomplete_output'
            break

        # 图确认早停（v7）：Step1 已给出具体漏洞类型，且 Top-K 路径存在
        # 写型危险 sink 调用——LLM 假设与图结构证据双确认，跳过 Step2 验证。
        # 离线验证（v5 日志 × 危险信号表交叉）：13/94 样本早停，判定变化 0。
        # v10: 信号收窄为写型 sink——弱信号样本改跑 Step2（vulnerability_type
        # 已设定且仅被具体类型覆盖，标签不变，仅 token +1 步）。
        # v21（STEP1_CONFIRM_STOP）：去掉图信号前置条件——temperature=0 下
        # Step2 对同一上下文的"确认"是同义反复（v20 全量：1524 个 ConvergeStop
        # 样本确认后精度 45.4%，零过滤），纯冗余 token。消融可关。
        if step == 1 and vulnerability_type not in ("Unknown", "Generic Vulnerability"):
            from config import STEP1_CONFIRM_STOP
            if not requested_gap and (STEP1_CONFIRM_STOP or _graph_danger_signal(G, initial_paths)):
                tag = "GraphConfirmStop" if _graph_danger_signal(G, initial_paths) \
                    else "Step1ConfirmStop"
                print(f"[{tag}] Step1 具体类型 '{vulnerability_type}'，提前终止")
                conclusion = result
                audit['stop_reason'] = 'confirmed_first_step'
                break

        # 良性+写型危险信号跳步（v8）：Step1 判良性且写型 sink 信号命中时直接终止。
        # 标签中性证明：末尾兜底对 Unknown+信号必判漏洞——若 Step2 确认漏洞，
        # 结果同为 1；若 Step2 仍良性，兜底仍判 1。跳过 Step2 仅省 token。
        # v10: 弱信号（free/alloc/转换/污点源）不再跳步——此类信号兜底
        # FP:TP=5:1（离线验证），改跑 Step2 交 LLM 判定，不做兜底。
        from config import USE_ZERO_TOKEN_SECURITY_NET, F1_EVIDENCE_ROUTING
        if step == 1 and vul_type == "Unknown" and not USE_ZERO_TOKEN_SECURITY_NET \
                and _graph_danger_signal(G, initial_paths):
            print("[BenignSignalSkip] Step1 良性但图危险信号命中，跳步交兜底判定")
            conclusion = result
            break

        # 消融 no_adapt_plan：固定调度顺序 CFG→DFG→CALL，
        # 不依据 LLM 输出决策动作
        if use_adapt_plan:
            action = proposed_action
        else:
            action = _fixed_plan_action(step)
        print(f"[Planner] 下一步动作: {action}")
        if expansion_disabled:
            conclusion = result
            audit['stop_reason'] = 'expansion_ablation'
            break

        # 低-token选择性二轮：绝大多数首轮良性结论直接结束；只有模型明确
        # 指出 error path 证据缺失，且下方 planner 也要求扩展时才继续。
        # 校准集上该不确定组漏洞率 4/5。它只是路由条件，不直接修改标签。
        if step == 1 and vul_type == "Unknown":
            from config import SELECTIVE_SECOND_PASS
            allow_second = (requested_gap if use_expansion else
                (_needs_evidence_expansion(result, action) if F1_EVIDENCE_ROUTING
                 else "error path" in result.lower()))
            if SELECTIVE_SECOND_PASS and not allow_second:
                print("[SelectiveStop] 无高收益 error-path 缺口，首轮终止")
                conclusion = result
                audit['stop_reason'] = 'no_requested_gap'
                break

        if incomplete:
            conclusion = result
            audit['stop_reason'] = 'incomplete_output'
            break
        if use_expansion and not requested_gap:
            conclusion = result
            audit['stop_reason'] = 'no_requested_gap'
            break

        if action == "Stop" or action == "SummarizeEvidence":
            audit['stop_reason'] = 'planner_stop'
            conclusion = result
            # 如果 LLM 主动停止但未给出明确漏洞类型，记录当前类型
            if vulnerability_type == "Unknown":
                vulnerability_type = vul_type
            break

        # 收敛即停：具体漏洞类型连续 2 步确认，后续步骤仅重复验证，节省 token
        if confirm_streak >= 2:
            print(f"[ConvergeStop] 漏洞类型 '{vulnerability_type}' 连续 {confirm_streak} 步确认，提前终止")
            conclusion = result
            break

        # 良性提前终止：连续 3 步无任何漏洞证据
        # （2 步即停会跳过第 3 步的换类型扩展，实测引入误报）
        if no_vuln_streak >= 3 and step >= 3:
            print(f"[EarlyStop] 连续 {no_vuln_streak} 步无漏洞证据，提前终止")
            conclusion = result
            break

        if step >= limit:
            break
        new_paths = _execute_action(engine, action, current_paths, G)
        if use_expansion:
            seen_paths = {tuple(p) for p in all_evidence_paths}
            new_paths = [p for p in _deduplicate_paths(new_paths) if tuple(p) not in seen_paths]
            if new_paths:
                from retrieval.retrieve_topk import retrieve_topk
                new_paths = retrieve_topk(G, new_paths)
            audit['expansion']['events'].append({'step': step, 'action': action,
                                                'new_paths': len(new_paths)})
            if not new_paths:
                conclusion = result
                audit['stop_reason'] = 'no_new_evidence'
                break
        if new_paths:
            current_paths = new_paths
            all_evidence_paths.extend(new_paths)
            if use_expansion and use_prog_state:
                _update_program_state(state, '', G, new_paths, step)

    # 循环耗尽（末步选了扩展动作、无任何 break）时 conclusion 保持空串——
    # 10617 翻转成 TP 后 raw_answer 仍为空的原因。回填最近一轮输出。
    # 行为不变性：末步提取已用 is_final=True 处理过同一文本，
    # 下方最终重检结果是幂等的，仅修复存储/解释的可见性。
    if not conclusion:
        conclusion = latest_output

    # 去重证据路径
    unique_paths = _deduplicate_paths(all_evidence_paths)

    # 最终判定：最终步结论优先（含良性改判覆盖历史漏洞类型）。
    # v16.1 修复：旧逻辑只在 Unknown 时重检——Step1 报漏洞、Step2 改判良性时
    # vulnerability_type 粘住旧类型（v16 实测 11/100 样本 LLM 最终判良性
    # 却被记为漏洞：5 FP + 6 "侥幸 TP"）。忠实呈现原则：LLM 最终判断
    # 无论漏洞/良性都必须覆盖历史累积（v12e 教训同构）。
    final_benign = False
    if conclusion:
        final_type = _extract_vulnerability_type(conclusion, is_final=True)
        if final_type != "Unknown":
            vulnerability_type = final_type
        elif _conclusion_is_benign(conclusion):
            # 最终步明确良性（"no vulnerability detected" 等）→ 覆盖历史
            # 漏洞类型，且下方的图信号兜底不得再翻转它
            final_benign = True
            vulnerability_type = "Unknown"

    if use_output_contract and trace and not trace[-1].get('output_fields_complete', False):
        vulnerability_type = 'Unknown'
    decision_status = ('Uncertain' if use_output_contract and (
        audit['output_incomplete'] or re.search(r'HYPOTHESIS:\s*Uncertain\b', conclusion, re.I))
        else ('Vulnerable' if vulnerability_type != 'Unknown' else 'Benign'))
    if decision_status == 'Uncertain':
        vulnerability_type = 'Unknown'

    # 图危险信号兜底（v5）：LLM 判良性/不确定，但 Top-K 证据路径上
    # 存在写型危险 sink 调用节点时，security-first 倾向报漏洞。
    # v10: 信号收窄为写型 sink——弱信号（free/alloc/转换/污点源）样本
    # 不再兜底，直接采用 LLM 判定（离线验证：弱信号兜底 FP:TP=5:1）。
    # v16.1: 最终步明确良性时跳过兜底（否则检索的危险路径必然把
    # 良性改判翻转回漏洞，最终结论形同虚设）。
    from config import USE_ZERO_TOKEN_SECURITY_NET
    if not USE_ZERO_TOKEN_SECURITY_NET and vulnerability_type == "Unknown" and not final_benign \
            and decision_status != 'Uncertain' \
            and _graph_danger_signal(G, initial_paths):
        print("[DangerSignal] LLM 判良性但 Top-K 路径含危险 sink 调用，兜底报漏洞")
        vulnerability_type = "Generic Vulnerability"

    # 生成漏洞解释
    explanation = generate_explanation(
        G, vulnerability_type, unique_paths[:15], state, conclusion
    )

    return {
        "vulnerability_type": vulnerability_type,
        "conclusion": conclusion,
        "evidence_paths": unique_paths[:15],
        "program_state": state,
        "explanation": explanation,
        "steps": step,
        "tokens_used": total_tokens,
        "trace": trace,
        "module_audit": audit,
        "decision_status": decision_status,
    }


# 消融 no_adapt_plan 的固定调度顺序：CFG → DFG → CALL → RetrieveAlias
# 按 step 递增轮转，不参考 LLM 输出
_FIXED_PLAN_SEQUENCE = ["ExpandCFG", "ExpandDFG", "ExpandCALL", "RetrieveAlias"]


def _fixed_plan_action(step: int) -> str:
    """消融 no_adapt_plan：返回固定调度动作（按步数轮转）。

    Step 1 的结果由调用方在进入此函数前已处理（step 从 1 起，
    此函数在 step>=1 的循环体末尾被调用决定下一步动作）。
    """
    idx = (step - 1) % len(_FIXED_PLAN_SEQUENCE)
    return _FIXED_PLAN_SEQUENCE[idx]


def _build_incremental_context(
    G: nx.MultiDiGraph,
    current_paths: list,
    all_evidence_paths: list,
    step: int,
    *, path_limit=1,
) -> str:
    """构建增量上下文：仅包含新增路径摘要，避免重复发送完整层次化上下文。

    v6: 改用 _compact_path 单行紧凑序列化（Top-2），路径证据本身保留，
    仅去除多行冗长格式的 token 冗余（多行版每步 ~900 tok → 紧凑版 ~300 tok）。
    v9: Top-1 恢复详细序列化（typed_dependency_path，带节点级安全标签
    SINK/SOURCE/ALLOC/FREE）——v8 的 15 个 FN 全部在 Step2 判良性，
    紧凑单行证据太薄是主嫌疑；详细版仅用于最关键的 1 条，其余保持紧凑。
    v14: Top-1 由多行详细格式改为 _labeled_compact_path 单行带标签紧凑格式
    （节点级 SINK/SOURCE/ALLOC/FREE 标签保留 = v9 FN 恢复关键；单行 35 字符
    截断 = 纯格式压缩）。Top-2 紧凑路径移除。实测依据：v13 Step2 样本
    45/48 超 1043（Step2 均值 1479 vs Step1-only 911），详细序列化均值
    603ch 是主因；削减目标 = 削冗余不削证据。
    """
    from linearization.typed_paths import _labeled_compact_path, path_evidence_tags
    parts = [f"[Incremental Update - Step {step}]"]
    parts.append(f"New paths to analyze: {len(current_paths)}")
    for i, path in enumerate(current_paths[:path_limit]):
        path_str = _labeled_compact_path(G, path)
        if path_str:
            # v16：路径级证据头仅危险侧（BUG-19；v15 曾含 SAFE 守卫计数，
            # 安全锚点双刃剑，回退 B 方案）
            tags = path_evidence_tags(G, path)
            head = f" [{tags}]" if tags else ""
            rendered = path_str if path_limit == 1 else path_str[:100]
            parts.append(f"\nPath {i+1}{head}: {rendered}")
    if len(current_paths) > path_limit:
        parts.append(f"\n... and {len(current_paths) - path_limit} more paths (omitted for token efficiency)")
    return "\n".join(parts)


# v16.1: 明确良性表述（不含不确定性词）——只有这些才豁免图信号兜底；
# "insufficient evidence" 等不确定表述仍走兜底（v10 已校准 FP:TP=5:1，
# 扩大豁免范围会引入额外变量）
_BENIGN_DEFINITE = [
    "no vulnerability", "not vulnerable", "benign",
    "no issue", "no bug", "no security",
    "no exploit", "no risk", "does not contain",
]


def _conclusion_is_benign(llm_output: str) -> bool:
    """v16.1: 最终步 conclusion 是否明确判良性（HYPOTHESIS 行良性表述）。

    只认明确良性词（_BENIGN_DEFINITE）——用于区分"判良性"（不得被
    图信号兜底翻转）与"不确定"（仍可兜底，维持 v10 校准）。
    """
    import re
    m = re.search(r'HYPOTHESIS:\s*(.+?)(?:\n|$)', llm_output, re.IGNORECASE)
    if not m:
        return False
    h = m.group(1).strip().lower()
    # BUG-B 修复(20261011 审查): _extract_vulnerability_type 通过 _has_benign_word
    # 把 "correctly/properly ..." 类表述判为良性(Unknown),但本函数不认——
    # 两套良性词表不一致导致最终良性结论无法覆盖 Step1 漏洞类型(v16.1 部分残留)。
    # 此处补齐 _has_benign_word;不确定性短语仍不豁免(维持 v16.1 设计)。
    return (any(p in h for p in _BENIGN_DEFINITE) or _SAFE_RE.search(h) is not None
            or _has_benign_word(h))


def _extract_vulnerability_type(llm_output: str, is_final: bool = False) -> str:
    """从 LLM 输出中提取漏洞类型。

    策略：
      1. 先检查否定/良性表述 → Unknown
      2. 匹配具体漏洞类型关键词
      3. 若提到漏洞相关通用词汇且无否定 → Generic Vulnerability（避免漏报）
      4. 否则 Unknown
    """
    import re
    hypothesis_match = re.search(r'HYPOTHESIS:\s*(.+?)(?:\n|$)', llm_output, re.IGNORECASE)
    if not hypothesis_match:
        # 没有 HYPOTHESIS 行时，扫描整个输出
        # BUG-A 修复(20261011 审查): 补齐 HYPOTHESIS 分支已有的不确定性/
        # 良性短语,此前 "insufficient evidence to confirm vulnerability" 在
        # 无 HYPOTHESIS 行时落入通用词匹配返回 Generic Vulnerability(误报)
        text = llm_output.lower()
        if any(p in text for p in ["no vulnerability", "not vulnerable", "benign",
                                    "no issue", "no bug", "no security",
                                    "no exploit", "does not contain", "no evidence", "no risk",
                                    "unlikely", "insufficient evidence", "cannot confirm",
                                    "not confirmed", "no proof", "inconclusive"]) \
                or _SAFE_RE.search(text) or _has_benign_word(text):
            return "Unknown"
        if any(p in text for p in ["vulnerability", "vulnerable", "exploit", "security flaw",
                                    "memory corruption", "unsafe", "dangerous"]):
            return "Generic Vulnerability"
        return "Unknown"

    hypothesis = hypothesis_match.group(1).strip().lower()

    # 1. 否定/良性表述
    if any(phrase in hypothesis for phrase in [
        "no vulnerability", "not vulnerable", "benign",
        "no issue", "no bug", "no security",
        "no exploit", "no risk", "does not contain", "no evidence",
        "unlikely", "insufficient evidence", "cannot confirm",
        "not confirmed", "no proof", "inconclusive",
    ]) or _SAFE_RE.search(hypothesis) or _has_benign_word(hypothesis):
        return "Unknown"

    # 2. 具体漏洞类型（优先匹配，不受不确定性影响）
    # 注意与 SYSTEM_PROMPT 中的类型缩写词表保持一致：
    # prompt 教 LLM 说 "UAF"/"Null Deref"，提取器必须同词表匹配
    # （v6b 教训：idx=1127 输出 "Null Deref" 未被识别 → FN）
    if ("use-after-free" in hypothesis or "use after free" in hypothesis
            or re.search(r'\buaf\b', hypothesis)):
        return "Use-After-Free"
    if "double free" in hypothesis:
        return "Double Free"
    if ("out-of-bounds read" in hypothesis or "out of bounds read" in hypothesis
            or "oob read" in hypothesis or "buffer over-read" in hypothesis
            or "buffer overread" in hypothesis):
        return "Out-of-Bounds Read"
    if ("buffer overflow" in hypothesis or "out-of-bounds write" in hypothesis
            or "out of bounds write" in hypothesis or "oob write" in hypothesis):
        return "Buffer Overflow"
    if ("integer overflow" in hypothesis or "arithmetic overflow" in hypothesis
            or "signed overflow" in hypothesis or "integer wraparound" in hypothesis
            or "integer wrap-around" in hypothesis):
        return "Integer Overflow"
    if "taint" in hypothesis:
        return "Taint-style Vulnerability"
    if ("null pointer" in hypothesis or "null deref" in hypothesis
            or "null-deref" in hypothesis):
        return "Null Pointer Dereference"
    if "memory leak" in hypothesis:
        return "Memory Leak"

    # 3. 通用漏洞词汇（无具体类型但明确提到漏洞）
    generic_vuln_words = [
        "vulnerability", "vulnerable", "exploit", "security flaw",
        "memory corruption", "unsafe", "dangerous", "bug",
        "defect", "flaw", "hazard", "风险", "漏洞", "缺陷",
    ]
    if any(w in hypothesis for w in generic_vuln_words):
        return "Generic Vulnerability"

    # 4. 未检测到任何漏洞词汇时，才因不确定性拒绝
    uncertain_words = ["potential", "possible", "might", "could", "maybe", "suspect", "疑似", "可能"]
    has_uncertain = any(w in hypothesis for w in uncertain_words)
    if has_uncertain and not is_final:
        return "Unknown"

    return "Unknown"


def _execute_action(
    engine: GraphEngine,
    action: str,
    current_paths: list,
    G: nx.MultiDiGraph,
) -> list:
    """
    执行受限图动作，返回新的路径列表。
    """
    new_paths = []
    end_nodes = set()
    for path in current_paths:
        if path:
            end_nodes.add(path[-1])

    for node in sorted(end_nodes, key=str)[:15]:
        if action == "ExpandDFG":
            paths = engine.expand_dataflow(node, max_hop=6)
        elif action == "ExpandCFG":
            paths = engine.expand_controlflow(node, max_hop=6)
        elif action == "ExpandCALL":
            paths = engine.expand_call(node, max_hop=4)
        elif action == "RetrieveAlias":
            paths = engine.retrieve_alias(node, max_hop=4)
        elif action == "CheckReachability":
            for path in current_paths:
                if len(path) >= 2:
                    src, sink = path[0], path[-1]
                    if engine.check_reachability(src, sink):
                        found = engine.find_path(src, sink)
                        if found:
                            new_paths.append(found)
            return new_paths
        else:
            continue
        new_paths.extend(paths)

    print(f"[Action] {action}: 扩展出 {len(new_paths)} 条新路径")
    return new_paths[:20]


def _update_program_state(
    state: ProgramState,
    llm_output: str,
    G: nx.MultiDiGraph,
    paths: list,
    step: int,
):
    """
    基于 LLM 推理结果和当前路径，更新程序状态记忆。

    通过分析路径中的代码片段自动检测变量生命周期事件：
      - malloc/calloc/realloc -> allocated
      - free -> freed
      - recv/read/scanf/gets -> tainted
      - -> 或 * 操作 -> dereferenced
    """
    def record(var, event, nid):
        # 源码扫描已记录的事件比路径子集更完整；不要用同一语义的图事件
        # 再记一次，否则一次 free 会被误判为 double-free。
        if any(h["state"] == event and h.get("step") == 0
               for h in state.get_state(var)):
            return
        state.update(var, event, nid, step)

    for path in paths:
        for nid in path:
            code = G.nodes.get(nid, {}).get("code", "").lower()

            if "malloc" in code or "calloc" in code or "realloc" in code:
                var = _extract_var(code)
                if var:
                    record(var, "allocated", nid)

            if re.search(r'\b(?:free|av_free|av_freep|kfree|munmap)\b', code):
                var = _extract_var(code)
                if var:
                    record(var, "freed", nid)

            # BUG-17 修复：子串匹配 "read" 命中 thread/already/webvtt_read_header、
            # "gets" 命中 budgets/targets/widgets → 虚假 tainted 事件。
            # 改函数调用模式（词边界 + 括号）
            if re.search(r'\b(?:recv|read|scanf|gets)\s*\(', code):
                var = _extract_var(code)
                if var:
                    record(var, "tainted", nid)

            if "->" in code or ("*" in code and "*/" not in code):
                var = _extract_var(code)
                if var:
                    record(var, "dereferenced", nid)


def _extract_var(code: str) -> str:
    """从代码片段中提取变量名。"""
    patterns = [
        r'(?:free|av_free|av_freep|kfree|munmap|malloc|calloc|realloc|av_malloc|av_calloc|kmalloc|kzalloc)\s*\(\s*(\w+)',
        r'(\w+)\s*->',
        r'\*\s*(\w+)',
        r'(?:recv|read|scanf|recvfrom|recvmsg)\s*\([^,]*,\s*(\w+)',
    ]
    for pat in patterns:
        match = re.search(pat, code)
        if match:
            return match.group(1)
    return ""


def _deduplicate_paths(paths: list) -> list:
    """去重路径（基于路径的元组表示）。"""
    seen = set()
    unique = []
    for p in paths:
        key = tuple(p)
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique


def _summarize_evidence(paths: list, G) -> str:
    """
    汇总已收集的证据路径，供 LLM Agent 参考。
    """
    if not paths:
        return "  (no evidence collected yet)"
    unique = _deduplicate_paths(paths)
    lines = []
    for i, path in enumerate(unique[:10]):
        nodes_desc = []
        for nid in path[:5]:
            code = G.nodes.get(nid, {}).get("code", "?")[:40]
            nodes_desc.append(code)
        path_str = " -> ".join(nodes_desc)
        lines.append(f"  Path {i+1} (len={len(path)}): {path_str}")
    if len(unique) > 10:
        lines.append(f"  ... and {len(unique) - 10} more paths")
    return "\n".join(lines)


def run_vuln_detection(
    client,
    model: str,
    hierarchical_context: str,
    sample_id: str = "",
    temperature: float = 0.0,
    max_tokens: int = 512,
) -> int:
    """
    轻量级漏洞检测入口（供 main.py 的各模式统一调用）。

    将层次化上下文发送给 LLM，返回 0 (良性) 或 1 (有漏洞)。

    与 reasoning_loop 的区别：
      - reasoning_loop: 多轮受限推理状态机（论文核心创新，内部使用）
      - run_vuln_detection: 单次 LLM 调用包装器（对外统一接口）
    """
    prompt = f"""You are a C/C++ vulnerability detection expert. Analyze the following hierarchical code analysis context and determine if the code contains a vulnerability.

{hierarchical_context}

Based on the above context, does this code contain a vulnerability?
Answer ONLY: VULNERABLE or BENIGN"""

    try:
        if hasattr(client, 'chat') and hasattr(client.chat, 'completions'):
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=temperature,
                max_tokens=max_tokens,
            )
            answer = response.choices[0].message.content.strip()
            raw = answer.lower()
        else:
            answer, _ = query_llm_with_retry(prompt, client)
            answer = answer.strip()
            raw = answer.lower()

        # BUG-07 修复：裸子串 "safe" 会把 "the code is unsafe" 误判良性
        # （_extract_vulnerability_type 的 _SAFE_RE 同类 bug 在此入口复发）。
        # 词边界 + (?<!not ) 排除："unsafe" 不命中，"not safe" 交由
        # "not vulnerable"/"no vulnerability" 语义组以外的否定词处理。
        verdict = parse_binary_verdict(answer)
        if verdict == 1:
            snippet = answer[:120].replace('\n', ' ')
            print(f"  [VulnDetect] {sample_id}: VULNERABLE -> '{snippet}'")
            return 1
        if verdict == 0:
            snippet = answer[:120].replace('\n', ' ')
            print(f"  [VulnDetect] {sample_id}: BENIGN -> '{snippet}'")
            return 0
        raise ValueError(f"Ambiguous LLM verdict: {answer[:120]!r}")

    except Exception as e:
        print(f"  [VulnDetect] {sample_id}: 调用失败 ({e})")
        return None
