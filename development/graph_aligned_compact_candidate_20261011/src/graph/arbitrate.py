"""v19 图特征仲裁层：分歧时信受限局部精审。

背景（三批实证）：
  - v13-v18 六版证据层改进均未突破 A 基线锁死的天花板（A 51/55/51，
    B 62/51/52，批噪声 ±5 内无真实增益）；
  - "把守卫证据喂给 LLM" 框架三次证伪（v15 SAFE / v15 复现 / v18
    GUARD-DOM：FP↓ 必然 FN↑，idx=24383 判词直接引用 "dominat" 当良性
    依据）；
  - 根因 = LLM 自由推理时判不好守卫充分性（r2 FN 11/11 + v18 FN 17/17
    被守卫说服）。

v19 机制（离线试点 _v19_pilot.json 验证，46 sink 样本跨 v18+r2 两批）：
  1. 图计算结构事实（guard_dom_pairs：sink + 支配链上数据流对齐守卫），
     **不进 Step1 上下文**；
  2. 主推理（自由形式）出预测后，仅对有 sink 的样本发一次极简审计
     prompt：只给守卫代码 + sink 代码对，二元提问（有守卫问
     SUFFICIENT/INSUFFICIENT，无守卫问 DANGEROUS/SAFE）；
  3. 精审与主判断**分歧**时采纳精审（P1 双向翻转）。

试点依据：分歧区 12 样本精审命中 10/12 = 83%（主判断仅 2/12）；P1 模拟
两批一致 +4 Acc（v18 52→56 / r2 51→55），触发率 6%/批 × 118 tok ≈
批均 +7 tok。风险声明：46 样本内选策略存在过拟合风险，正式结论需
v19 新批验证。

判别力不对称（试点实测）：精审判漏洞准（真漏洞 69-91% 命中 INSUF/
DANGER），判良性差（真正良仅 17-38% 命中 SUF/SAFE）——仲裁的价值
主要在分歧区的方向修正，不是独立分类器。
"""
import time

AUDIT_SYSTEM = ("You are a precise C code security auditor. "
                "Answer with exactly one word as instructed.")

PROMPT_GUARD = """Security audit of one check in C code.

SINK (dangerous operation):
{sink}

GUARD (check that dominates this sink in the control flow):
{guard}

Question: does the guard fully prevent the dangerous outcome of the sink?
Answer exactly one word: SUFFICIENT or INSUFFICIENT."""

PROMPT_NOGUARD = """Security audit of one operation in C code.

SINK (dangerous operation):
{sink}

No guard dominates this sink on the control flow path.

Question: is this operation dangerous?
Answer exactly one word: DANGEROUS or SAFE."""


def _audit_verdict(client, sink: str, guard, model: str) -> tuple:
    """受限二元审计：返回 (verdict 0/1/None, tokens)。None=解析失败。"""
    sink = sink[:300]
    prompt = (PROMPT_GUARD.format(sink=sink, guard=guard[:300]) if guard
              else PROMPT_NOGUARD.format(sink=sink))
    for _ in range(3):
        try:
            r = client.chat.completions.create(
                model=model,
                messages=[{"role": "system", "content": AUDIT_SYSTEM},
                          {"role": "user", "content": prompt}],
                temperature=0.0, max_tokens=10)
            ans = (r.choices[0].message.content or "").strip().upper()
            tok = r.usage.total_tokens if r.usage else 0
            if "INSUFFICIENT" in ans or "DANGEROUS" in ans:
                return 1, tok
            if "SUFFICIENT" in ans or "SAFE" in ans:
                return 0, tok
            return None, tok  # 格式不符，不重试（temperature=0 确定性）
        except Exception:
            time.sleep(2)
    return None, 0


def arbitrate(path_graph, topk_paths, b_pred: int, client,
              model: str = None) -> tuple:
    """图特征仲裁：分歧时信受限局部精审（P1 双向翻转）。

    参数：
        path_graph: 与路径同源的图对象（SG 或 G）
        topk_paths: Top-K 路径（sink 排序优先级）
        b_pred: 主推理预测（0/1）
        client: OpenAI 兼容客户端
    返回：
        (final_pred, audit_tokens, audit_note, audit_info)
        audit_note 为空串 = 未触发；否则记录翻转信息供归因。
        audit_info = {"triggered": bool, "verdict": 0/1/None}——v20 结构化
        持久化用（v19 缺陷：FLIP 只混在 raw_answer 自由文本 + 日志里，
        归因需日志对齐还原；全集规模必须由 JSON 自带结构化字段）。
    """
    if b_pred is None or client is None:
        return b_pred, 0, "", {"triggered": False, "verdict": None}
    try:
        from graph.guard_dom import guard_dom_pairs
        pairs = guard_dom_pairs(path_graph, topk_paths)
    except Exception as e:
        return b_pred, 0, f"[Arbitrate] pairs 计算失败: {e}", \
            {"triggered": False, "verdict": None}
    if not pairs:
        return b_pred, 0, "", {"triggered": False, "verdict": None}  # 无 sink：不仲裁

    if model is None:
        from config import LLM_MODEL
        model = LLM_MODEL
    sink, guard = pairs[0]
    verdict, tok = _audit_verdict(client, sink, guard, model)
    info = {"triggered": True, "verdict": verdict}
    if verdict is None or verdict == b_pred:
        return b_pred, tok, (f"[Arbitrate] confirm (audit={verdict})" if verdict is not None else ""), info

    # 分歧 → 采纳精审（试点：分歧区精审 83% vs 主判断 17%）
    note = (f"[Arbitrate] FLIP {b_pred}->{verdict} "
            f"(guard={'Y' if guard else 'n'} sink={sink[:40]})")
    return verdict, tok, note, info
