# Verdict-First Output Contract Candidate (2026-10-12)

## 动机

verdict_fidelity 批次（output/verdict_fidelity_llm_20261011）的截断归因分析
（evaluation/VERDICT_FIDELITY_LLM_FINDINGS_20261011.md 补充章节）：

- 987/1022 调用（96.6%）finish_reason=length，全部恰好 150 completion tokens；
- 734/981 截断首步回答缺 ACTION JSON（75%），planner 关键词兜底触发 493/508 行；
- 250/250 FP 的最终调用截断且漏洞关键词在 HYPOTHESIS 行内——漏洞假设 →
  Step1ConfirmStop 提前终止，模型没有机会完成缓解算术或 step-2 扩展；
- 201/211 FN = 良性 HYPOTHESIS + 截断——ACTION 被切导致证据扩展请求丢失；
- 对照：35 个完整调用全部判良性（30 TN + 5 FN），完整回答仅在"易"行发生。

根因是契约格式顺序：OBSERVATION→HYPOTHESIS→REASONING→ACTION 下，
判定存活但自我纠正与代理动作被切。判定放第一行 + 删除叙述行 +
ACTION 提到第二行，使决策与动作在 150-token 上限内永远存活。

## 改动范围（单变量：仅 SYSTEM 输出契约）

相对 development/type_coverage_reconstructed_20261008/src（对照臂，47 文件）
只改 2 个文件：

1. reasoning/prompts.py
   - SYSTEM_PROMPT 的 Format 段替换为两行契约（判定先行）：
     ```
     Format: answer with exactly these two lines and nothing else
     VERDICT: <one type, or "no vulnerability detected", or "uncertain">
     ACTION: {"action":"ExpandDFG|ExpandCFG|ExpandCALL|RetrieveAlias|CheckReachability|SummarizeEvidence|Stop","reason":"at most 32 ASCII chars"}
     ```
     首行（角色/类型/启发式警告）逐字节不变；"Format:" 行首保留使
     split 派生常量（COMPACT/BOUNDED，均为 off 路径）不变。
   - _summarize_prior：提取 VERDICT（兼容 HYPOTHESIS 回退）+ ACTION 行，
     替代原 HYPOTHESIS+REASONING 字段；预算 60/65 字符不变。
2. reasoning/reasoning_loop.py（4 处正则，词表/阈值/流程逻辑零变化）
   - L237 fields_ok 判定行匹配 `(?:VERDICT|HYPOTHESIS)`
   - L425 Uncertain 检测行匹配对齐
   - L531 _conclusion_is_benign 判定行匹配对齐
   - L548 _extract_vulnerability_type 判定行匹配对齐

其余 45 文件（pipeline/图压缩/检索/Top-K/typed_paths/planner/llm_api/config）
与对照逐字节一致。BOUNDED_OUTPUT_CONTRACT/COMPACT_VERDICT_PROMPT 等
off 路径行为不变；max_tokens=150、temperature=0、model、步数/尝试上限
全部冻结。

## 设计原则

- 判定先行：决策行第一行，150 上限内永远存活；截断只损失无关文本。
- 三态保留：`uncertain` 判定不触发 Step1ConfirmStop（非具体类型），
  自动获得 step-2 扩展机会，对冲果断良性偏见（完整调用 5/35 FN）。
- 不引入弃权：保持 type_coverage 解码哲学（解析可见文本，不因
  finish_reason=length 弃权）——display-first 血统的严格 JSON+length
  弃权曾致 949/1016 弃权、全门槛崩。
- ACTION 次行：恢复模型意图动作（57% 可解析 ACTION 的截断回答想要
  证据扩展），planner 兜底退回真正的兜底角色。
- 字节预算背书：compact-output preflight 实测 Stop JSON 112-116B、
  Query 200-236B（含 reason）≈ 40-80 tokens，150 限内 2-4 倍余量。

## 验证阶梯（全部离线先行）

1. evaluation/test_verdict_first_20261012.py 单元测试；
2. 508 行双臂离线 preflight（request 差异须全部落在 SYSTEM 段，
   user 消息逐字节一致，selection_drift=0）；
3. 1016 mock 运行时 preflight；
4. 真实 1016 批次需另行明确付费授权（本候选不自带授权）。

## 已知风险

- 模型契约遵守率只有真实付费批次可测（mock 不证明）；
- 判定先行可能强化过早承诺；三态 uncertain 与 step-2 扩展是对冲；
- reason ≤32 ASCII 是提示约束，无运行时截断/修复。
