# VERDICT_FIRST_LLM_FINDINGS_20261012

verdict_first_candidate_20261012(输出契约判定先行)vs 冻结 foundation,
SVEN 254×双臂×双重复=1016 结果,DeepSeek(deepseek-flash),max_tokens=150,
temperature=0。授权:Human approved verdict-first full254x2x2 single batch
2026-10-12(一次消耗,不重跑)。

## 批次完整性

- 1018 实际调用(control r1 256 含 2 次 step-2 重试,其余 254×3),
  0 错误 / 0 HTTP 失败 / 0 unknown usage,单一模型 deepseek-flash,826,917 tokens;
- functional_gate PASS(双臂双重复全分母、无 uncertain 行);
- 双臂 user 消息逐字节一致(mock preflight user_message_drift=0),差异仅 SYSTEM 契约段;
- 输出目录 output/verdict_first_llm_20261012(代码/工具快照三份入档)。

## 主指标

| 臂/重复 | F1 | Acc | Prec | Rec | MCC | FP | FN | TP | TN |
|---|---|---|---|---|---|---|---|---|---|
| control/r1 | .5964 | .5630 | .5616 | .6357 | .1251 | 64 | 47 | 82 | 61 |
| control/r2 | .5639 | .5433 | .5474 | .5814 | .0857 | 62 | 54 | 75 | 63 |
| verdict/r1 | .1259 | .5079 | .6429 | .0698 | .0652 | **5** | 120 | 9 | 120 |
| verdict/r2 | .1259 | .5079 | .6429 | .0698 | .0652 | **5** | 120 | 9 | 120 |

常量基线:always_positive F1=.6736/Acc=.5079;always_negative F1=0/Acc=.4921。
verdict 臂 Acc(50.79%)与 always_positive 持平、F1 远低;control 亦不敌
always_positive F1。

## 门槛判定(4 诊断门槛仅 1 过)

- fp_not_worse_both: **PASS**(5≤64、5≤62;delta CI95 [-94,-29],稳健);
- global_nonnegative_both: FAIL(F1 -0.4705、Acc -0.0551 双重复);
- global_intervals_positive: FAIL(F1 CI95 [-0.643,-0.272] 全负);
- beats_constant_both: FAIL。
- exploratory_support=FALSE → **候选不晋级,保持冻结 OFF;无激活/重跑/上传**。

## 机制发现

1. **截断通道被完全消除(设计目标 100% 达成)**:length_calls control
   248/256+242/254(≈96.5%,与 FINDINGS_20261011 归因一致)→ verdict
   **0/508**;契约遵从率 508/508(每条回答均有 VERDICT 行),两步调用消失
   (control 有 2 次 step-2,verdict 全部单步);每行 tokens 881/874→751(-15%)。
2. **FP 通道假设证实**:FP 64/62→5/5(-92%),precision .56→.64。原批次
   250/250 FP 来自被截断的漏洞 HYPOTHESIS 行;消除截断即消除该通道。
3. **FN 机制假设证伪(本批次核心教训)**:原假设 FN 95% 源于"良性
   HYPOTHESIS 被截断且 ACTION 丢失"。实际:给模型完整输出空间后,479/508
   (94.3%)的调用明确输出 "no vulnerability detected"(类型判定 28 条:
   integer overflow 18 / buffer overflow 10,uncertain 1),FN 反而
   47/54→120/120。**截断并未掩盖真实检出**——control 的 recall(.64/.58)
   主要由 Step1ConfirmStop、planner 兜底、图危险信号等机械放大通道贡献,
   它们同时制造 TP 与 FP;干净两行输出绕过兜底,暴露模型层判断极度保守。
4. **确定性效应**:双重复预测分歧 control 45 → verdict 2,r1/r2 指标完全
   相同;temperature=0+紧契约≈确定性输出(重复失去方差信息)。
5. **变化归因**:changed_first_input=254/254(SYSTEM 契约全行生效);
   r1 净正确 -14(60 得/74 失),r2 净 -9(57 得/66 失)。

## 结论与指导

- 契约收紧是成功的工程手段(截断 0%、FP -92%、确定性、-15% token),
  但单变量净效应为 F1 崩塌;根因在模型层保守偏置,不在解析层。
- 该候选结论:verdict line 保留价值成立(FP 通道证据),但**单独收紧
  输出契约不可行**;后续候选若走此方向需非对称设计(判定先行+受控次步
  证据字段,或检索侧提升证据密度说服模型),不得依赖兜底机械放大。
- 授权已消耗;本批次为最终记录,无重跑。
