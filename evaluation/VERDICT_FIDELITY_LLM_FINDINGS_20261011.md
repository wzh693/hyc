# 判定保真修复全量LLM开发对照

状态：COMPLETE。真实单批 1016 计划结果全部执行完毕，0 结果错误、0 HTTP 失败、
0 未知 usage；functional_gate 通过。2026-10-11（Asia/Shanghai）；本批付费授权已消耗。
完整性/账目审计通过不等于质量门槛通过；四项开发门槛中仅 FP 门槛通过。

## 当前决定

保留冻结基础，verdict_fidelity 候选继续 OFF，不推广、不上传 GitHub、不自动重跑。
FP 通道按修复目标方向改善（双重复 FP 67→60 / 63→60，TN 58→65 / 62→65，
Accuracy 双重复上升），但全部差异的家族 bootstrap CI95 均跨 0，不能声称统计显著；
F1 双重复一个 -0.09pp 一个 +0.64pp，方向不一致。这是已曝光 SVEN 开发对照，
不是独立论文测试，也不是单组件因果消融。

## 候选内容回顾（相对冻结 foundation 的唯一差异）

1. BUG-A `_extract_vulnerability_type` 无 HYPOTHESIS 行分支补齐不确定性/良性短语；
2. BUG-B `_conclusion_is_benign` 补 `_has_benign_word`；
3. BUG-C `parse_binary_verdict` 良性短语表与 `_BENIGN_DEFINITE` 对齐；
4. BUG-D `_slice_source` 注释剥离（含跨行 /* */、字符串字面量豁免）。
检索/图压缩/Top-K 与 foundation 逐字节一致（preflight selection_drift=0）。

## 全量指标（254 条/臂/重复）

| 重复 | 基础F1 | 候选F1 | 基础Acc | 候选Acc | 基础FP | 候选FP | 基础MCC | 候选MCC |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 57.45% | 57.36% | 53.94% | 55.51% | 67 | 60 | 0.077 | 0.109 |
| 2 | 56.18% | 56.82% | 53.94% | 55.12% | 63 | 60 | 0.078 | 0.102 |

- 全局家族 bootstrap（重复池化）：F1 差异 -0.10pp，CI95 [-6.63, +6.06]；
  Accuracy 差异 +1.57pp，CI95 [-5.17, +8.16]；FP 差异 -7，CI95 [-21, +5]。
  三区间均跨 0：点估计与门槛方向一致，统计上不显著。
- 全阳性参考 F1=67.36%（Acc 50.79%）；两臂双重复 F1 均低于该参考（数据集
  129 阳/125 阴的类别结构使然），MCC 双重复均为正（候选 0.109/0.102，
  基础 0.077/0.078）。
- 门槛：fp_not_worse_both 通过；global_nonnegative_both（F1 r1 -0.09pp）、
  global_intervals_positive、beats_constant_both 未通过。auto_promoted=false。

## 按CWE（F1，重复1/2）

| CWE（每重复分母） | 基础 | 候选 | 备注 |
| --- | ---: | ---: | --- |
| CWE-125（91） | 60.19% / 63.37% | 59.41% / 57.73% | 混合，略降 |
| CWE-190（70） | 65.17% / 60.67% | 68.29% / 68.29% | 双重复均升；FP 25→19、27→19；MCC 0.136→0.274 |
| CWE-416（93） | 45.78% / 41.56% | 43.90% / 44.71% | 混合 |

CWE-190（整数溢出）组获益最明确：良性词表统一把被误报的边界检查正确判为良性。

## 输入变化分解

- 53 行首轮输入改变（BUG-D 注释剥离改写 SRC 段）：重复1 预测差异 22
  （获益11/损失11），重复2 差异 21（获益10/损失11）——SRC 注释剥离本身
  净效应约中性。
- 201 行输入未变：重复1 差异 26（获益15/损失11），重复2 差异 36（获益20/损失16）
  ——这些差异来自 BUG-A/B/C 判定词表对相同输入下 LLM 回答的解释变化，
  净效应 +4/+4，即 FP 改善主要来自判定解析侧而非切片侧。
- 臂内重复间预测不一致：基础 36、候选 47（temperature=0 下 API 仍非确定），
  与既有批次一致；重复不是新增独立样本。

## 完整账目

- 1016 计划结果，1022 次实际 API 调用（255+254+256+257），全部成功；
  HTTP 失败 0、未知 usage 0、结果错误 0、Uncertain 0。
- 请求 deepseek-chat，实际 1022 次均返回 deepseek-flash（与既往批次一致）。
- 总 reported tokens=893,381（884.75/行）；987/1022 次调用 finish_reason=length，
  150-token 输出上限截断仍是主要瓶颈（96.6% 调用触顶，与既有批次同量级）。

## 工程修复与实际效果必须分开

- 4 项修复均经 21 项探针检查 + 15 项单元测试 + 66 文件进程隔离全量测试
  （含全部既有测试）+ 508 行双臂离线 preflight（selection_drift=0，
  unexpected_request_diff=0，53 行仅 SRC 段变化）+ 1016 mock 运行时验证后
  才进入付费批次；执行链路本身可信。
- preflight 曾对候选臂误报 "Training/model module imported"：根因是
  graph_window preflight 的检查假设候选退役训练分支，而本候选保留
  foundation 训练分支（pipeline.py 双臂逐字节一致，运行期导入
  learning.scorer 为两臂对称行为，不触发 torch）。该检查已按实验语义移除
  并在协议文档记录；不改变任何候选源码。
- 质量结论：FP 通道修复方向正确但幅度小、不显著；F1 平坦。词表修复
  单独不足以把该管线推过全阳性参考线。

## 下一步建议（未实施、未授权新付费批次）

1. 输出截断是当前最大瓶颈（96.6% 调用 length 触顶）：下一候选应优先收紧
   输出契约（更短的 HYPOTHESIS/REASONING 叙述格式），而不是继续扩词表。
2. 判定词表修复的净效应集中在判定解析侧（+4/+4）；如继续该方向，
   需对 53 行 SRC 变化样本与 201 行不变样本分别做误例逐条审查，确认
   注释剥离未引入新的证据缺失。
3. 不建议在此基础上叠加更多良性短语——r1 已出现 TP 79→76 的代价，
   良性词表扩张对 TP/FN 的边际风险在上升。

## 截断归因补充分析（2026-10-11，事后离线分析）

复算脚本：evaluation/_analyze_truncation_20261011.py、
_analyze_truncation2_20261011.py（数据源为本批 1016 结果 + 1022 回执）。

- 截断形态：987/1022 调用 finish_reason=length，completion_tokens 全部
  恰为 150（硬顶）；734/981 截断的首步回答缺 ACTION JSON（75%）；
  HYPOTHESIS 行出现前已花掉中位 204 字符。
- FP 通道：250/250（100%）FP 的最终调用截断且漏洞关键词就在 HYPOTHESIS
  行内——机制为"漏洞 HYPOTHESIS → 具体类型 → Step1ConfirmStop 提前终止"
  （control 臂 225/508 行=44% 走此路径），模型没有机会在 REASONING 完成
  缓解措施算术（idx=134 例：边界乘积算到一半被切）也没有 step-2 扩展。
- FN 通道：201/211（95%）FN = 良性 HYPOTHESIS + 截断；ACTION 被切 →
  无法请求证据扩展（能给出 ACTION 的 247 个截断回答中 85/149 想要扩展：
  ExpandDFG 60、ExpandCALL 16、ExpandCFG 6 等）。
- 对照：完整（stop）调用仅 35/1016（3.4%），全部判良性，30 TN + 5 FN + 0 FP。
- 代理退化：planner 关键词兜底触发 493/508 行（control）——模型意图动作
  在绝大多数行里被兜底替代。
- 敏感性：若截断修复使 30% 的 FP 经自我纠正转良性，汇总 F1 由 56.96%
  升至约 59.2%（+2.3pp；假设性边界，非承诺）。

## 收紧输出契约建议（下一单变量候选，未实施）

格式（判定先行、去叙述、ACTION 次行、三态保留）：

```
VERDICT: <type | "no vulnerability detected" | "uncertain">
ACTION: {"action":"ExpandDFG|ExpandCFG|ExpandCALL|RetrieveAlias|CheckReachability|SummarizeEvidence|Stop","reason":"<=32 ASCII chars"}
```

- 设计依据：当前契约 OBSERVATION→HYPOTHESIS→REASONING→ACTION 顺序下，
  判定存活但自我纠正（REASONING 算术）与代理动作（ACTION）75% 被切；
  判定放第一行则 150 上限内永远存活。字节预算有 compact-output preflight
  实测背书（Stop JSON 112-116B、Query 200-236B ≈ 40-80 tokens）。
- 改动范围仅两处：SYSTEM prompt Format 段 + reasoning_loop.py 行匹配
  （HYPOTHESIS: → VERDICT: 等价改写，词表逻辑不动）；其余 45 文件冻结。
- 解码哲学保持 type_coverage 血统（解析可见文本、不因 length 弃权）：
  display-first 血统的严格 JSON+length 弃权曾致 949/1016 弃权、全门槛崩。
- 三态 uncertain 保留，对冲"完整调用 5/35 FN"式果断良性偏见。
- 验证阶梯：单元测试 → 508 行双臂离线 preflight（request 差异应全部
  落在 SYSTEM 段）→ 1016 mock 运行时 → 新付费批次需另行授权。
- 风险：prompt-only 约束的模型真实合规率只有付费批次可测（mock 无法证明，
  compact-output FINDINGS 已声明此限制）；不要同时动 max_tokens=150 冻结。

## 证据位置

- output/verdict_fidelity_preflight_20261011：508 行双臂离线 preflight（通过）。
- output/verdict_fidelity_runtime_preflight_20261011：1016 mock 运行时验证（通过）。
- output/verdict_fidelity_llm_20261011：真实批次原始结果、请求/回答、usage、
  冻结快照、report.json（指标/门槛/bootstrap/输入分解）。
- evaluation/VERDICT_FIDELITY_LLM_PROTOCOL_20261011.md：本批协议。
