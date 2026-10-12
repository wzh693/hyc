# 非对称证据负担契约 1016 付费批次 FINDINGS（2026-10-12）

## 一句话结论

非对称契约候选（asymmetric_bounds_candidate_20261012）未通过质量门槛：4 项门槛仅
fp_not_worse_both 通过，exploratory_support=False，保持 foundation 冻结、候选 OFF。
但相对 verdict-first 候选，机制假设获得部分验证：非对称负担 + 受控次步使 recall 从
.07 恢复到 .21/.24（TP 9→27/31）、FP 稳定 13/13、截断通道保持归零。失败根源进一步
下移并被本批次证伪性定位：模型层良性偏置对证据不敏感——挑战步在全源码 + 标注 DEP
路径条件下 0/89 次改判类型。

## 批次配置与完整性

- 254 SVEN 行 × 双臂（control=冻结 foundation，asym=非对称契约）× 双重复 = 1016 行
- DeepSeek https://api.deepseek.com/v1，请求 deepseek-chat，实际全部返回 deepseek-flash，
  max_tokens=150，temperature=0，max 2 steps / 3 attempts per step
- 授权：Human approved asymmetric-bounds full254x2x2 single batch 2026-10-12（本对话
  显式"可以"），已消耗，一次消耗不重跑
- 冻结链全过：SHADOW 508 双臂 preflight → 1016 mock（1354 mock 请求 = control 508 +
  asym 846）→ 付费批次；运行期逐字节快照（code/control/tooling）与 prepare() 复核通过
- 实际调用 1107 次（control 255+255，asym 297+300），0 错误 / 0 未知用量，
  949,998 tokens，全部 deepseek-flash
- functional_gate=True（1016 行 0 errors / 0 uncertain / 单一实际模型）

## 主结果

| 指标 | control/r1 | asym/r1 | control/r2 | asym/r2 |
|---|---|---|---|---|
| TP | 79 | 27 | 70 | 31 |
| TN | 66 | 112 | 62 | 112 |
| FP | 59 | 13 | 63 | 13 |
| FN | 50 | 102 | 59 | 98 |
| F1 | .5918 | .3195 | .5344 | .3584 |
| Accuracy | .5709 | .5472 | .5197 | .5630 |
| Precision | .5725 | .6750 | .5263 | .7045 |
| Recall | .6124 | .2093 | .5426 | .2403 |
| MCC | .1409 | .1445 | .0387 | .1801 |

- always_positive 常量基线：F1 .6736（Acc .5079）
- 门槛判定：fp_not_worse_both PASS（13≤59/63）；global_nonnegative_both FAIL；
  global_intervals_positive FAIL（F1 delta -.272，CI95 [-.469, -.068]；FP delta
  -46，CI95 [-71, -24]）；beats_constant_both FAIL（.32/.36 < .6736）
- 重复间预测分歧：control 57 vs asym 18（契约收紧使模型行为更稳定）
- 输入变化分解（changed_first_input=254 行，SYSTEM 段差异）：r1 预测差异 106 行
  （gained 50 / lost 56）；r2 差异 109 行（gained 60 / lost 49）

## 机制分析（508 asym 行合计）

1. 截断通道完全消除：asym length_calls = 0/597；control 244/510（≈96% 截断）。
   asym 平均 completion ≈40 tokens/调用，远离 150 上限（继承 verdict-first 结论，
   本批再次确认）。
2. step1 类型判定率 16.5%（84/508）vs verdict-first 批非良性回答率 5.7%：
   BOUNDS 义务把部分良性偏置推成了类型判定。84 个类型判定全部成为 pred1
   （TP58 + FP26），FP 13/13 全部来自该通道，precision .675/.70。
3. 良性回答 424/508（83.5%），其中 335（79.0%）附带了通过验证器的逐字守卫引用
   → benign_bounds_proven 单请求退出，构成 188 TN + 147 FN。核心发现：
   逐字守卫引用 ≠ 语义安全证明——漏洞函数中同样普遍存在含守卫 token 的真实代码
   行，验证器只能验证"引用是否逐字且形似守卫"，无法验证"引用是否真正覆盖风险
   sink"。200 个 FN 中 147 个（73.5%）经此通道流出，远高于设计预期
   （mock 场景仅假设 1/3 良性行即停，真实即停率达 79%）。
4. 挑战步 89 行：step1 良性且引用无效 → step2 FULL SRC + Prior 摘要 + Top-2
   带标签 DEP 路径。结果 0/89 改判类型，全部维持良性（36 TN + 53 FN）。
   温度 0 下模型层良性偏置对全源码级证据不敏感——证伪了"给足证据即可恢复
   recall"的假设，是本批次最核心的机制结论，也直接界定了 prompt/契约侧杠杆
   的天花板。
5. 审计标签偏差（不影响结论有效性）：挑战步终局的 stop_reason 实际为
   planner_stop（step2 良性回答内 ACTION Stop 先触发 planner 分支，早于
   expansion break），未按设计落盘 asymmetric_challenge_final，
   challenge_verdict 未记录。预测、请求数（597 = 508 + 89）、冻结不变量均不受
   影响。单元测试在循环层验证过四条终态路径，但未覆盖全管道中 planner 先行的
   路径顺序；后续若复活挑战步设计需先修此标签路径。
6. 对照臂自身漂移：control 本批 F1 .5918/.5344 vs verdict-first 批 .5964/.5639，
   重复间分歧 57（API 非确定性对长输出臂影响更大）；asym 分歧仅 18。

## 跨批对照（verdict-first 批为独立批次，仅作机制参照，非同批对照）

| | verdict-first（上批） | asym（本批） | control（本批） |
|---|---|---|---|
| TP | 9 | 27 / 31 | 79 / 70 |
| FP | 5 | 13 / 13 | 59 / 63 |
| FN | 120 | 102 / 98 | 50 / 59 |
| TN | 120 | 112 / 112 | 66 / 62 |
| F1 | .1259 | .3195 / .3584 | .5918 / .5344 |
| Recall | .07 | .21 / .24 | .61 / .54 |
| 截断率 | 0 | 0 | ≈96% |

- 相对 verdict-first：recall ×3、F1 ×2.5，FP 5→13（+8）但仍远低于 control；
  精度通道成果（截断归零、FP 受控、precision 上升）全部保持。
- 相对 control：FP -78%、TN 112 vs 66/62、precision +11~18pp、MCC 两重复均更高，
  但 recall 差距（.21/.24 vs .61/.54）使 F1 仍不及 control，更不及
  always-positive .6736。
- recall 天花板被 step1 类型率（16.5%）与挑战步 0 改判率（0/89）锁死：
  契约侧（输出格式 / 证据负担 / 次步挑战）已无进一步杠杆。

## 工程结论与下一步

- 契约侧候选链条（verdict-first → asymmetric-bounds）已系统性验证完毕：输出截断
  可完全消除、FP 可控、precision 可升，但 recall 受模型层良性偏置压制，且该偏置
  在温度 0 下对证据不敏感，无法靠 prompt 侧修复。
- 下一步（用户既定顺序）：检索侧增强候选。检索质量决定 step1 prompt 中证据的
  针对性与密度，或能在模型判定前提升类型率。注意：检索变更将破坏现有冻结
  topk 缓存机制，preflight 需重新设计 selection 不变量（不能沿用
  selection_drift=0 的双臂一致假设）。
- foundation 保持冻结；本候选保持 OFF；本授权已消耗，不重跑、不自动晋升。

## 原始数据

- 批次产物：output/asymmetric_bounds_llm_20261012/（report.json、results.jsonl、
  api_receipts.jsonl、code_snapshot/、control_snapshot/、tooling_snapshot/）
- 前置离线验证：output/asymmetric_bounds_preflight_20261012/（508 双臂）、
  output/asymmetric_bounds_runtime_mock_20261012/（1016 mock，1354 请求）
- 候选源码：development/asymmetric_bounds_candidate_20261012/src/（47 文件；
  相对 foundation 仅 2 文件差异：reasoning/prompts.py、reasoning/reasoning_loop.py）
- 工具链：evaluation/run_asymmetric_bounds_llm_20261012.py、
  evaluation/preflight_asymmetric_bounds_20261012.py、
  evaluation/test_asymmetric_bounds_20261012.py
