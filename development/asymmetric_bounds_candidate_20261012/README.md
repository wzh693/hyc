# asymmetric_bounds_candidate_20261012（非对称证据负担契约候选）

## 动机

verdict-first 批次（1016 次，DeepSeek，output/verdict_first_llm_20261012）证明：
两行判定先行契约完全消除输出截断（96.5%→0）并砍掉 92% 的 FP（64/62→5/5），
但 recall 从 .64/.58 崩塌至 .07——479/508（94.3%）的调用在干净输出空间下直接
回答 "no vulnerability detected"，暴露模型层强烈的良性偏置；control 的 recall
主要来自 Step1ConfirmStop/planner 兜底/图危险信号等机械放大通道（同时制造
TP 与 FP）。FINDINGS 结论：单独收紧输出契约不可行，后续需非对称设计
（判定先行 + 受控次步证据），不得依赖兜底机械放大。本候选即该方向。

## 设计：证据负担非对称

判定行（VERDICT 先行）保留；两判定路径的证据成本刻意不对称：

- **报漏洞**：与 verdict-first 相同——一行 VERDICT 类型 + 一行 ACTION 即可
  （该路径 FP 已被证明可控：5/5，precision .64）。
- **报良性/不确定**：必须额外给出 `BOUNDS:` 行，**逐字引用** SRC 中守卫该
  危险操作的源码行（边界/NULL/尺寸检查）。解析器验证引用：
  1. 归一化（去空白、小写）后，BOUNDS 文本中存在 ≥10 连续字符的源码逐字片段；
  2. 该片段含守卫 token（比较运算/if/while/for/NULL/sizeof/!ident 等）。
  裸 sink 行引用（非守卫）与自然语言转述（无法验证）均判无效。

**受控次步**：step1 非类型判定且 BOUNDS 引用无效时不终止，进入 step2 挑战——
完整函数源码（非切片；SVEN 254 样本 max 4656 字符，无截断）+ 前步判定摘要 +
Top-2 带标签 DEP 路径 + 显式要求："要么逐字引用守卫行证实良性，要么给出类型"。
step2 判定为终局。三条终态路径：

| step1 | BOUNDS | step2 | 终态 | 预测 |
|---|---|---|---|---|
| 类型 | — | — | Step1ConfirmStop（不变） | 1 |
| 良性/不确定 | 有效引用 | — | benign_bounds_proven（1 请求） | 0 |
| 良性/不确定 | 无效/缺失 | 良性（无论引用） | asymmetric_challenge_final（2 请求） | 0 |
| 良性/不确定 | 无效/缺失 | 类型 | asymmetric_challenge_final（2 请求） | 1 |

recall 恢复来源：(a) 负向断言的举证成本迫使模型真正检索守卫，找不到守卫时
倾向于改报类型；(b) step2 完整源码补足切片证据缺失。**无任何标签机械翻转**：
预测只来自模型自身 VERDICT 行；step2 良性即便引用仍无效也采信（次步的意义
是完整证据下的复查，不是新的放大通道）。安全网（zero_token，0→1 单向，
阈值 4）与两臂对称，保持不动。

## 最小差异（vs 冻结 foundation；谱系 = verdict-first 已验证改动 + 非对称增量）

仅 2 个文件：

1. `reasoning/prompts.py`：SYSTEM Format 段两行契约 → 加第三行 BOUNDS
   （Format 段之前的首行与 control 逐字节一致，TYPE_COVERAGE 替换不受影响）；
   新增 `build_bounds_challenge_prompt()`。其余继承 verdict-first
   （`_summarize_prior` 重写版等）。
2. `reasoning/reasoning_loop.py`：新增 `_BOUNDS_LINE_RE`/`_GUARD_FRAG_RE`/
   `_benign_bounds_valid()`；循环中 step1 非类型判定的三个分支（证引用即停/
   无引用 continue 进次步/次步终局审计）；`audit['asymmetric']` 记录
   step1 引用有效性、challenge_step、challenge_verdict、challenge_bounds_valid。
   其余继承 verdict-first。检索/图压缩/Top-K/pipeline 不动。

检索冻结不变量保持：step1 user 消息逐字节一致（首个请求与 control 仅 SYSTEM
段不同），topk/graph_sha256 双臂相同；step2 请求是新增调用，不参与冻结校验。

## 验证阶梯

1. 单元测试（隔离进程，~20 例）：契约格式、引用验证器（逐字/转述/sink 行/
   注释博弈/短引用）、循环集成（四条终态路径 + 请求计数 + challenge prompt 内容）。
2. 508 双臂离线 preflight（SHADOW 冻结）：mock 场景 idx%3 覆盖三条非类型终态
   路径 + 类型路径；不变量：0 错误、selection_drift=0、user_message_drift=0、
   system_contract_changes=254、请求计数符合场景、step2 含 FULL SRC。
3. 1016 mock 运行（--preflight-only）：冻结校验 + 双臂全分母 + 会计完整性。
4. 付费批次（需显式授权，一次消耗不重跑）。

## 成本与风险

- 成本：候选臂 step1 508 次必发生；无法给出有效引用的良性回答再付 step2
  （完整源码 prompt，~+200-800 tokens/次）。最坏全量挑战：~1.3M tokens
  （对照 verdict-first 批次 827k）；若多数良性能引用守卫则接近 90 万。
- FP 风险：举证负担可能诱发"为回避引用而报类型"——FP 从 5 回升的幅度是
  本批次要测的核心问题之一（门槛 fp_not_worse_both 保护下限）。
- FN 残留：模型引用真实但与 sink 无关的守卫行（如无关 NULL 检查）时，
  引用有效但语义空转——此类 FN 非本候选可解，留检索侧候选。
- 确定性：temperature=0 下双重复预期高度一致（同 verdict-first）。

## 门槛（与 verdict-first 同四门）

fp_not_worse_both / global_nonnegative_both / global_intervals_positive /
beats_constant_both；exploratory_support = functional ∧ 全部门通过。
不晋级即保持冻结 OFF，无激活/重跑/上传。
