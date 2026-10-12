# VERDICT_FIDELITY_LLM_PROTOCOL_20261011

单批付费评测协议:verdict_fidelity_candidate_20261011(候选) vs 冻结 foundation(对照),
SVEN 全 254 行 × 双臂 × 双重复 = 1016 计划结果,DeepSeek 端点,用户付费。

## 候选内容(相对冻结 foundation 的唯一差异)

1. **BUG-A** `reasoning/reasoning_loop.py` `_extract_vulnerability_type` 无 HYPOTHESIS 行
   回退分支补齐不确定性/良性短语("unlikely"/"insufficient evidence"/"cannot confirm"/
   "not confirmed"/"no proof"/"inconclusive"/"no exploit")。此前 "insufficient evidence
   to confirm vulnerability" 在该分支落入通用词匹配返回 Generic Vulnerability(误报)。
2. **BUG-B** `_conclusion_is_benign` 补齐 `_has_benign_word`(correctly/properly 类明确
   良性表述)。此前最终良性结论无法覆盖 Step1 漏洞类型(v16.1 部分残留,FP 源)。
3. **BUG-C** `parse_binary_verdict` 良性短语表与 `_BENIGN_DEFINITE` 对齐(补
   "no security"/"no exploit"/"no risk")。
4. **BUG-D** `linearization/typed_paths.py` `_slice_source` 先经 `_strip_c_comments_line`
   剥离注释(含行尾 //、行中与跨行 /* */,字符串字面量除外)再匹配 keep_pat。
   此前注释中提到的危险 API 会被当作代码证据注入 SRC 切片(误报注入通道)。

## 不变量(由 preflight 强制)

- 检索/topk/graph 与 foundation 完全一致(selection drift = 0);
- 双臂首请求差异仅允许出现在 user 消息 SRC 段(unexpected_request_diff = 0);
- foundation 47 文件哈希不变;
- 请求参数:model=deepseek-chat, max_tokens=150, temperature=0, 每步≤3次尝试, ≤2步。

注:graph_window preflight 的 "Training/model module imported" 检查不适用于本实验——
该实验候选退役了训练分支(learning 导入即漂移);本候选保留 foundation 训练分支,
pipeline.py 与对照逐字节一致,运行期导入 learning.scorer(不触发 torch,模型缺失时
回退启发式)是两臂对称的 foundation 行为,已由 selection_drift/request_diff 不变量覆盖。

## 门槛(诊断性,不自动晋级)

- global_nonnegative_both:候选 F1/Acc 双重复均 ≥ 对照;
- fp_not_worse_both:候选 FP 双重复均 ≤ 对照(修复目标为 FP 通道);
- global_intervals_positive:全局 F1/Acc 分组 bootstrap CI95 下界 > 0;
- beats_constant_both:候选双重复 F1/Acc > 总是预测漏洞基线且 MCC > 0。

## 已知限制

- SVEN 为本地已曝光开发集(含相关/冲突行),非独立最终测试;重复不是新样本;
- r1 区间为描述性,非因果/泛化证明;检索为冻结缓存,非速度基准;
- 无自动激活、无重跑、无锁定 Devign、无 GitHub 上传、无论文就绪声明。

## 授权

Human approved verdict-fidelity full254x2x2 single batch 2026-10-11(本次对话)。
