# VERDICT_FIRST_LLM_PROTOCOL_20261012

单批付费评测协议:verdict_first_candidate_20261012(候选) vs 冻结 foundation(对照),
SVEN 全 254 行 × 双臂 × 双重复 = 1016 计划结果,DeepSeek 端点,用户付费。

## 候选内容(相对冻结 foundation 的唯一差异,共 2 个文件)

1. **输出契约判定先行** `reasoning/prompts.py` SYSTEM_PROMPT Format 段改为两行契约:
   `VERDICT: <one type, or "no vulnerability detected", or "uncertain">`
   `ACTION: {"action":"...","reason":"at most 32 ASCII chars"}`
   动机:VERDICT_FIDELITY_LLM_FINDINGS_20261011 截断归因显示 96.6% 调用触顶
   150 tokens;FP 通道 = 漏洞 HYPOTHESIS 行截断后仍被按字面提取;FN 通道 = 良性
   HYPOTHESIS 被截断且 ACTION 丢失。判定先行保证判定行在 150 上限内永远存活。
2. **解析器双标签兼容** `reasoning/reasoning_loop.py` 4 处正则(fields_ok/
   Uncertain 检测/_conclusion_is_benign/_extract_vulnerability_type)接受
   VERDICT|HYPOTHESIS 双标签;词表、阈值、流程零变化。
3. **前步摘要重写** `reasoning/prompts.py` `_summarize_prior` 提取
   VERDICT(兼容 HYPOTHESIS 回退)+ ACTION 两字段,预算 60/65 字符,去叙述。

## 不变量(由 preflight 强制)

- 检索/topk/graph 与 foundation 完全一致(selection drift = 0);
- 双臂首请求差异仅允许出现在 system 消息(system_only_request_diff,
  user_message_drift = 0);
- system_contract_changes == 254(system 契约全行生效);
- foundation 47 文件中其余 45 文件哈希不变(候选仅 prompts.py/
  reasoning_loop.py 与对照不同,IsolationTests 验证);
- 请求参数:model=deepseek-chat, max_tokens=150, temperature=0, 每步≤3次尝试, ≤2步。

## 门槛(诊断性,不自动晋级)

- global_nonnegative_both:候选 F1/Acc 双重复均 ≥ 对照;
- fp_not_worse_both:候选 FP 双重复均 ≤ 对照;
- global_intervals_positive:全局 F1/Acc 分组 bootstrap CI95 下界 > 0;
- beats_constant_both:候选双重复 F1/Acc > 总是预测漏洞基线且 MCC > 0。

## 已知限制

- SVEN 为本地已曝光开发集(含相关/冲突行),非独立最终测试;重复不是新样本;
- r1 区间为描述性,非因果/泛化证明;检索为冻结缓存,非速度基准;
- SYSTEM 契约改变模型输出分布,候选臂按两行格式产出;指标为二元预测,
  不受格式差异影响,但跨候选批次的行为学可比性限于 binary verdict 层;
- 无自动激活、无重跑、无锁定 Devign、无 GitHub 上传、无论文就绪声明。

## 授权

Human approved verdict-first full254x2x2 single batch 2026-10-12(本次对话)。
preflight(508 离线 + 1016 mock)全部通过后批准;授权一次消耗,不重跑。
