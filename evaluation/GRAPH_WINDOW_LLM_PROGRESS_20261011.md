# 修复版全量LLM批次进度

用户已明确批准本批外发和费用，协议见 GRAPH_WINDOW_LLM_PROTOCOL_20261011.md。
2026-10-11 14:08（Asia/Shanghai）启动独立隐藏监督器，启动PID31872。
PID只是启动信息，不能当作持续存活证明。

- 全254条离线508mock核验通过，55空证据恢复54，剩余idx146保留。
- 27项工具/候选/基础身份回归通过。
- 完整1016运行时mock通过：
  `output/graph_window_runtime_preflight_v2_20261011/runtime_verification.json`。
- 首次运行时预检因工具缺少subprocess导入未启动子进程，原记录保留，0外发。
- 单次真实批次已启动，尚未完成，不提前报告指标。

权威状态：`output/graph_window_llm_supervisor_20261011/state.json`。
真实批次：`output/graph_window_llm1016_20261011/`。
过程中分别在control/display子目录追加results.jsonl和api_receipts.jsonl；
完成后汇总1016结果，生成report.json，再执行一次离线实际回答重放audit.json。
监督器心跳10秒，阶段失败即停，无自动重启、重跑或失败行补跑。
不覆盖旧实验、修改模型/阈值、读取锁定Devign、训练、重建CPG或上传GitHub。

本批包含所有失败/弃权/空证据，SVEN已曝光开发对照，不是独立论文测试。
源码安全网沿用基础，因此LLM初判、最终预测和弃权必须分列解读。
基础旧解析与候选bounded解析不同，这是组合候选，不能单独归因窗口收益。
实际模型、失败、未知用量及完整费用Token须以本批API收据为准。
