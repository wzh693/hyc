# 紧凑输出契约离线验收（2026-10-11）

工程验收通过，尚无新的真实LLM结果，候选冻结/OFF。
输出：`output/converged_compact_output_preflight_20261011`。
对照为display-first＋扩充GAT；不是默认type-coverage基础版。

32项单元测试通过（本候选8项、display-first4项、原架构20项）。覆盖三类Stop、
三步Query、同问题早停、无效target/边拒绝、完整JSON且length仍弃权、部分JSON
和Markdown不兜底，以及校准安全网拒绝。没有修改既有decoder或推理状态逻辑。

全SVEN254×2臂，508个实际首轮mock请求，0错误、0外部连接、0付费调用。
254对实际user消息、证据回执、图压缩、共享评分摘要、Top-K、STATE和输出预算
完全一致；254对仅SYSTEM输出契约改变。两臂分别完整重建254原图、582条展示
路径、2494次源码行和反向依赖来源，通过。源文件和模型快照哈希前后匹配。
idx146仍保留，不能用输出格式弥补原图缺失。mock不证明真实完整回答率改善。

## 输出契约

Stop：verdict/action/reason，去掉长hypothesis叙述，reason最多32ASCII字符。
Query：附真实target和合法edge_types；Vulnerable Query额外保留8字符以内稳定
hypothesis键，以兼容原有连续同类型漏洞确认早停。三步查询机制不删改。
三态Uncertain保留，不强迫模型猜良性；length/无效JSON仍按冻结decoder弃权。
这些长度是提示约束，不新增运行时字符串裁剪或格式修复，模型能否遵守待测。

## 长度检查的精确边界

全254原图中最长ID为12字符。使用32ASCII字符reason的最大JSON转义压力样例
（连续反斜杠），Stop为112～116UTF8字节；含全部4种合法依赖类型的Query为
200～236字节（Vulnerable含8字符hypothesis）。所有样例完整JSON可被旧decoder
处理，但不能用字节数换算宣称已证明150真实输出Token足够。
本地没有tiktoken或DeepSeek tokenizer；未下载工具、未调用API测长，精确模型
Token计数为null。真实截断率、正常Uncertain比例、Acc/F1都还没有新结论。

## 后续与权限

先固定这个单一候选，不同时改图证据、扩大150Token预算、换模型或加CWE规则。
若要检验输出是否真正完整，下一批需新全量254control/candidate各重复两次、
1016计划结果的明确外发/费用授权，并在调用前冻结协议与全1016运行时mock。
主要关注完整JSON率、length、明确Uncertain/解析弃权，以及完整分母检测指标；
不能用有效输出子集高分替代全量指标。
过去的949弃权结果不改写，已消费的真实批次不重跑。默认基础保持，图安全网
仍shadow，没有训练、锁定Devign访问、下载、GitHub上传或新监控自动化。
