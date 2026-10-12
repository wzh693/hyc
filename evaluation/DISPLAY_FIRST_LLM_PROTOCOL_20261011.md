# 已批准的单次全量LLM对照（2026-10-11）

人类同意本批外发与费用：本地公开已曝光SVEN全部254条，冻结收敛v2/control
与display-first/display各重复两次，共1016计划结果；同一个扩充GAT。
endpoint=https://api.deepseek.com/v1，requested_model=deepseek-chat，记录实际模型。
每结果最多3步，每步最多3次尝试，输出150Token，temperature0，超时90秒，
并发4。无SDK隐式重试；HTTP尝试逐条记账。失败、截断、未知用量、Uncertain、
不变输入及idx146全部保留，不自动重跑。没有额外批次授权。

先冻结源码、模型、协议、工具、全量样本身份及首轮实际请求，执行1016个实际
运行时mock请求（stop）并核对完整身份集合，另外用合成测试核对3步/重试上限。
通过才允许真实调用。确定性图和GAT分数可复用，不复用任何LLM回答。
固定shuffle seed20261011；每样本repeat1/2反转两版本先后。
候选只改首轮SRC切片准则点；真实后续路径可能因答案不同而不同。

请求包括源码证据/图路径/STATE/推理上下文，不包含标签或CWE。单次返回JSON
必须符合冻结decoder；length返回Uncertain，不关键词兜底、不重试格式错误。
主指标完整254分母；弃权按目标相反计错，同时单列弃权率，避免混淆强制二分类
与有效答案。报告Acc/F1/MCC/BA、CWE、两次一致性、调用/Token/length/实际模型。

在调用前固定支持门槛，不按结果放宽：
1. 两次候选整体Acc/F1均不低于control。
2. 两次CWE125 Acc/F1均严格增加。
3. r1全局F1与CWE125 Acc的家族bootstrap差值95%下界均>0（2000次/seed20261011）。
4. 两次CWE190/416 BA下降均不超过.02。
5. 两次候选Acc/F1超过全阳性参考、MCC>0。
功能门槛独立报告：1016完整结果、无运行失败/弃权/未知用量、实际模型唯一。
任一失败不自动激活；即使全过也需另行决策，不视为独立论文测试。

真实输出保存逐次API回执与完整trace；离线重放每条真实回答，核对请求顺序、
首轮冻结配方、步骤/尝试、pred和usage。默认基础不变，图安全网shadow；不训练、
不调整阈值或图、不得读取锁定Devign、下载新数据或上传GitHub。

## 首次运行时预检拒绝与环境冻结（任何付费调用之前）

初次预检output/display_first_runtime_preflight_20261011保留：1016结果、644个
实际mock请求、372个首轮冻结不一致错误，0付费调用。只读复核idx31显示
SRC/PATHS相同、STATE不同：集合遍历依赖Python进程哈希种子。
不修改冻结架构或STATE算法；新图证据预检、运行时预检、真实执行及重放均在
进程启动前固定PYTHONHASHSEED=0，运行清单记录该环境。重新生成完整254×2
同期图预检于converged_display_first_preflight_seed0_20261011，再全1016运行时
预检于display_first_runtime_preflight_v2_20261011。旧失败不覆盖或解释为通过。
这是调用前工程纠正，不是自动重复付费批次；真实批次仍只有1016个计划结果。
