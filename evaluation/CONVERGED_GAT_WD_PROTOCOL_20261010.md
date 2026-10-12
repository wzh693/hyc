# 单一共享评分学习候选：权重衰减

用户在上一轮诊断后要求继续，并指出有更多数据集可用。先完成已建议的
单变量学习实验；多数据集接入单列，不混入这一消融，不因此授权付费LLM。

固定控制为 `output/converged_minimal_gat_training_20261010`，新输出为
`output/converged_gat_wd_training_20261010`。不覆盖来源、结果或默认基础。

唯一训练差异：Adam的weight_decay从默认0改为0.001。仍为seed42、lr0.001、
10轮、累积16、熵正则0.01、同7维输入和hash token、同GAT架构与dropout。
从相同初始化开始，不加载控制组训练权重续训。完整初始selection结果需
与控制逐项相等，否则中止；三个分组与原组成员须逐项相等。

范围为同一clean-development300已准备缓存，293张图，231/36/26冻结分组，
全部7条不可用保留。源/图/元数据/模型/清单哈希绑定；训练前后审计控制身份。
不访问Devign验证、锁定集、SVEN标签或其他新数据。不扫参、不换种子、不自动重跑。

选轮仍按全部selection的bag AUC，最高者且同分取最早；calibration不参与选轮。
报告选轮、完整train/selection/calibration、历轮损失及selection AUC。诊断门槛
沿用calibration AUC>0.5且balanced accuracy@0.5>0.5；不得事后改阈值、反转概率。
是否优于原模型单独报告，不将过门槛等同于显著收益或可上线。

现有26条calibration已被查看，只能称重复开发诊断，不是新的独立验证。
若失败，保留实验并停止这项超参数尝试；后续数据扩充需有数据准入和冻结协议。
即使成功，图安全网仍shadow，未获新LLM/安全网校准/最终投稿测试资格。

执行入口：

```powershell
python -B -m evaluation.train_converged_gat_wd_20261010 --output output/converged_gat_wd_training_20261010
```

新执行器由冻结训练器逐段复制而来，沿用相同特征与评估函数；除weight_decay
之外增加的是身份断言和结果记录。工具哈希在输出split.json中冻结。
