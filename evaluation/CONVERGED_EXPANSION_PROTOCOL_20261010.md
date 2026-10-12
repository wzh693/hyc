# 固定数据扩充实验

用户同意扩大训练覆盖。唯一学习改动是训练范围：原231张训练图加上盘点中
全部2344条新增干净development候选的可用图。原selection36、calibration26
及其连接组保持不变。原300范围及新增2344合计2644条，所有失败保留。
新增候选涉及2074个组，使用全部行，不按标签或模型得分抽样、不替换失败。

不改七维特征、GAT/MIL架构、共享评分、检索、提示或安全网。训练恢复原Adam
lr.001、weight_decay=0、seed42、10轮、累积16、熵正则.01；不采用失败WD模型。
训练步数随数据增长而增长，这是扩充实验的一部分，不称等计算预算消融。
同组多行可能增加组内权重，需披露；不在本轮同时改为组加权损失。

准备前冻结准入报告、development清单、完整样本身份、工具/源码哈希。
原始JSON文件仅做字节级SHA与结构扫描，只有批准的2344个对象被JSON解码、
核验源码/项目/提交并落盘；未解码、分析或训练验证/锁定对象。不载入整个
JSON对象列表；不下载其他语料，不读取锁定测试预测，不调用外部模型。

使用相同既有Joern解析/清洗/导出及最小特征编码。两worker；每个解析/导出
阶段180秒上限；每行一轮尝试。恢复只处理尚未尝试的行，不自动重试失败。
先用合成C函数核验运行环境，这不是抽样质量评测。环境检查失败则不批量启动。
图必须有已定义函数体、非空最小特征；每图保存源码/图SHA与构建结果。

完整2344条准备完成且可用比例>=90%才允许训练；未通过则保留失败并停止，
不挑成功子集降格为新范围。成功图上MIL训练与bag诊断另报可用分母，全部
2644计划行及不可用名单同时保留，不将不可用误记为良性或伪造预测。

选轮只用原完整selection AUC，最高且同分取最早。calibration不参与选轮；
预声明开发诊断门槛仍为AUC>0.5且BA@0.5>0.5。三个划分与初始化逐项核验，
原历史模型作为控制，只改变训练数据范围。当前selection/calibration已经
曝光，不能称新的独立验证。失败不自动调参/换种子/补充来源重训。

预期准备需较长时间；阶段状态必须区分“清单冻结”“图准备中”“准备完成”
“训练完成”，不能把启动当完成。默认基础不改，安全网保持shadow，真实LLM
和GitHub发布均未授权。任何模型内部过线仍不能替代系统LLM和独立投稿测试。

```powershell
python -B -m evaluation.prepare_converged_expansion_20261010 --output output/converged_expansion_cpg_20261010 --freeze-only
python -B -m evaluation.prepare_converged_expansion_20261010 --output output/converged_expansion_cpg_20261010 --resume
python -B -m evaluation.train_converged_expanded_20261010 --output output/converged_expanded_gat_training_20261010
```
