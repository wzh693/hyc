# 收敛架构修订v2（2026-10-10）

用户同意继续处理原型剩余问题。本目录是新的隔离候选，不修改旧原型、当前基础、
已冻结源文件或历史结果。不调用真实LLM、不访问锁定Devign、不自动推送GitHub。

## 当前方案

保持共享GAT/MIL分数→压缩/检索→三段式证据→受限推理→图风险后处理主线。
不按数据集CWE路由，不补充CWE专用API表，不复用失败回答冒充新质量成绩。

- 准则点：按同一份全图注意力分数，在可映射到已有源码的CALL/RETURN节点中
  选Top-K；覆盖一般辅助调用和算术操作，不以危险API白名单限定切片。
- 压缩：不选携带整段函数文本的METHOD/BLOCK等容器；保留既有危险调用force-keep。
  单个非强制节点超剩余预算时跳过，不使后续所有便宜节点被整体放弃。
- 检索：AST用于GAT编码，不用作展示路径的依赖边。路径可含显式CFG，但源码切片
  只用DFG/REACHING_DEF/CDG/CONTROL_DEPENDENCE。候选仍有512条/6节点硬上限，
  按共享评分排序准则点与扩展节点，并如实记录上限触及，不声称完整枚举。
- 展示：完整路径序列化可行性是排序前的约束，排序仍是相同共享分数加结构项；
  不另加读取/危险性优先权重。短JSON字段减少元数据重复，不截断任何节点code。
- SRC：从选中路径终点在原CPG反向依赖闭包投影源码，完整源码行预算1100字符；
  恢复压缩图之外的真实依赖并明确记录来源，不把AST或CFG当控制依赖。
- STATE及推理沿用保守MAY观察，最多三步，150输出Token；新路径查询必须绑定
  实际展示节点，不能凭空扩展。当前与原基础的步数/证据预算不同，不称等预算质量对照。

## 新GAT训练（单次固定实验，不自动重试）

只用 `output/devign_development300_20261005` 中、逐条匹配干净development
清单的300条已准备缓存。293张图可用，7条不可用记录保留。按清单group_id哈希
分成train231、selection36、calibration26，三组不相交。未使用原legacy训练缓存
或锁定/验证样本，未为训练加载整份Devign源码。

输入仅6维节点类型one-hot+1维log代码长度，及32维hash-token嵌入；移除API族、
漏洞类型提示、邻域危险计数等36维人工特征。2层GATv2、128隐藏、4头、5类边；
节点分数仍为MIL池化注意力，不是边注意力或因果归因。CFG/CDG在既有编码器的
边类型分类中合并，不能声称GAT区分了全部细粒度CPG边语义。

固定seed42、Adam lr=.001、10epochs、梯度累积16、归一化注意力熵正则.01。
只按完整selection AUC选轮，calibration不用于选轮；不以SVEN得分选模型。
结果 `output/converged_minimal_gat_training_20261010`：选第7轮，selection AUC
0.443636；calibration AUC0.484848、balanced accuracy0.418182，预设模型诊断
门槛失败。随机初始化selection AUC0.665455不是另一份可推广的质量结论。
不自动继续训练/调参或换随机种子；该模型仅用于本轮工程诊断，不默认启用。

## 图安全网校准边界

`calibrate_graph_proxy.py` 覆盖全部26条保留校准分组，固定阈值网格
1/2/3/4/6/8/12/16/24/32，独立检查危险信号的选择性。
代理阈值需至少选3条、precision≥2/3且FPR≤.1，无运行失败；不修改网格挑结果。
此工具没有真实LLM初判，不能测FN恢复或TN误翻；即便有代理阈值，输出status
也只能是proxy_only，生产验证器拒绝作为翻转凭据。不得把bag分类校准或mock初判
当成完整图后验证校准。真正阈值需要新的同期真实初判和开发校准授权。

## 验证入口

```powershell
python -B -m unittest development.converged_graph_v2_candidate_20261010.test_architecture
python -B -m development.converged_graph_v2_candidate_20261010.audit_training --run output/converged_minimal_gat_training_20261010
python -B -m development.converged_graph_v2_candidate_20261010.calibrate_graph_proxy --output output/<fresh-proxy-dir>
python -B -m development.converged_graph_v2_candidate_20261010.run_offline --output output/<fresh-preflight-dir>
python -B -m development.converged_graph_v2_candidate_20261010.audit_offline --run output/<preflight-dir>
```

预检覆盖全部本地SVEN254条，基础/候选各254条首轮mock，共508个实际请求。
源码、数据和工具先冻结后验证；独立审计重建原图、完整节点code、真实边、
反向依赖闭包、源码行映射和预算。不存在新LLM质量指标；模型诊断失败和安全网
未校准必须单列，不能用“工程pass”宣布“全部通过”。

用户接受探索小幅下降换取精炼。非劣容忍度此前建议为整体F1/准确率2个百分点，
但尚待真实协议确认；不能用本次bag诊断或不同预算mock计算非劣。是否降低风险
需在模型效果之外，分别量化特征维度、规则分支、实际Token/调用和耗时。
