# 隔离单一候选：图锚定读取依赖SRC切片

默认开发基础仍为 ../type_coverage_reconstructed_20261008/src。此目录不是默认启用版。
47文件从冻结基础复制，仅linearization/backward_slice.py改变；使用既有
USE_BACKWARD_SLICE接线。control=0，read_slice=1，其余基础设置全部不变。

读取准则取既有Top-K的标准扫描/复制源/比较源、下标或解引用CALL；排除可识别的
纯赋值目标。不以CWE/标签/真值选择。源参数/宽度从原源码取得，歧义/位置缺失回退。
沿原图REACHING_DEF/DFG及真实CDG/CONTROL_DEPENDENCE最多5跳、最多128节点，
仅保留共享读取目标/宽度标识符的数据依赖；不把CFG当支配或容量证明。
原SRC600..1100字符预算不变。原源码整行、作用域原有括号、带行号省略注释；
不足则遗漏并记录，不编造补全，不启用完整源码，不修DOT解码或改图/排序/判定。

真实测试按用户2026-10-09单次授权，先冻结预检：同一30条公开SVEN、control/
read_slice各两次、120结果、DeepSeek deepseek-chat/实际模型记录、max2步×3尝试、
输出150。保留失败，不自动重跑、扩大254、启用候选或上传。SVEN是开发曝光集。

批次已完成：120成功调用、实际均deepseek-flash、104087 Token，审计通过但
四项质量门槛全失败。授权已用完，本候选不启用；默认继续基础。
预检仅5/30输入改变；r1整体净多正确2条全部来自不变输入，不是切片提升证据。
完整结论 ../../evaluation/GRAPH_READ_SLICE_LLM_FINDINGS_20261009.md。
