# 紧凑输出契约单一候选

2026-10-11用户同意先做离线候选，不授权新付费批次。本目录在冻结display-first
证据方案上只改SYSTEM中的输出格式要求；模型、证据、150Token、最多3步及解码
保持不变。用私有函数环境替换SYSTEM，冻结原模块不修改，不全局monkey-patch。

普通Stop只要求verdict/action/reason，reason最多32个ASCII字符；Query另带真实
target和edge_types。去掉长hypothesis叙述，但Vulnerable Query保留至多8字符的
稳定hypothesis键，供原有“连续同类型漏洞确认”早停使用；不删除或重写该逻辑。
Query边集合合法范围不改，不限制到某个CWE或手工API列表。Uncertain仍可返回，
不为提高确定判定率强迫Benign；无部分JSON或关键词解析兜底。

字符约束是给模型的提示，不是客户端截断或新解析器。违反格式仍由冻结decoder
处理，length仍弃权。没有本地DeepSeek tokenizer，字符/UTF8字节工程检查不是
150真实Token的精确证明，更不能用mock推断真实完整输出率。

全本地SVEN254×2臂离线首轮mock；另用合成Query链验证三步、同类型早停、
非法target/边拒绝和截断弃权。重复离线同一fixture不作为更多独立样本。
保持PYTHONHASHSEED=0，对照为冻结display-first＋扩充GAT（不是默认基础版）。
全请求除SYSTEM输出契约之外必须逐字相同；图/源码来源核验照旧。
候选身份以执行清单source_tool_hashes绑定，原policy摘要不覆盖wrapper，不可
用于图安全网翻转校准。安全网shadow，候选OFF，不下载、不训练、不上传。
