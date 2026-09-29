"""
预定义动作集合 (Constrained Action Set)。

HGL-Vul 的核心创新：限制 LLM 只能执行预定义动作，
从而避免自由形式推理带来的"推理漂移"问题。
"""

ACTIONS = [
    "ExpandDFG",         # 沿数据流扩展
    "ExpandCFG",         # 沿控制流扩展
    "ExpandCALL",        # 沿调用链扩展
    "RetrieveAlias",     # 检索别名传播
    "CheckReachability", # 验证路径可达性
    "SummarizeEvidence", # 汇总当前证据
    "Stop",              # 停止推理
]

# LLM 输出关键词 -> 动作映射
# 当 LLM 输出中包含对应关键词时，调度器自动选择相应动作
ACTION_KEYWORDS = {
    "ExpandDFG": [
        "data flow", "dfg", "data dependency", "数据流",
        "propagat", "define", "reach",
    ],
    "ExpandCFG": [
        "control flow", "cfg", "control dependency", "控制流",
        "branch", "condition", "execution path",
    ],
    "ExpandCALL": [
        "call", "function call", "调用", "invoke",
        "interprocedural", "cross function",
    ],
    "RetrieveAlias": [
        "alias", "pointer", "别名", "指针",
        "reference", "address",
    ],
    "CheckReachability": [
        "reachable", "reachability", "可达", "verify",
        "connect", "path exists",
    ],
    "SummarizeEvidence": [
        "summarize", "evidence", "conclude", "汇总", "结论",
        "sufficient", "enough", "final",
    ],
    "Stop": [
        "stop", "done", "complete", "完成", "结束",
        "terminate",
    ],
}