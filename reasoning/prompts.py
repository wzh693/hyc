"""
LLM Prompt 模板。

HGL-Vul 的 prompt 设计遵循以下原则：
  1. 明确角色定位：漏洞推理助手
  2. 结构化输出格式：OBSERVATION/HYPOTHESIS/NEXT_ACTION/REASONING
  3. 层次化上下文注入：函数摘要 -> 基本块 -> 类型化路径
  4. 显式状态信息：程序状态记忆
"""

SYSTEM_PROMPT = """C vuln auditor. Input: SRC / DEP PATHS (REACHING_DEF=data, CFG=control, CALL; node tags [SINK]/[SOURCE]/[ALLOC]/[FREE] danger) / STATE. Types: UAF, Double Free, Buffer Overflow, Taint, Null Deref, Memory Leak. Only say "no vulnerability" if the code is clearly safe; any risky pattern (unchecked copy, free-then-use, missing bounds check, unchecked alloc) means vulnerable. Be terse.
Format:
OBSERVATION: <one sentence>
HYPOTHESIS: <type or "no vulnerability detected">
REASONING: <short evidence>"""


def build_user_prompt(
    function_summary: str,
    hierarchical_context: str,
    program_state_dump: str,
    step: int,
    exploration_state: str = "",
    evidence_summary: str = "",
    prev_conclusion: str = "",
) -> str:
    """
    构建用户 prompt（token 受控的多步模式）。
      Step 1: 完整层次化上下文（源码切片 + 图路径）
      Step 2+: 仅增量上下文（上轮结论摘要 + 新检索路径），
               不重发完整层次结构，控制多步 token 开销
    """
    if step <= 1:
        return f"""{hierarchical_context}

Analyze SRC slice, verify with paths. Answer now."""
    prev = prev_conclusion.strip()[:150] if prev_conclusion else "(none)"
    return f"""Prior: {prev}

{hierarchical_context}

Refine: confirm type or rule out. Answer now."""


def build_prompt_vuln_check_flat(paths_context: str) -> str:
    """
    构建扁平化漏洞检测 prompt（用于消融实验的 no_hier_lin 配置）。
    跳过层次化结构，直接将路径序列化为文本块。
    """
    return f"""You are a vulnerability detection expert. Analyze the following code dependency paths to determine if there is a vulnerability.

Vulnerability types to consider:
- Use-After-Free (UAF): memory freed then dereferenced
- Double Free: same memory freed twice
- Buffer Overflow: unsafe memory copy without bounds check
- Taint-style: user input reaches dangerous functions (e.g. system, exec)
- Memory Leak: allocated memory not freed on all paths
- Null Pointer Dereference: pointer dereferenced after being set to NULL

Dependency Paths:
{paths_context}

Answer with exactly one word: "vulnerable" if any vulnerability is present, or "benign" if the code is safe.
"""