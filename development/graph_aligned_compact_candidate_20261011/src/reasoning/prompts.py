"""
LLM Prompt 模板。

HGL-Vul 的 prompt 设计遵循以下原则：
  1. 明确角色定位：漏洞推理助手
  2. 结构化输出格式：OBSERVATION/HYPOTHESIS/NEXT_ACTION/REASONING
  3. 层次化上下文注入：函数摘要 -> 基本块 -> 类型化路径
  4. 显式状态信息：程序状态记忆
"""

SYSTEM_PROMPT = """C vuln auditor. Input: SRC / DEP PATHS (REACHING_DEF=data, CFG=control, CALL; node tags [SINK]/[SOURCE]/[ALLOC]/[FREE] danger) / STATE. Types: UAF, Double Free, Buffer Overflow, Taint, Null Deref, Memory Leak. Distinguish evidence from heuristics: do not call code vulnerable solely because it allocates without a local free or frees inside a branch. Be terse.
Format:
OBSERVATION: <one sentence>
HYPOTHESIS: <type or "no vulnerability detected">
REASONING: <short evidence>
ACTION: {"action":"ExpandDFG|ExpandCFG|ExpandCALL|RetrieveAlias|CheckReachability|SummarizeEvidence|Stop","reason":"short reason"}"""


COMPACT_SYSTEM_PROMPT = SYSTEM_PROMPT.split("\nFormat:", 1)[0] + """
Output exactly three short lines, under 100 tokens total, verdict first:
HYPOTHESIS: <type or "no vulnerability detected">
REASONING: <at most 20 words: concrete evidence or missing evidence>
ACTION: {"action":"Stop|ExpandDFG|ExpandCFG|ExpandCALL|RetrieveAlias|CheckReachability|SummarizeEvidence","reason":"at most 5 words"}"""


def needs_expanded_types(user_prompt: str) -> bool:
    """Route by observed operations, never by dataset metadata or labels."""
    import re
    match = re.search(r'(?:^|\n)SRC:\n(.*?)(?:\n\n(?:DEP PATHS|SUMMARY|STATE|EXPLORATION STATE):|$)',
                      user_prompt, re.S)
    code = match.group(1) if match else user_prompt
    from graph.security_net import _mask_noncode
    code = _mask_noncode(code)
    return bool(re.search(r'(?:\w|\))\s*\[[^\]\n]+\]', code) or re.search(
        r'(?<![=!<>])=(?!=)[^;\n]*(?:\w|\))\s*(?:\*|\+|<<)\s*(?:\w|\()', code))


def get_system_prompt(user_prompt: str = "", *, bounded_output=False) -> str:
    from config import COMPACT_VERDICT_PROMPT, TYPE_COVERAGE_PROMPT, TYPE_COVERAGE_ROUTING
    prompt = COMPACT_SYSTEM_PROMPT if COMPACT_VERDICT_PROMPT else SYSTEM_PROMPT
    if bounded_output:
        prompt = SYSTEM_PROMPT.split('\nFormat:', 1)[0] + '''
Output exactly these three lines, within 100 tokens. Do not add prose:
HYPOTHESIS: <type, Benign, or Uncertain>
ACTION: {"action":"Stop|ExpandDFG|ExpandCFG|ExpandCALL|RetrieveAlias|CheckReachability","reason":"up to 5 words"}
REASONING: <up to 15 words, concrete evidence or missing evidence>
Request expansion only for a specific missing dependency; a dangerous API alone is not proof.'''
    if TYPE_COVERAGE_PROMPT and (not TYPE_COVERAGE_ROUTING or needs_expanded_types(user_prompt)):
        prompt = prompt.replace('Buffer Overflow, Taint',
            'Buffer Overflow, Out-of-Bounds Read, Integer Overflow, Taint')
    prompt += '\nDEP PATHS are complete JSON path arrays: id=node id, c=node code, l=Joern line, e=incoming edge types. Missing paths or source remain unknown.'
    return prompt


BOUNDED_OBSERVATION_PROMPT = SYSTEM_PROMPT.split("\nFormat:", 1)[0] + """
Format (each field MUST be short; output all four fields within 120 tokens):
OBSERVATION: <at most 15 words: key operations and dependencies>
HYPOTHESIS: <type or "no vulnerability detected">
REASONING: <at most 15 words: supporting evidence>
ACTION: {"action":"ExpandDFG|ExpandCFG|ExpandCALL|RetrieveAlias|CheckReachability|SummarizeEvidence|Stop","reason":"at most 5 words"}"""


def _summarize_prior(output: str, limit: int = 150) -> str:
    """Keep the verdict and evidence gap within the existing character budget."""
    import re
    fields = []
    for label, budget in (("HYPOTHESIS", 60), ("REASONING", 65)):
        match = re.search(
            rf"^\s*{label}:\s*([^\n\r]*)", output, re.IGNORECASE | re.MULTILINE
        )
        if match:
            fields.append(f"{label}: {match.group(1).strip()[:budget]}")
    return (" | ".join(fields) if fields else output.strip())[:limit] or "(none)"


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
        planner = exploration_state.strip() or "(no actions executed)"
        return f"""{hierarchical_context}

EXPLORATION STATE:
{planner}

Analyze SRC slice, verify with paths. Answer now."""
    from config import STRUCTURED_PRIOR_SUMMARY
    prev = (_summarize_prior(prev_conclusion) if STRUCTURED_PRIOR_SUMMARY
            else prev_conclusion.strip()[:150] or "(none)")
    state = program_state_dump.strip()[:350] if program_state_dump else "(none)"
    exploration = exploration_state.strip()[:350] if exploration_state else "(none)"
    evidence = evidence_summary.strip()[:500] if evidence_summary else "(none)"
    return f"""Prior: {prev}

{hierarchical_context}

PROGRAM STATE UPDATE:
{state}

EXPLORATION STATE:
{exploration}

EVIDENCE SUMMARY:
{evidence}

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
