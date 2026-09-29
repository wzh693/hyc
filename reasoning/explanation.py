"""
漏洞证据链生成 (Vulnerability Explanation Generation)。

生成完整的、可解释的漏洞报告，包括：
  - 漏洞类型
  - source-sink 传播路径
  - 关键控制条件
  - 变量生命周期
  - 触发原因分析
"""

import networkx as nx
from linearization.typed_paths import typed_dependency_path
from planning.state_memory import ProgramState


def generate_explanation(
    G: nx.MultiDiGraph,
    vulnerability_type: str,
    evidence_paths: list,
    program_state: ProgramState,
    llm_conclusion: str,
) -> str:
    """
    生成完整漏洞证据链。

    参数:
        G: 代码属性图
        vulnerability_type: 漏洞类型
        evidence_paths: 证据路径列表
        program_state: 程序状态记忆
        llm_conclusion: LLM 推理结论
    返回:
        格式化的漏洞报告
    """
    parts = []
    parts.append("=" * 70)
    parts.append("VULNERABILITY REPORT - HGL-Vul Analysis")
    parts.append("=" * 70)

    # 1. 漏洞类型
    parts.append(f"\n[Vulnerability Type]: {vulnerability_type}")

    # 2. Source-Sink 传播路径
    parts.append("\n[Source-Sink Propagation Paths]:")
    if evidence_paths:
        for i, path in enumerate(evidence_paths):
            parts.append(f"\n  Evidence Path #{i+1} ({len(path)} nodes):")
            serialized = typed_dependency_path(G, path)
            for line in serialized.split("\n"):
                parts.append(f"    {line}")
    else:
        parts.append("  (no evidence paths)")

    # 3. 变量生命周期
    parts.append("\n[Variable Lifecycle Analysis]:")
    parts.append(program_state.dump())

    # 4. LLM 推理结论
    parts.append(f"\n[LLM Analysis]:\n{llm_conclusion}")

    # 5. 触发条件分析
    parts.append("\n[Trigger Condition Analysis]:")
    vt_lower = vulnerability_type.lower()

    if "use-after-free" in vt_lower:
        parts.extend(_analyze_uaf(program_state))
    elif "double free" in vt_lower:
        parts.extend(_analyze_double_free(program_state))
    elif "taint" in vt_lower:
        parts.extend(_analyze_taint(program_state))
    elif "null pointer" in vt_lower:
        parts.extend(_analyze_null_pointer(program_state))
    else:
        parts.append("  Vulnerability type-specific analysis not available.")

    # 6. 总结
    parts.append("\n" + "=" * 70)
    parts.append("END OF REPORT")
    parts.append("=" * 70)

    return "\n".join(parts)


def _analyze_uaf(state: ProgramState) -> list:
    """分析 Use-After-Free 触发条件。"""
    lines = []
    for var, history in state.states.items():
        if state.is_freed_and_used(var):
            freed_step = None
            deref_step = None
            freed_source = None
            deref_source = None
            for h in history:
                if h["state"] == "freed" and freed_step is None:
                    freed_step = h["step"]
                    freed_source = h["source"]
                if h["state"] == "dereferenced":
                    deref_step = h["step"]
                    deref_source = h["source"]
            # step=0（track_vars 产生的源码事件）是合法值，必须用 is not None 判空
            if freed_step is not None and deref_step is not None:
                lines.append(f"  Variable '{var}': Use-After-Free CONFIRMED")
                lines.append(f"    - Freed at step {freed_step} (node: {freed_source})")
                lines.append(
                    f"    - Dereferenced at step {deref_step} (node: {deref_source})"
                )
                lines.append(
                    f"    - Gap: {deref_step - freed_step} steps between free and use"
                )
    if not lines:
        lines.append("  No Use-After-Free pattern confirmed.")
    return lines


def _analyze_double_free(state: ProgramState) -> list:
    """分析 Double Free 触发条件。"""
    lines = []
    for var, history in state.states.items():
        if state.is_double_free(var):
            free_steps = [
                (h["step"], h["source"]) for h in history if h["state"] == "freed"
            ]
            lines.append(f"  Variable '{var}': Double Free CONFIRMED")
            lines.append(
                f"    - First free at step {free_steps[0][0]} (node: {free_steps[0][1]})"
            )
            lines.append(
                f"    - Second free at step {free_steps[1][0]} (node: {free_steps[1][1]})"
            )
            if len(free_steps) > 2:
                lines.append(f"    - Additional frees: {len(free_steps) - 2} more")
    if not lines:
        lines.append("  No Double Free pattern confirmed.")
    return lines


def _analyze_taint(state: ProgramState) -> list:
    """分析污点传播触发条件。"""
    lines = []
    for var, history in state.states.items():
        if state.is_taint_propagation(var):
            taint_source = None
            sink = None
            for h in history:
                if h["state"] == "tainted" and taint_source is None:
                    taint_source = h
                if h["state"] == "dereferenced":
                    sink = h
            if taint_source and sink:
                lines.append(f"  Variable '{var}': Taint Propagation CONFIRMED")
                lines.append(
                    f"    - Taint source at step {taint_source['step']} "
                    f"(node: {taint_source['source']})"
                )
                lines.append(
                    f"    - Sink at step {sink['step']} "
                    f"(node: {sink['source']})"
                )
    if not lines:
        lines.append("  No Taint Propagation pattern confirmed.")
    return lines


def _analyze_null_pointer(state: ProgramState) -> list:
    """分析空指针解引用触发条件。"""
    lines = []
    for var, history in state.states.items():
        if state.is_null_pointer_deref(var):
            lines.append(f"  Variable '{var}': Null Pointer Dereference CONFIRMED")
            lines.append("    - Dereferenced without any NULL check")
    if not lines:
        lines.append("  No Null Pointer Dereference pattern confirmed.")
    return lines