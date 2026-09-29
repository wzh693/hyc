from config import DANGEROUS_APIS, TAINT_SOURCES, MEMORY_OPS
import re

# 核心 SINK API（最危险的操作，优先级最高）
SINK_APIS = {
    "strcpy", "strcat", "sprintf", "system", "execve", "popen",
    "memcpy", "memmove", "memset", "gets", "scanf",
    "strncpy", "strncat", "snprintf",
    "printf", "fprintf",
}

# ALLOC/FREE API 对（用于 UAF/DF 检测）
ALLOC_APIS = {
    "malloc", "calloc", "realloc", "alloca", "mmap",
    "av_malloc", "av_calloc", "av_realloc", "av_mallocz", "av_malloc_array",
    "kmalloc", "kzalloc", "kcalloc",
}

FREE_APIS = {
    "free", "munmap",
    "av_free", "av_freep",
    "kfree",
}

TAINT_APIS = TAINT_SOURCES


def summarize_function(code: str) -> str:
    """
    生成函数级摘要，显式区分 SINK / SOURCE / ALLOC / FREE。

    输出格式：
      [SINK]    危险操作端点（数据流入危险函数）
      [SOURCE]  污点数据入口（用户输入/外部数据）
      [ALLOC]   内存分配
      [FREE]    内存释放
      [配对]    ALLOC+FREE 模式检测
    """
    code_lower = code.lower()
    lines = code.split("\n")
    summary_parts = []

    # —— SINK 检测（大小写敏感：C 语言函数名区分大小写） ——
    found_sinks = [api for api in SINK_APIS if re.search(rf'\b{re.escape(api)}\s*\(', code)]
    if found_sinks:
        summary_parts.append(f"[SINK] {', '.join(found_sinks)}")

    # —— SOURCE 检测 ——
    found_sources = [api for api in TAINT_APIS if re.search(rf'\b{re.escape(api)}\s*\(', code)]
    if found_sources:
        summary_parts.append(f"[SOURCE] {', '.join(found_sources)}")

    # —— ALLOC 检测 ——
    found_alloc = [api for api in ALLOC_APIS if re.search(rf'\b{re.escape(api)}\s*\(', code)]
    if found_alloc:
        summary_parts.append(f"[ALLOC] {', '.join(found_alloc)}")

    # —— FREE 检测 ——
    found_free = [api for api in FREE_APIS if re.search(rf'\b{re.escape(api)}\s*\(', code)]
    if found_free:
        summary_parts.append(f"[FREE] {', '.join(found_free)}")

    # —— 配对检测：ALLOC 无 FREE → 内存泄漏 ——
    if found_alloc and not found_free:
        summary_parts.append(
            "[LEAK] alloc without free in function scope"
        )

    # —— 条件释放检测：free 在 if 块内 → 潜在 UAF ——
    if found_free:
        for i, line in enumerate(lines):
            if re.search(r'\b(?:free|av_free|av_freep|kfree|munmap)\b', line.lower()):
                for j in range(max(0, i - 5), i):
                    if "if" in lines[j].lower():
                        summary_parts.append(
                            "[UAF-RISK] free() inside conditional branch"
                        )
                        break
                break

    # —— 循环中的危险操作 ——
    for sink in found_sinks:
        if sink in {"memcpy", "strcpy", "strcat", "sprintf"}:
            for i, line in enumerate(lines):
                if sink in line.lower():
                    for j in range(max(0, i - 5), i):
                        line_j = lines[j].lower()
                        if "while" in line_j or "for" in line_j:
                            summary_parts.append(
                                f"[LOOP-DANGER] {sink} inside loop"
                            )
                            break
                    break

    if not summary_parts:
        # 论文设计：函数级摘要仅描述模式，不做安全判定。
        # 但需要提供足够的结构信息和 API 调用线索给 LLM。
        func_name = "unknown"
        for line in lines[:3]:
            m = re.match(r'\w+\s+\*?(\w+)\s*\(', line)
            if m:
                func_name = m.group(1)
                break
        n_lines = len([l for l in lines if l.strip()])
        has_cond = any(
            kw in code_lower for kw in ("if ", "else", "switch", "while", "for")
        )
        has_indir = "->" in code
        has_ptr = "*" in code and "/*" not in code

        # —— 提取所有函数调用（不限于标准库） ——
        all_calls = re.findall(r'\b(\w+)\s*\(', code)
        # 去掉语言关键字
        skip = {"if", "for", "while", "switch", "return", "sizeof", "else",
                "case", "break", "continue", "do", "goto"}
        func_calls = sorted(set(c for c in all_calls if c not in skip and len(c) > 1))
        # 按是否有返回值使用分类
        # 匹配: ret = func(...) 或 ret = ptr->method(...) 或 ret = obj->field->method(...)
        ret_used = re.findall(r'(\w+)\s*=\s*(?:\w+(?:\s*->\s*\w+)*)\s*\(', code)
        ret_vars = sorted(set(r for r in ret_used if r not in skip))

        parts = [f"[FUNC] {func_name} ({n_lines} active lines)"]

        # API 调用清单（最重要的信息）
        if func_calls:
            parts.append(f"[CALLS] {', '.join(func_calls[:10])}")
            if len(func_calls) > 10:
                parts[-1] += f" ... +{len(func_calls)-10} more"

        # 返回值追踪
        if ret_vars:
            parts.append(f"[RETVAR] return values: {', '.join(ret_vars)}")

        # 结构体成员访问摘要
        struct_writes = re.findall(r'(\w+)->(\w+)\s*=', code)
        if struct_writes:
            fields = sorted(set(f"{p}->{m}" for p, m in struct_writes))
            parts.append(f"[STRUCT-W] writes to: {', '.join(fields[:6])}")

        struct_reads = re.findall(r'(\w+)->(\w+)\s*(?!\s*=)', code)
        if struct_reads:
            fields = sorted(set(f"{p}->{m}" for p, m in struct_reads if (p, m) not in struct_writes))
            if fields:
                parts.append(f"[STRUCT-R] reads from: {', '.join(fields[:6])}")

        # 函数指针调用检测
        fptr_calls = re.findall(r'(\w+)->(\w+)\s*\(', code)
        if fptr_calls:
            parts.append("[FPTR] function pointer calls detected")

        if has_cond:
            parts.append("[CFG] conditional control flow present")
        if has_indir and not fptr_calls:
            parts.append("[INDIRECT] uses pointer indirection (->)")
        if has_ptr:
            parts.append("[POINTER] involves pointer operations")

        return "\n".join(parts)

    return "\n".join(summary_parts)