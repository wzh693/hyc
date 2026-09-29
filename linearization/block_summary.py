from config import DANGEROUS_APIS, TAINT_SOURCES, MEMORY_OPS
import re

# 安全关键关键词（用于摘要生成时的优先级标识）
CRITICAL_PATTERNS = {
    "alloc": "ALLOC", "malloc": "ALLOC", "calloc": "ALLOC", "realloc": "ALLOC",
    "av_malloc": "ALLOC", "av_realloc": "ALLOC", "kmalloc": "ALLOC",
    "free": "FREE", "av_free": "FREE", "kfree": "FREE",
    "memcpy": "COPY", "strcpy": "COPY", "sprintf": "FMT",
    "if": "BRANCH", "else": "BRANCH", "switch": "BRANCH",
    "while": "LOOP", "for": "LOOP",
    "return": "RET",
}

COMBINED_APIS = DANGEROUS_APIS | TAINT_SOURCES | MEMORY_OPS


def summarize_block(block_code: str) -> str:
    """
    生成基本块级安全摘要。

    输出格式（单行紧凑）：
      [BLOCK: ALLOC+LIB] malloc(256) -> local ptr; if(!ptr) return NULL;

    与旧版的区别：
      - 单行紧凑输出，减少 token 消耗
      - 标签优先突出内存/安全操作
      - 合并连续行，避免冗余
    """
    lines = [l.strip() for l in block_code.split("\n") if l.strip()]
    if not lines:
        return ""

    # 收集这一块的安全标签
    block_tags = set()
    key_lines = []
    for line in lines:
        line_lower = line.lower()
        for api, tag in CRITICAL_PATTERNS.items():
            if re.search(rf'\b{re.escape(api)}\s*\(', line):
                block_tags.add(tag)
        # 收集关键行：危险 API 调用、条件、循环、声明
        is_critical = (
            any(re.search(rf'\b{re.escape(api)}\s*\(', line) for api in COMBINED_APIS) or
            "(" in line and ")" in line or
            any(kw in line_lower for kw in ("if", "else", "while", "for", "switch", "return"))
        )
        if is_critical:
            key_lines.append(line[:100])

    tag_str = "+".join(sorted(block_tags)) if block_tags else "CODE"
    line_str = "; ".join(key_lines[:3])
    return f"[{tag_str}] {line_str}"