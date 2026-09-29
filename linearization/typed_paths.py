import re
import networkx as nx
from config import DANGEROUS_APIS, TAINT_SOURCES, MEMORY_OPS


def extract_api_hints(code: str) -> dict:
    """
    从源代码中提取 API 提示，供 typed_dependency_path 标注路径用。

    返回格式：
      {
        "sink_apis": {"strcpy", "sprintf", ...},
        "source_apis": {"recv", "scanf", ...},
        "alloc_apis": {"malloc", "calloc", ...},
        "free_apis": {"free", ...},
      }
    """
    code_lower = code.lower()
    # 从代码中提取所有标识符（函数名、变量名等）
    tokens = set(re.findall(r'\b([a-zA-Z_]\w*)\b', code_lower))

    def match(apis: set) -> set:
        return {a for a in apis if a in tokens}

    # 真正的 SINK 是危险操作端点（如 strcpy, system, memcpy），
    # 而 malloc/free 属于 ALLOC/FREE，不应出现在 sink_apis 中。
    alloc_free_apis = {
        "malloc", "calloc", "realloc", "alloca", "mmap",
        "av_malloc", "av_calloc", "av_realloc", "av_mallocz", "av_malloc_array",
        "kmalloc", "kzalloc", "kcalloc",
        "free", "munmap", "kfree", "av_free", "av_freep",
    }
    sink_only = DANGEROUS_APIS - alloc_free_apis

    return {
        "sink_apis": match(sink_only),
        "source_apis": match(TAINT_SOURCES),
        "alloc_apis": match({a for a in MEMORY_OPS if a in {"malloc", "calloc", "realloc", "alloca", "mmap",
                                                              "kmalloc", "kzalloc", "av_malloc", "av_calloc",
                                                              "av_mallocz", "av_malloc_array"}}),
        "free_apis": match({a for a in MEMORY_OPS if a in {"free", "munmap", "kfree", "av_free", "av_freep"}}),
    }


def _node_text_fields(nd: dict) -> str:
    """提取节点所有文本字段用于匹配。"""
    return " ".join(filter(None, [
        nd.get("code", ""),
        nd.get("name", ""),
        nd.get("method", ""),
    ]))


def _node_security_hit(nd: dict) -> tuple:
    """节点危险侧安全命中：返回 (label, api)。

    优先级：SINK > SOURCE > ALLOC > FREE。api 为具体命中的 API 名——
    v15（BUG-19）：路径级标注只列该路径节点实际命中的 API，弃用
    函数级全局标注（良性函数任一处 memcpy 会让所有路径都带
    SINK=memcpy，危险信号失真放大）。
    """
    text = _node_text_fields(nd).lower()

    # SINK：危险 API（strcpy, system, memcpy, sprintf 等）
    sink_apis = {"strcpy", "strcat", "sprintf", "system", "execve", "popen",
                 "memcpy", "memmove", "memset", "gets", "scanf",
                 "strncpy", "strncat", "snprintf"}
    for api in sink_apis:
        if re.search(rf'\b{re.escape(api)}\b', text):
            return "SINK", api

    # ALLOC：内存分配
    alloc_apis = {"malloc", "calloc", "realloc", "alloca", "mmap",
                  "av_malloc", "av_calloc", "av_realloc", "av_mallocz",
                  "kmalloc", "kzalloc", "kcalloc"}
    for api in alloc_apis:
        if re.search(rf'\b{re.escape(api)}\b', text):
            return "ALLOC", api

    # FREE：内存释放
    free_apis = {"free", "munmap", "av_free", "av_freep", "kfree"}
    for api in free_apis:
        if re.search(rf'\b{re.escape(api)}\b', text):
            return "FREE", api

    # SOURCE：污点源
    taint_sources = {"recv", "read", "fread", "scanf", "gets", "fgets",
                     "argv", "getenv", "recvfrom", "recvmsg",
                     "copy_from_user", "fopen", "open"}
    for api in taint_sources:
        if re.search(rf'\b{re.escape(api)}\b', text):
            return "SOURCE", api

    return "", ""


def _node_security_label(nd: dict) -> str:
    """节点危险侧安全标签：SINK, SOURCE, ALLOC, FREE。

    优先级：SINK > SOURCE > ALLOC > FREE。
    被 _path_security_score / select_vuln_aware_topk 用于检索打分——
    v15 安全锚点 [SAFE] 不进此函数（避免改变路径检索选择，单变量纪律）。
    """
    return _node_security_hit(nd)[0]


# v15 安全锚点：节点级缓解（mitigation）证据模式。
# NULL 检查：==/!= NULL、!ident（!= 的 ! 后跟 = 不命中，无歧义）
_SAFE_NULL_RE = re.compile(r'(?:==|!=)\s*null\b|!\s*\(?\s*[a-z_]\w*')
# 边界/长度比较：< >（排除 <=、>=、->、<<、>>——<= 恰是 off-by-one 高发写法）
_SAFE_BOUND_RE = re.compile(r'(?<![<>\-])(?:<|>)(?![<>=])')
# sizeof/strlen/ARRAY_SIZE 长度守卫（malloc 上下文中的 sizeof 是分配尺寸，非守卫）
_SAFE_SIZE_RE = re.compile(r'\b(?:sizeof|strlen|array_size)\s*\(')
_ALLOC_CALL_RE = re.compile(r'\b(?:malloc|calloc|realloc|kmalloc|kzalloc|'
                            r'av_malloc|av_calloc|av_realloc|av_mallocz)\s*\(')


def _node_safe_label(nd: dict) -> str:
    """v15 安全锚点：节点级缓解证据标签（"SAFE" 或 ""）。

    仅用于 LLM 可见序列化（_labeled_compact_path / path_evidence_tags），
    与危险侧标签成对呈现——v14 主缺口 FP 41 的根因是证据只有危险侧，
    良性样本的防护措施（NULL 检查/边界比较/长度守卫）对 LLM 不可见。

    模式（危险标签优先级更高，同一节点两者并存时序列化只显示危险侧，
    但 path_evidence_tags 的 SAFE 计数两者都收）：
      - NULL 检查：if (!p) / if (p == NULL) / if (p != NULL)
      - 边界/长度比较：i < n（不含 <=/>=，off-by-one 不算守卫）
      - sizeof/strlen/ARRAY_SIZE（非 malloc 参数上下文）
    """
    text = _node_text_fields(nd).lower()
    if _SAFE_NULL_RE.search(text):
        return "SAFE"
    if _SAFE_SIZE_RE.search(text) and not _ALLOC_CALL_RE.search(text):
        return "SAFE"
    if _SAFE_BOUND_RE.search(text):
        return "SAFE"
    return ""


def _path_security_score(G: nx.MultiDiGraph, path: list) -> float:
    """
    计算路径的漏洞安全得分：路径中有几种不同的安全标签类型。

    sink + source = 完整污点链（最高分）
    alloc + free = UAF/double-free 模式
    只有危险 API = 部分可疑
    """
    labels = set()
    for nid in path:
        lbl = _node_security_label(G.nodes.get(nid, {}))
        if lbl:
            labels.add(lbl)
    score = 0
    score += 10 if "SINK" in labels else 0
    score += 8 if "SOURCE" in labels else 0
    score += 6 if "ALLOC" in labels else 0
    score += 5 if "FREE" in labels else 0
    return score


def select_vuln_aware_topk(G: nx.MultiDiGraph, paths: list, k: int = 10, max_path_len: int = 8) -> list:
    """
    从候选路径中选出 Top-K 漏洞感知路径。

    策略：
      1. 优先选择包含 SINK + SOURCE 的完整污点链
      2. 其次选择含 ALLOC + FREE 的内存操作链
      3. 再次选择含单个安全标签的路径
      4. 控制路径长度，过滤过长路径
      5. 去重：避免选择重复的安全标签组合
    """
    if not paths:
        return []

    # 过滤过长路径
    valid = [p for p in paths if len(p) <= max_path_len]

    # 按安全得分排序
    scored = [(p, _path_security_score(G, p)) for p in valid]
    scored.sort(key=lambda x: x[1], reverse=True)

    selected = []
    seen_combos = set()
    for path, score in scored:
        # 收集本条路径的安全标签组合
        labels = tuple(sorted(
            _node_security_label(G.nodes.get(nid, {}))
            for nid in path
            if _node_security_label(G.nodes.get(nid, {}))
        ))
        if labels and labels in seen_combos:
            continue  # 跳过与已选路径相同标签组合的路径
        if labels:
            seen_combos.add(labels)
        selected.append(path)
        if len(selected) >= k:
            break

    # 如果没选够，用原始 top-k 补齐
    if len(selected) < k:
        for path, _ in scored:
            if path not in selected:
                selected.append(path)
            if len(selected) >= k:
                break

    return selected[:k]


def typed_dependency_path(G: nx.MultiDiGraph, path: list, api_hints: dict = None) -> str:
    """
    类型化依赖路径表示 + 安全标签标注。

    标注层次：
      路径级:  从 api_hints（源码提取的 API 信息）生成路径级 API 注解
      节点级:  从 DOT 节点文本字段匹配安全标签（SINK/SOURCE/ALLOC/FREE）

    api_hints 格式（可选）：
      {"sink_apis": {"strcpy", ...}, "source_apis": {"recv", ...},
       "alloc_apis": {"malloc", ...}, "free_apis": {"free", ...}}

    输出格式示例:
    ## Path Annotation: [ALLOC=malloc] → [SINK=memcpy]
    [CONTAINS:ptr = malloc(256)] --REACHING_DEF--> [DOMINATE:ptr]
      --CFG--> [CONTAINS:memcpy(buf ptr n)]
    """
    if len(path) < 2:
        return ""

    outputs = []

    # ── 路径级 API 注解（当 DOT 节点无法携带 API 名时，用源码信息补充）──
    if api_hints:
        path_annotations = []
        for label, apis in [
            ("SINK", api_hints.get("sink_apis", set())),
            ("SOURCE", api_hints.get("source_apis", set())),
            ("ALLOC", api_hints.get("alloc_apis", set())),
            ("FREE", api_hints.get("free_apis", set())),
        ]:
            if apis:
                path_annotations.append(f"[{label}={','.join(sorted(apis))}]")
        if path_annotations:
            outputs.append("## Path Context: " + " ".join(path_annotations))

    # ── 节点级安全标签（从 DOT 文本字段匹配）──
    path_labels = {}
    for nid in path:
        path_labels[nid] = _node_security_label(G.nodes.get(nid, {}))

    for i in range(len(path) - 1):
        src = path[i]
        dst = path[i + 1]

        edge_data = G.get_edge_data(src, dst)
        if edge_data:
            edge_types = sorted(set(
                attr.get("edge_type", "?")
                for attr in edge_data.values()
                if isinstance(attr, dict)
            ))
            edge_type = "+".join(edge_types)
        else:
            edge_type = "?"

        src_node = G.nodes.get(src, {})
        dst_node = G.nodes.get(dst, {})

        src_code = src_node.get("code", src_node.get("name", "?")).strip()[:60]
        dst_code = dst_node.get("code", dst_node.get("name", "?")).strip()[:60]
        src_type = src_node.get("node_type", "?")
        dst_type = dst_node.get("node_type", "?")

        src_label = path_labels.get(src, "")
        dst_label = path_labels.get(dst, "")
        src_tag = f"[{src_label}] " if src_label else ""
        dst_tag = f"[{dst_label}] " if dst_label else ""

        outputs.append(
            f"{src_tag}[{src_type}:{src_code}]\n"
            f"  --{edge_type}-->\n"
            f"{dst_tag}[{dst_type}:{dst_code}]"
        )

    # ── 路径级安全标签摘要 ──
    all_labels = set(l for l in path_labels.values() if l)
    if all_labels or (api_hints and any(api_hints.values())):
        summary_parts = []
        if all_labels:
            summary_parts.append("Node tags: " + " + ".join(sorted(all_labels)))
        if api_hints:
            for label in ("sink_apis", "source_apis", "alloc_apis", "free_apis"):
                apis = api_hints.get(label, set())
                if apis:
                    label_name = label.replace("_apis", "").upper()
                    summary_parts.append(f"{label_name} APIs: {','.join(sorted(apis))}")
        if summary_parts:
            outputs.append(f"\n[SUMMARY] {' | '.join(summary_parts)}")

    return "\n".join(outputs)


def _compact_path(G: nx.MultiDiGraph, path: list, max_len: int = 300) -> str:
    """单行紧凑路径序列化：[TYPE:code] --EDGE--> [TYPE:code]，控制 token 预算。"""
    # 防御：过滤不可哈希节点 id（部分路径结构返回嵌套 list）
    if len(path) < 2 or not all(isinstance(n, (str, int)) for n in path):
        return ""
    segments = []
    for i in range(len(path) - 1):
        src_node = G.nodes.get(path[i], {})
        dst_node = G.nodes.get(path[i + 1], {})
        src_code = (src_node.get("code") or src_node.get("name") or "?").strip()[:35]
        dst_code = (dst_node.get("code") or dst_node.get("name") or "?").strip()[:35]
        edge_data = G.get_edge_data(path[i], path[i + 1])
        if edge_data:
            ets = sorted(set(
                a.get("edge_type", "?") for a in edge_data.values() if isinstance(a, dict)
            ))
            et = "+".join(ets)[:20]
        else:
            et = "?"
        if i == 0:
            segments.append(f"[{src_node.get('node_type','?')}:{src_code}]")
        segments.append(f"--{et}--> [{dst_node.get('node_type','?')}:{dst_code}]")
    line = " ".join(segments)
    return line[:max_len]


def _labeled_compact_path(G: nx.MultiDiGraph, path: list, max_len: int = 350) -> str:
    """带节点级安全标签的单行紧凑序列化（v14 Step2 增量上下文用）。

    v9 教训：Step2 证据太薄导致 15 个 FN，节点级 SINK/SOURCE/ALLOC/FREE
    标签是 FN 恢复的关键，必须保留；而多行详细格式（typed_dependency_path，
    每跳 3 行、60 字符截断，实测均值 603ch）是 v13 Step2 token 超标主因
    （Step2 样本 45/48 超 1043，均值 1479 vs Step1-only 911）。
    本函数保留全部节点 + 安全标签 + 边类型，仅压缩格式：单行、35 字符截断。
    """
    if len(path) < 2 or not all(isinstance(n, (str, int)) for n in path):
        return ""
    segments = []
    for i in range(len(path) - 1):
        src_node = G.nodes.get(path[i], {})
        dst_node = G.nodes.get(path[i + 1], {})
        src_code = (src_node.get("code") or src_node.get("name") or "?").strip()[:35]
        dst_code = (dst_node.get("code") or dst_node.get("name") or "?").strip()[:35]
        edge_data = G.get_edge_data(path[i], path[i + 1])
        if edge_data:
            ets = sorted(set(
                a.get("edge_type", "?") for a in edge_data.values() if isinstance(a, dict)
            ))
            et = "+".join(ets)[:20]
        else:
            et = "?"
        if i == 0:
            # v16：仅危险侧标签（SINK/SOURCE/ALLOC/FREE）。
            # v15 曾回落 [SAFE] 缓解标签（证据双侧化），实测安全锚点双刃剑：
            # FP→TN 11 但 TP→FN 12（Rec 86→62 崩盘）——真实漏洞常带"看似
            # 防护"的检查，双侧判词把 LLM 朝判良性推。v16 回退该层（B 方案）。
            lbl = _node_security_label(src_node)
            tag = f"[{lbl}]" if lbl else ""
            segments.append(f"{tag}[{src_node.get('node_type','?')}:{src_code}]")
        lbl2 = _node_security_label(dst_node)
        tag2 = f"[{lbl2}]" if lbl2 else ""
        segments.append(f"--{et}--> {tag2}[{dst_node.get('node_type','?')}:{dst_code}]")
    return " ".join(segments)[:max_len]


def path_evidence_tags(G: nx.MultiDiGraph, path: list, max_len: int = 64) -> str:
    """路径级证据标注头（v15 引入 BUG-19 修复，v16 去除 SAFE 计数）。

    危险侧：该路径节点实际命中的危险 API（SINK=memcpy / FREE=av_free ...）

    与函数级全局 api_hints 标注的区别：良性函数任一处 memcpy 不再污染
    所有路径的标注——每条路径只报告自己的证据。
    v16：v15 曾附加缓解侧 SAFE 守卫计数（SAFE xN），实测为安全锚点
    双刃剑来源之一，随 SAFE 层一并回退（B 方案）。
    """
    danger, seen = [], set()
    for nid in path:
        nd = G.nodes.get(nid, {})
        lbl, api = _node_security_hit(nd)
        if lbl and (lbl, api) not in seen:
            seen.add((lbl, api))
            danger.append(f"{lbl}={api}")
    tags = danger[:4]
    return "|".join(tags)[:max_len]


def _norm_code(s: str) -> str:
    """归一化代码片段（去除全部空白），用于图节点 code 与源码行的匹配。"""
    return "".join(s.split())


def _line_vuln_value(line: str, anchors: set = None, guard_boost: int = 0) -> int:
    """估算一行的漏洞证据价值分（越高越值得保留在 SRC 切片中）。

    anchors: 图锚定代码片段集合（压缩图危险节点 + Top-K 路径节点的 code，
    归一化后的字符串）。行命中锚点说明该行被图检索判定为漏洞相关。
    """
    import re
    low = line.lower()
    v = 0
    # 图锚定：图压缩/路径检索判定为漏洞相关的节点代码出现在本行
    if anchors:
        line_norm = _norm_code(line)
        if len(line_norm) >= 6 and any(a in line_norm for a in anchors):
            v += 12
    # 危险 API（sink/source/alloc/free）
    if re.search(r'\b(?:strcpy|strcat|sprintf|snprintf|system|exec|popen|memcpy|memmove|memset|'
                 r'gets|scanf|fgets|recv|recvfrom|read|fread|malloc|calloc|realloc|free|kfree|'
                 r'kmalloc|kzalloc|strncpy|strncat|copy_from_user|getenv|argv)\b', low):
        v += 10
    # 数组索引 / 指针解引用 / 取地址
    if "[" in line:
        v += 8
    if "->" in line or re.search(r'\*\s*\w', line):
        v += 8
    # 边界/长度比较（越界检测关键）
    if re.search(r'[<>]=?|[!=]=', line):
        v += 5
    # 赋值 / 函数调用
    if re.search(r'\w\s*\(', line) or re.search(r'[=+\-*/%&|^]', line):
        v += 3
    # 控制流
    if re.search(r'^\s*(?:if|else|for|while|switch|case|return|goto|do)\b', line, re.I):
        v += 4
    # v22.1：守卫行**条件化**提权（guard_boost 由调用方按预算扩容状态传入）。
    # v22 无条件 +10 在 1500-3000B 桶实测零和挤占（该桶 len//8<600，预算
    # 恒为 600，守卫行挤掉原证据行）→ TP→FN 9 个、FN 21 个中 19 个
    # raw_answer 引用守卫词判良性——v12h 教训复现。守卫提权仅在 SRC
    # 预算扩容生效的函数（src_budget>600，即 ≥4800B）上启用（+10），
    # 守卫行从扩容的增量预算入选而非零和替换；中短函数回退 v20 行为。
    # （v15 教训边界不变：只保证守卫**原文行**存活于 SRC 切片，不加
    # [SAFE] 标签、不加判词，判定权仍完全在 LLM。）
    if guard_boost and (_SAFE_NULL_RE.search(low) or _SAFE_BOUND_RE.search(low)
                        or _SAFE_SIZE_RE.search(low)):
        v += guard_boost
    # v12h（已回滚）: mitigation 行 +8 加分实验——Acc 56→52 净负
    # （TN→FP 9 vs FP→TN 4，FN→TP 仅 +5），与 v11 朴素证据增强同构：
    # 良性样本拿到更富 mitigation 证据反而判可疑。切片仍保留
    # if (!p) / p=NULL 行（守恒证据），只是不再加权优先。
    # v22 边界说明：与 v12h 的关键差异 = 同版本内 SRC 预算随长度自适应
    # 扩张（600→≤1100）——守卫行从"扩容后的增量预算"中入选（危险行
    # 仍按价值降序优先），而非 v12h 固定 450 预算下与危险行的零和替换。
    # v12h 为单批 100 样本结论（r2 教训：单批噪声 ±4-5 点），v22 上线前
    # 需 300 样本随机批复验；若守卫行挤占导致 FP 回升，优先回退本项。
    return v


def _slice_source(src: str, max_chars: int = 450, anchors: set = None,
                  guard_boost: int = 0) -> str:
    """证据锚定源码切片：仅保留语义关键行，剔除结构性冗余。

    保留：函数签名、控制流（if/else/for/while/switch/case/do/return）、
          赋值/调用/指针/数组操作、goto/label、预处理指令、类型声明。
    剔除：空行、注释、纯括号/分号行。
    连续剔除行超过 3 行时插入 "..." 占位以保持结构感。

    超过 max_chars 时按"漏洞证据价值"优先截断：
      - 图锚定（anchors）：压缩图危险节点/Top-K 路径节点的 code 命中行优先；
      - 文本启发式：危险 API / 数组索引 / 指针解引用 / 边界比较。
    切片因此是"图引导的证据检索"产物，而非纯文本截断。
    """
    import re
    if not src:
        return ""

    keep_pat = re.compile(
        r"(^\s*(?:if|else|for|while|switch|case|default|do|return|goto|break|continue)\b)"
        r"|[=+\-*/%&|^<>!]="  # 赋值/复合赋值/比较
        r"|\w\s*\("          # 函数调用
        r"|->|\[.+\]|\*"    # 指针/数组访问
        r"|^\s*#"            # 预处理
        r"|^\s*\w[\w\s\*,]*\(.*\)\s*\{?\s*$"  # 函数签名/声明
    )

    out_lines = []
    skip_streak = 0
    for line in src.split("\n"):
        stripped = line.strip()
        if not stripped:
            skip_streak += 1
            continue
        # 注释行
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            skip_streak += 1
            continue
        # 纯括号/分号行
        if all(ch in "{}();," for ch in stripped):
            skip_streak += 1
            continue
        if keep_pat.search(line):
            if skip_streak >= 3:
                out_lines.append("...")
            skip_streak = 0
            out_lines.append(line.rstrip())
        else:
            skip_streak += 1

    total = sum(len(l) + 1 for l in out_lines)
    if total <= max_chars:
        return "\n".join(out_lines)

    # 预算内优先保留高价值行（保持原始相对顺序）
    # 函数签名/头部（前 2 行）强制保留
    head = out_lines[:2]
    body = out_lines[2:]
    budget = max_chars - sum(len(l) + 1 for l in head)
    # v22 修复：selected 改存原序索引——原实现以行文本做 picked/order 键：
    #   1) 重复文本行互相覆盖（order 映射到最后一个索引 → 重排错位）；
    #   2) 第三遍未排除 "..." 占位行（3 字符白占预算）；
    #   3) 重复文本行只有第一条能入选。三遍价值分配策略不变。
    # v22 修复 2：索引化后重复行全部可入选——循环体/模板代码的机械重复
    # （如 30 条相同 for 行，实测刷屏吃光预算挤出 memcpy/守卫行）需设
    # 上限。同文本最多 2 条：double-free（free(p) × 2）等"重复即证据"
    # 的模式仍保留，机械膨胀被截断。
    seen_text = {}
    line_scores = {}
    for i, l in enumerate(body):
        if l.strip() == "...":
            continue
        cnt = seen_text.get(l, 0)
        if cnt >= 2:
            continue
        seen_text[l] = cnt + 1
        line_scores[i] = _line_vuln_value(l, anchors, guard_boost)
    selected = set()
    used = 0
    # 第一遍：图锚定 + 高价值行（>=8）优先
    # v12g: 按价值降序分配预算（原为顺序先到先得，头部声明行挤掉尾部证据行，
    # 如 10617 的 buf_end/buf_ptr 初始化被截丢 -> LLM 判 "set elsewhere" 而 FN）
    for i, v in sorted(line_scores.items(), key=lambda x: -x[1]):
        l = body[i]
        if v >= 8 and used + len(l) + 1 <= budget:
            selected.add(i)
            used += len(l) + 1
    # 第二遍：中价值行（>=5）
    for i, v in line_scores.items():
        if i in selected:
            continue
        l = body[i]
        if v >= 5 and used + len(l) + 1 <= budget:
            selected.add(i)
            used += len(l) + 1
    # 第三遍：按顺序补足剩余行（排除 "..." 占位——占位符本身无证据价值，
    # 让位于真实代码行；未截断路径的 skip_streak 占位逻辑不受影响）。
    # 重复上限与 line_scores 构建一致（同文本 ≤2），防止第三遍把
    # 被过滤的机械重复行漏选回来；计数继承前两遍已选中的重复行。
    fill_seen = {}
    for i in selected:
        fill_seen[body[i]] = fill_seen.get(body[i], 0) + 1
    for i, l in enumerate(body):
        if i in selected or l.strip() == "...":
            continue
        cnt = fill_seen.get(l, 0)
        if cnt >= 2:
            continue
        if used + len(l) + 1 <= budget:
            selected.add(i)
            fill_seen[l] = cnt + 1
            used += len(l) + 1

    # 按原顺序重排
    result = head + [body[i] for i in sorted(selected)]
    joined = "\n".join(result)
    if len(joined) > max_chars:
        joined = joined[:max_chars] + "\n..."
    return joined


def _collect_graph_anchors(G, topk_paths) -> set:
    """收集图锚定代码片段：压缩图中危险节点的 code + Top-K 路径节点的 code。

    用于图锚定源码切片：命中锚点的源码行被优先保留，使 SRC 切片成为
    "图压缩 + 路径检索"的产物，与框架主线自洽。
    """
    anchors = set()
    # 危险节点（code 含危险 API 调用）
    for nid, ndata in G.nodes(data=True):
        code = (ndata.get("code") or "").strip()
        if len(code) >= 6:
            anchors.add(_norm_code(code))
    # Top-K 路径节点
    for path in (topk_paths or []):
        for nid in path:
            code = (G.nodes.get(nid, {}).get("code") or "").strip()
            if len(code) >= 6:
                anchors.add(_norm_code(code))
    return anchors


def build_hierarchical_context(
    first_arg,
    second_arg=None,
    third_arg=None,
    fourth_arg=None,
    fifth_arg=None,
    api_hints: dict = None,
) -> str:
    """
    构建完整的层次化上下文 (Hierarchical Context)，供 LLM 消费。

    支持两种调用方式：

    [方式 A - 原始版] 从 GraphEngine 构建，用于 reasoning_loop 内部:
      build_hierarchical_context(G, function_code, function_summary, block_summaries, topk_paths)

    [方式 B - 便捷版] 从已序列化的字符串构建，用于 main.py 直接调用:
      build_hierarchical_context(func_summary, block_summaries, paths_context, state_str)

    api_hints: 从源码提取的安全 API 分类（用于路径级标注）
      {"sink_apis": set(), "source_apis": set(), "alloc_apis": set(), "free_apis": set()}

    四层结构：
      Layer 1: 函数级摘要 - 全局危险行为概览（含 SINK/SOURCE/ALLOC/FREE 标注）
      Layer 2: 基本块级摘要 - 控制流关键语义
      Layer 3: 类型化依赖路径 - 细粒度漏洞传播链（含路径级 API 注解）
      Layer 4: 程序状态记忆 - 变量生命周期追踪
    """
    parts = []

    # 检测调用方式：如果 first_arg 是 MultiDiGraph，走方式 A
    if isinstance(first_arg, nx.MultiDiGraph):
        G = first_arg
        function_code = second_arg
        function_summary = third_arg
        block_summaries = fourth_arg or {}
        topk_paths = fifth_arg or []

        parts.append("SRC:")
        # 图锚定源码切片：压缩图危险节点 + Top-K 路径节点的 code 作为锚点，
        # 命中锚点的源码行优先保留（图引导的证据检索，而非纯文本截断）。
        # 历史 450→900 纯放大对指标中性（旧分配=先到先得，放大多收噪声行）；
        # v12g 改为价值降序分配 + 600：同预算下证据行存活率提高
        anchors = _collect_graph_anchors(G, topk_paths)
        # v22：SRC 预算随函数长度自适应——固定 600 对大函数仅保留 ~6% 行
        # （≥10000B 桶 F1 55.3 vs A 63.1 主因），且 v20 实测 B tok 均值 1017
        # < 1043 目标，预算空间存在。策略：min(1100, max(600, len//8))——
        # <4800B 不变（全分布 65%+ 样本零影响），≥5000B 渐增至 1100。
        # 实测均值增量 ~12 tok（受影响样本 ~8.5% × +100~170 tok）。
        if function_code:
            src_budget = min(1100, max(600, len(function_code) // 8))
            # v22.1：守卫提权仅在预算扩容生效（src_budget>600，≥4800B）时
            # 启用——扩容函数守卫行从增量预算入选；中短函数（预算 600 不变）
            # 回退 v20 行为，避免零和挤占（v22 300 批 1500-3000B 桶实测）。
            gboost = 10 if src_budget > 600 else 0
            src = _slice_source(function_code, max_chars=src_budget,
                                anchors=anchors, guard_boost=gboost)
        else:
            src_budget = 600
            src = ""
        parts.append(src)
        parts.append("")

        parts.append("SUMMARY:")
        fs = function_summary or ""
        if len(fs) > 150:
            fs = fs[:150]
        parts.append(fs)
        parts.append("")

        parts.append("BLOCKS:")
        if block_summaries:
            # v22：SRC 扩容样本压 1 块对冲 token（每块 ~80ch）；短函数保持 2 块
            n_blocks = 1 if src_budget > 600 else 2
            for block_id, summary in list(block_summaries.items())[:n_blocks]:
                if summary:
                    first = summary[0] if isinstance(summary, list) else summary
                    parts.append(f"- B{block_id}: {first}")
        parts.append("")

        # v16：SAFE 缓解证据层已回退（v15 安全锚点双刃剑：TP→FN 12 崩 Rec）。
        # _detect_benign_evidence 仍保留供 build_compact_context 用，但不再
        # 进 Step1 主上下文（B 方案：去掉 SAFE 层，只留危险侧证据 + 路径头）。

        if api_hints:
            api_parts = []
            for label, apis in [
                ("SINK", api_hints.get("sink_apis", set())),
                ("SOURCE", api_hints.get("source_apis", set())),
                ("ALLOC", api_hints.get("alloc_apis", set())),
                ("FREE", api_hints.get("free_apis", set())),
            ]:
                if apis:
                    api_parts.append(f"[{label} {','.join(sorted(apis))}]")
            if api_parts:
                parts.append("APIS: " + " ".join(api_parts))
                parts.append("")

        # v19：GUARD-DOM 事实层已撤下（v18 实证第三次双刃剑：FP 38→31
        # 但 FN 11→17，idx=24383 判词直接引用 "dominat" 当良性依据）。
        # "把守卫证据喂给 LLM" 框架证伪——图特征改为事后仲裁（graph/
        # arbitrate.py），不再进 Step1 上下文。

        parts.append("DEP PATHS:")
        if topk_paths:
            # v14 token 控制：3→2 条（v13_token_audit.json 实证 Top-3 近重复，
            # P1/P2 完整保留，削冗余不削证据）。
            # v15（BUG-03 接线 + BUG-19 路径级标注）：_compact_path（无标签）
            # → _labeled_compact_path（节点级 SINK/SOURCE/ALLOC/FREE 标签），
            # 并加路径级证据头 [SINK=api|FREE=api]——只列该路径实际命中的
            # API。原 compare_devign 的 paths_context（多行详细序列化 + 函数级
            # api_hints）从未传入 reasoning_loop，其意图经此接线落地；函数级
            # 全局标注会在良性样本上把一处 memcpy 放大成所有路径的 SINK 证据
            # （BUG-19），弃用。v16 回退 SAFE 层：证据头不含 SAFE xN、节点
            # 标签不含 [SAFE] 回落（B 方案）。
            # max_len 300→260：标签与证据头占预算，硬上限不变（v14 DEP 层
            # 2×300ch ≈ v15 2×260+头 2×35ch，token 中性交换）。
            # v19：恢复 260（v18 的 240 是 GUARD-DOM 层抵扣，层已撤）。
            # v22：大函数（src_budget>600）扩到 4 条×300ch——固定 2×260 与
            # 函数长度无关，4096 图预算的压缩证据 95% 对 LLM 不可见（token
            # 断裂，各长度桶 B tok 恒定 966-1067 实证）；短函数维持 2×260。
            # TOP_K_PATHS=15 的 ranker 输出在 Step1 仅消费前 2/4 条。
            if src_budget > 600:
                n_dep, dep_max = 4, 300
            else:
                n_dep, dep_max = 2, 260
            for i, path in enumerate(topk_paths[:n_dep]):
                serialized = _labeled_compact_path(G, path, max_len=dep_max)
                if serialized:
                    tags = path_evidence_tags(G, path)
                    head = f" [{tags}]" if tags else ""
                    parts.append(f"P{i+1}{head}: {serialized}")
        else:
            parts.append("  (none)")
        parts.append("")
        parts.append("STATE:")
        if function_code:
            from planning.state_memory import ProgramState
            state = ProgramState()
            state.track_vars(function_code)
            state_str = state.serialize()
            if state_str:
                # 状态串上限 150 字符，控制 token 预算（v6: 200→150）
                parts.append(state_str[:150])
            else:
                parts.append("  (no variable state tracked)")
        else:
            parts.append("  (no source code available for state tracking)")

        return "\n".join(parts)

    else:
        # 方式 B：接收已序列化的字符串
        func_summary = first_arg
        block_summaries = second_arg or {}
        paths_context = third_arg or []
        state_str = fourth_arg or ""

        parts.append("=" * 60)
        parts.append("LAYER 1: FUNCTION-LEVEL SUMMARY")
        parts.append("=" * 60)
        parts.append(func_summary)
        parts.append("")

        # API 上下文：从源码提取的安全 API 分类（补充 DOT 不保留 API 名的问题）
        if api_hints:
            parts.append("=" * 60)
            parts.append("API CONTEXT: security-relevant APIs detected in source")
            parts.append("=" * 60)
            for label, apis in [
                ("SINK", api_hints.get("sink_apis", set())),
                ("SOURCE", api_hints.get("source_apis", set())),
                ("ALLOC", api_hints.get("alloc_apis", set())),
                ("FREE", api_hints.get("free_apis", set())),
            ]:
                if apis:
                    parts.append(f"  [{label}] {', '.join(sorted(apis))}")
            parts.append("")

        parts.append("=" * 60)
        parts.append("LAYER 2: BASIC BLOCK SUMMARY")
        parts.append("=" * 60)
        if block_summaries:
            for block_id, summary in block_summaries.items():
                if summary:
                    parts.append(f"\n--- Block {block_id} ---")
                    parts.append(str(summary))
        else:
            parts.append("  (no block-level summary available)")
        parts.append("")

        parts.append("=" * 60)
        parts.append("LAYER 3: TYPED DEPENDENCY PATHS")
        parts.append("=" * 60)
        if paths_context:
            for i, path_str in enumerate(paths_context):
                parts.append(f"\n--- Path #{i+1} ---")
                parts.append(path_str)
        else:
            parts.append("  (no dependency paths retrieved)")
        parts.append("")

        if state_str:
            parts.append("=" * 60)
            parts.append("LAYER 4: PROGRAM STATE MEMORY")
            parts.append("=" * 60)
            parts.append(state_str)
            parts.append("")

        return "\n".join(parts)


def _extract_dataflow_relations(code: str) -> str:
    """
    从源码中提取关键数据流关系，以紧凑格式呈现。

    识别模式：
      - var = malloc/calloc(...)       → ALLOC flow
      - free(var)                      → FREE flow
      - strcpy/memcpy/sprintf(dst,src) → SINK flow (dst ← src)
      - recv/read(...,buf,...)         → TAINT flow
      - var = expr                     → ASSIGN flow
    """
    import re
    relations = []

    alloc_matches = re.findall(
        r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?(malloc|calloc|realloc|alloca|kmalloc|kzalloc|av_malloc|av_calloc)\s*\(([^)]*)\)',
        code
    )
    for var, func, args in alloc_matches:
        relations.append(f"{var}←{func}({args[:30]})")

    free_matches = re.findall(r'\b(free|kfree|av_free|av_freep|munmap)\s*\(\s*(\w+)\s*\)', code)
    for func, var in free_matches:
        relations.append(f"{var}→{func}()")

    sink_matches = re.findall(
        r'\b(strcpy|strcat|sprintf|memcpy|memmove|gets|scanf)\s*\(\s*([^,)]+)',
        code
    )
    for func, first_arg in sink_matches:
        first_arg = first_arg.strip()
        relations.append(f"{first_arg}←{func}()")

    taint_matches = re.findall(
        r'\b(recv|read|fread|fgets|recvfrom)\s*\([^)]*,\s*([^,)]+)',
        code
    )
    for func, buf in taint_matches:
        buf = buf.strip().lstrip("&")
        relations.append(f"{buf}←{func}()")

    if not relations:
        return ""
    result = " | ".join(relations[:8])
    if len(result) > 200:
        result = result[:200] + ".."
    return result


def _detect_vuln_patterns(code: str) -> str:
    """
    漏洞模式预检测（置信度分级版）。

    返回格式：每个 hint 带置信度标签 [HIGH/MED/LOW]
      - HIGH: 有明确证据链（free→deref 位置确认，tainted source→sink 确认）
      - MED: 有部分证据（malloc 无 NULL 检查，dangerous API 无 bounds）
      - LOW: 仅模式匹配（仅存在 free+malloc，仅存在 dangerous API）

    新增模式：
      - Unchecked return: 关键函数返回值未检查
      - Integer overflow: 乘法结果用于 malloc 参数
      - Off-by-one: 循环边界 <= 而非 <
    """
    import re
    hints = []

    free_vars = re.findall(r'\b(?:free|kfree|av_free|av_freep)\s*\(\s*(\w+)\s*\)', code)
    for var in set(free_vars):
        # BUG-15 修复（2026-09-17 审查报告）：
        #   1. 内层 DOUBLE-FREE 计数词表与外层对齐（原只有 free|kfree，
        #      FFmpeg 里两次 av_freep(p) 不触发提示）
        #   2. UAF 偏移量原用模式字符串长度（≈42 字符）当匹配长度——
        #      free 后 42 字符内的 deref 全部漏检（恰恰是最典型的
        #      紧凑写法 free(p); p->x）。改用 m.end() 实际匹配终点
        free_matches = list(re.finditer(
            rf'\b(?:free|kfree|av_free|av_freep)\s*\(\s*{re.escape(var)}\s*\)', code))
        if len(free_matches) >= 2:
            hints.append(f"[HIGH] DOUBLE-FREE: {var} freed {len(free_matches)} times")
        uaf_confirmed = uaf_possible = False
        for m in free_matches:
            code_after = code[m.end():]
            if re.search(rf'\b{re.escape(var)}\b\s*(?:->|\[|\.\w+\s*\()', code_after):
                hints.append(f"[HIGH] UAF-RISK: {var} used after free")
                uaf_confirmed = True
                break
            if not uaf_possible and re.search(rf'\b{re.escape(var)}\b', code_after):
                uaf_possible = True
        if not uaf_confirmed and uaf_possible:
            hints.append(f"[MED] UAF-POSSIBLE: {var} reused after free (no deref confirmed)")

    unchecked_malloc = re.findall(
        r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc|kmalloc|kzalloc)\s*\([^;]+\);',
        code
    )
    for var in unchecked_malloc:
        null_check = re.search(rf'\b{re.escape(var)}\s*(?:==|!=)\s*(?:NULL|0)\b', code)
        if_not = re.search(rf'if\s*\(\s*!?\s*{re.escape(var)}\b', code)
        early_return = re.search(rf'if\s*\([^)]*!{re.escape(var)}[^)]*\)\s*\{{[^}}]*return', code)
        if not null_check and not if_not and not early_return:
            deref_without_check = re.search(rf'\b{re.escape(var)}\s*(?:->|\.)(?!NULL|0)', code)
            if deref_without_check:
                hints.append(f"[MED] NULL-DEREF-RISK: {var} from malloc unchecked")
            else:
                hints.append(f"[LOW] MALLOC-UNCHECKED: {var} from malloc, no NULL check found")

    unsafe_copy = list(re.finditer(
        r'\b(strcpy|strcat|sprintf|gets)\s*\(\s*(\w+)',
        code
    ))
    for um in unsafe_copy:
        func, dst = um.group(1), um.group(2)
        size_check = re.search(rf'sizeof\s*\(\s*{re.escape(dst)}\s*\)', code)
        # BUG-16 修复：bound_check 原在全文搜索——任何位置出现无关的
        # sizeof/strn 都会抑制该 dst 的 UNSAFE-COPY 提示。限定在调用点
        # 前后 200 字符窗口（边界检查通常紧邻调用）
        window = code[max(0, um.start() - 200): um.end() + 200]
        bound_check = re.search(rf'(?:strn|sn|sizeof).*{re.escape(dst)}', window)
        if not size_check and not bound_check:
            source_taint = re.search(rf'(?:recv|read|fgets|scanf)\s*\([^)]*,\s*[^,)]+,\s*[^)]*{re.escape(dst)}', code)
            if source_taint:
                hints.append(f"[HIGH] OVERFLOW-RISK: {func}({dst}) with tainted source, no bounds check")
            elif func == "gets":
                hints.append(f"[HIGH] OVERFLOW-RISK: gets({dst}) always unsafe")
            else:
                hints.append(f"[LOW] UNSAFE-COPY: {func}({dst}) no bounds check (source unconfirmed)")

    printf_fmt = re.findall(r'\b(?:printf|fprintf)\s*\(\s*([^,)]+)', code)
    for fmt_arg in printf_fmt:
        fmt_arg = fmt_arg.strip()
        if not fmt_arg.startswith('"'):
            hints.append(f"[MED] FMTSTR-RISK: printf with non-literal format")

    unchecked_ret = re.findall(
        r'(?:(?:recv|read|write|send|fopen|malloc|calloc|realloc|socket|connect|accept|ioctl|setsockopt|getsockopt|pthread_create|pthread_mutex_lock)\s*\([^;]*\))\s*;',
        code
    )
    if unchecked_ret:
        count = len(unchecked_ret)
        if count >= 3:
            hints.append(f"[MED] UNCHECKED-RET: {count} critical function returns not checked")

    int_overflow_malloc = re.findall(
        r'(?:malloc|calloc|realloc|kmalloc)\s*\(\s*(\w+)\s*\*\s*(\w+)',
        code
    )
    for a, b in int_overflow_malloc:
        hints.append(f"[LOW] INT-OVERFLOW: {a}*{b} in malloc arg, possible integer overflow")

    loop_le = re.findall(r'for\s*\(\s*[^;]*;\s*(\w+)\s*<=\s*(\w+)\s*;', code)
    for var, bound in loop_le:
        arr_access = re.search(rf'\b{re.escape(var)}\b\s*\[', code)
        if arr_access:
            hints.append(f"[LOW] OFF-BY-ONE: loop {var}<={bound} with array access, possible off-by-one")

    if not hints:
        return ""
    return " | ".join(hints[:8])


def _detect_benign_evidence(code: str) -> str:
    """
    良性证据检测：识别代码中的安全防护措施，帮助 LLM 判断为 SAFE。

    检测模式：
      - NULL 检查：if (ptr == NULL) / if (!ptr)
      - 边界检查：sizeof / strn / snprintf
      - 错误处理：perror / exit / return -1 after check
      - 锁保护：pthread_mutex_lock / unlock 配对
      - 安全替代：strncpy / snprintf / strncat
      - 条件释放：if (ptr) free(ptr)
      - 返回值检查：if (recv() < 0) / if (fopen() == NULL)
    """
    import re
    evidence = []

    null_checks = re.findall(r'if\s*\(\s*(\w+)\s*(?:==|!=)\s*(?:NULL|0)\s*\)', code)
    if_not_checks = re.findall(r'if\s*\(\s*!\s*(\w+)\s*\)', code)
    all_null = set(null_checks + if_not_checks)
    if all_null:
        evidence.append(f"NULL-CHECK: {', '.join(list(all_null)[:6])}")

    # BUG-16 修复：memcpy 是 DANGEROUS_APIS/BACKSTOP 核心成员，带错误
    # 长度的 memcpy 正是经典溢出 sink——[SAFE] 标注会压掉真漏洞（FN）
    safe_copies = re.findall(r'\b(strncpy|snprintf|strncat)\s*\(', code)
    if safe_copies:
        evidence.append(f"SAFE-COPY: {len(safe_copies)} bounded copy functions")

    sizeof_checks = re.findall(r'sizeof\s*\(\s*(\w+)\s*\)', code)
    if sizeof_checks:
        evidence.append(f"SIZEOF: {', '.join(sizeof_checks[:6])}")

    error_handling = re.findall(r'\b(?:perror|exit|return\s+-1|return\s+NULL|goto\s+err|goto\s+fail|goto\s+cleanup)\b', code)
    if len(error_handling) >= 2:
        evidence.append(f"ERR-HANDLE: {len(error_handling)} error handling paths")

    mutex_lock = re.findall(r'pthread_mutex_lock\s*\(', code)
    mutex_unlock = re.findall(r'pthread_mutex_unlock\s*\(', code)
    if mutex_lock and mutex_unlock:
        evidence.append(f"MUTEX: {len(mutex_lock)} lock/unlock pairs")

    free_in_error = re.findall(r'goto\s+(?:err|fail|cleanup|out)', code)
    free_after_goto = re.findall(r'(?:err|fail|cleanup|out)\s*:\s*(?:[^;]*\bfree\b)', code)
    if free_after_goto:
        evidence.append(f"CLEANUP-PATH: free in error cleanup path")

    conditional_free = re.findall(r'if\s*\(\s*(\w+)\s*\)\s*\{?\s*(?:free|kfree)\s*\(\s*\1\s*\)', code)
    if conditional_free:
        evidence.append(f"COND-FREE: {len(conditional_free)} conditional frees")

    ret_checks = re.findall(r'if\s*\(\s*(?:\w+\s*=\s*)?(?:recv|read|fopen|malloc|calloc|realloc)\s*\([^)]*\)\s*(?:==|!=|<|>=|<=)\s*', code)
    if ret_checks:
        evidence.append(f"RET-CHECK: {len(ret_checks)} return value checks")

    if not evidence:
        return ""
    return " | ".join(evidence[:7])


def _split_by_control_flow(code: str) -> list:
    import re
    lines = code.split('\n')
    blocks = []
    current_block = []
    control_keywords = re.compile(
        r'^\s*(if\s*\(|else\s*(?:if\s*\()?|for\s*\(|while\s*\(|do\s*\{|switch\s*\(|case\s|default\s*:|return\b|break\b|continue\b|goto\b|\})'
    )
    for line in lines:
        stripped = line.strip()
        if not stripped:
            if current_block:
                blocks.append('\n'.join(current_block))
                current_block = []
            continue
        if control_keywords.match(line) and current_block:
            blocks.append('\n'.join(current_block))
            current_block = []
        current_block.append(line)
    if current_block:
        blocks.append('\n'.join(current_block))
    merged = [b for b in blocks if b.strip()]
    if not merged:
        merged = [code]
    return merged


def build_compact_context(
    G: nx.MultiDiGraph,
    function_code: str,
    function_summary: str,
    block_summaries: dict,
    topk_paths: list,
) -> str:
    """
    分层图线性化上下文（研究计划 §4 三层表示 + §6 程序状态记忆）。

    核心策略：标注引导 + 安全关键区域实际代码
    - 结构化标注（[HINT]/[SAFE]/[DATAFLOW]/[STATE]）引导 LLM 注意力
    - 安全关键区域保留实际代码（[DANGER] ±3行上下文）
    - 非安全区域仅保留摘要，节省 token
    """
    import re
    parts = []

    func_sig = ""
    if function_code:
        sig_match = re.search(
            r'((?:static\s+)?(?:inline\s+)?(?:const\s+)?\w+(?:\s+\*+)?\s+\w+\s*\([^)]*\))',
            function_code
        )
        if sig_match:
            func_sig = sig_match.group(1).strip()[:80]

    if func_sig:
        parts.append(f"[FUNC] {func_sig}")
    parts.append(f"[SUMM] {function_summary}")

    if function_code:
        vuln_hints = _detect_vuln_patterns(function_code)
        if vuln_hints:
            parts.append(f"[HINT] {vuln_hints}")

    if function_code:
        benign_ev = _detect_benign_evidence(function_code)
        if benign_ev:
            parts.append(f"[SAFE] {benign_ev}")

    if function_code:
        df = _extract_dataflow_relations(function_code)
        if df:
            parts.append(f"[DATAFLOW] {df}")

    if function_code:
        from planning.state_memory import ProgramState
        state = ProgramState()
        state.track_vars(function_code)
        state_str = state.serialize()
        if state_str:
            compact_state = state_str.replace("\n", " ").strip()
            if len(compact_state) > 300:
                compact_state = compact_state[:400] + ".."
            parts.append(f"[STATE] {compact_state}")

    path_lines = []
    for i, path in enumerate(topk_paths[:7]):
        if len(path) < 2:
            continue
        nodes = []
        labels = set()
        for j, nid in enumerate(path[:8]):
            nd = G.nodes.get(nid, {})
            code = nd.get("code", nd.get("name", "?")).strip()
            if len(code) > 60:
                code = code[:60] + ".."
            ntype = nd.get("node_type", "?")
            lbl = _node_security_label(nd)
            if lbl:
                labels.add(lbl)
            nodes.append(f"{ntype[:3]}:{code}")
        label_str = f"[{''.join(sorted(labels))}]" if labels else ""
        path_line = f"P{i+1}{label_str} " + " -> ".join(nodes)
        path_lines.append(path_line)
    if path_lines:
        parts.append("[PATHS]")
        for pl in path_lines:
            parts.append(f"  {pl}")

    lines = function_code.split('\n') if function_code else []
    danger_pattern = re.compile(
        r'\b(free|kfree|av_free|malloc|calloc|realloc|strcpy|strcat|sprintf|vsprintf|memcpy|memmove|gets|scanf|system|execve|popen|recv|read|fread|fopen|open|printf|fprintf)\s*\('
    )
    danger_line_indices = set()
    for li, line in enumerate(lines):
        if danger_pattern.search(line):
            for offset in range(-3, 4):
                danger_line_indices.add(li + offset)

    if function_code:
        assign_pattern = re.compile(r'\b\w+\s*=\s*(?:malloc|calloc|realloc|recv|read|fopen)\s*\(')
        for li, line in enumerate(lines):
            if assign_pattern.search(line):
                for offset in range(-1, 3):
                    danger_line_indices.add(li + offset)

    if danger_line_indices:
        parts.append("[CODE]")
        sorted_indices = sorted(danger_line_indices)
        groups = []
        current_group = [sorted_indices[0]]
        for idx in sorted_indices[1:]:
            if idx - current_group[-1] <= 3:
                current_group.append(idx)
            else:
                groups.append(current_group)
                current_group = [idx]
        groups.append(current_group)

        code_budget = 2500
        used = 0
        for group in groups:
            if used >= code_budget:
                break
            start = max(0, group[0] - 1)
            end = min(len(lines), group[-1] + 2)
            for li in range(start, end):
                if used >= code_budget:
                    break
                if 0 <= li < len(lines):
                    marker = ">>>" if li in danger_line_indices else "   "
                    line_text = lines[li].rstrip()
                    if len(line_text) > 100:
                        line_text = line_text[:100] + ".."
                    parts.append(f"  {marker} L{li+1}: {line_text}")
                    used += len(line_text) + 10

    return "\n".join(parts)