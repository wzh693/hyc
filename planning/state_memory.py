"""
程序状态记忆模块 (Program State Memory)。

维护关键变量的生命周期状态，包括：
  - allocated: 已分配
  - freed: 已释放
  - tainted: 已污染
  - dereferenced: 已解引用
  - alias-propagated: 别名传播
  - null-checked: 已空指针检查
  - bounds-checked: 已边界检查

通过显式状态跟踪，降低 LLM 在长距离分析中的状态遗忘问题。
"""


def create_program_state():
    """Single opt-in factory; legacy behavior remains the default."""
    from config import OBSERVED_STATE_CANDIDATE
    if OBSERVED_STATE_CANDIDATE:
        from planning.observed_state import ObservedProgramState
        return ObservedProgramState()
    return ProgramState()


class ProgramState:

    VALID_STATES = {
        "allocated",
        "freed",
        "tainted",
        "dereferenced",
        "alias-propagated",
        "null-checked",
        "bounds-checked",
        "error-checked",
        "checked",
        "indexed",
        "assigned",
    }

    def __init__(self):
        self.states = {}  # var_name -> list of {"state", "source", "step"}

    def update(self, var: str, state: str, source_node: str = "", step: int = 0):
        """
        更新变量状态。
        参数:
            var: 变量名
            state: 状态值（必须在 VALID_STATES 中）
            source_node: 触发状态变更的节点 ID
            step: 推理步数
        """
        if state not in self.VALID_STATES:
            raise ValueError(
                f"Invalid state '{state}'. Valid: {self.VALID_STATES}"
            )
        if var not in self.states:
            self.states[var] = []
        # 同一图节点可能出现在多条路径、多个推理步骤中；它仍是同一个
        # 程序事件，重复记录会把一次 free 伪造成 double-free。
        if any(h["state"] == state and h["source"] == source_node
               for h in self.states[var]):
            return
        self.states[var].append({
            "state": state,
            "source": source_node,
            "step": step,
        })

    def get_state(self, var: str) -> list:
        """获取变量的状态历史。"""
        return self.states.get(var, [])

    def get_current_state(self, var: str) -> str:
        """获取变量当前最新状态。"""
        history = self.states.get(var, [])
        if not history:
            return "unknown"
        return history[-1]["state"]

    def is_freed_and_used(self, var: str) -> bool:
        """
        检查 Use-After-Free 模式：
        变量被 free 后又出现 dereferenced。
        """
        history = self.states.get(var, [])
        states = [h["state"] for h in history]
        try:
            freed_idx = max(i for i, s in enumerate(states) if s == "freed")
            deref_after = any(
                s == "dereferenced" for s in states[freed_idx + 1:]
            )
            return deref_after
        except ValueError:
            return False

    def is_double_free(self, var: str) -> bool:
        """
        检查 Double Free 模式：
        同一变量被 free 两次或以上。
        """
        history = self.states.get(var, [])
        free_count = sum(1 for h in history if h["state"] == "freed")
        return free_count >= 2

    def is_taint_propagation(self, var: str) -> bool:
        """
        检查污点传播模式：
        tainted -> alias-propagated -> dereferenced
        """
        history = self.states.get(var, [])
        states = [h["state"] for h in history]
        return "tainted" in states and (
            "dereferenced" in states or "alias-propagated" in states
        )

    def is_null_pointer_deref(self, var: str) -> bool:
        """
        检查空指针解引用风险模式：
        变量被解引用但从未做过 NULL 检查。
        （原实现"deref 出现在 null-check 之后"实际是安全模式 if(!p) return; p->x，逻辑反了）
        """
        history = self.states.get(var, [])
        states = [h["state"] for h in history]
        return "dereferenced" in states and "null-checked" not in states

    def dump(self) -> str:
        """
        导出当前状态，供 LLM 消费。
        输出格式:  var_name: state1(step1) -> state2(step2) -> ...
        """
        lines = []
        for var, history in self.states.items():
            state_chain = " -> ".join(
                f"{h['state']}(step{h['step']})" for h in history
            )
            lines.append(f"  {var}: {state_chain}")
        if not lines:
            return "  (no variables tracked)"
        return "\n".join(lines)

    def serialize(self) -> str:
        """
        dump() 的别名，供外部模块统一调用。
        """
        return self.dump()

    def track_vars(self, code: str):
        """
        从源代码中提取并初始化所有变量的状态跟踪。
        扫描代码中的内存分配、释放、解引用等操作，
        为后续推理提供初始程序状态记忆。

        支持的检测模式：
          - malloc/calloc → allocated
          - free → freed
          - recv/read/scanf → tainted
          - *ptr = / ptr[i] → dereferenced
          - == NULL / != NULL → null-checked
          - sizeof / if (len <) → bounds-checked
        """
        import re

        keywords = {"if", "else", "while", "for", "return", "sizeof", "switch",
                    "case", "struct", "static", "const", "typedef", "enum", "union",
                    "break", "continue", "goto", "do", "extern", "volatile", "inline",
                    "void"}
        events = []  # (source offset, priority, variable, state, source)

        def add_event(pos, var, state, source, priority=1):
            var = (var or "").lstrip("&*")
            if not var or var in keywords:
                return
            self.states.setdefault(var, [])
            events.append((pos, priority, var, state, source))

        # Declarations and parameters establish the tracked variable universe.
        decl_re = re.compile(
            r'\b(?:const\s+)?(?:struct\s+\w+|union\s+\w+|unsigned|signed|long|short|'
            r'int|char|void|float|double|size_t|u?int\d+_t|uintptr_t|ssize_t|off_t|bool|FILE)'
            r'(?:\s+\w+)*\s+\**\s*(\w+)')
        for m in decl_re.finditer(code):
            if m.group(1) not in keywords:
                self.states.setdefault(m.group(1), [])

        alloc_re = re.compile(
            r'\b(\w+)\s*=\s*(?:\([^;=]*?\)\s*)?'
            r'(malloc|calloc|realloc|alloca|mmap|av_malloc|av_calloc|av_mallocz|'
            r'av_malloc_array|kmalloc|kzalloc)\s*\(')
        for m in alloc_re.finditer(code):
            add_event(m.start(), m.group(1), "allocated", m.group(2))

        free_re = re.compile(r'\b(free|av_free|kfree|av_freep|munmap)\s*\(\s*([&*]?\w+)')
        for m in free_re.finditer(code):
            add_event(m.start(), m.group(2), "freed", m.group(1))

        # Source APIs have different argument positions; capture the buffer argument explicitly.
        taint_patterns = [
            ("buffer_second", re.compile(
                r'\b(recv|recvfrom|recvmsg|read)\s*\([^,]*,\s*&?(\w+)')),
            ("buffer_first", re.compile(r'\b(fread|fgets|gets)\s*\(\s*&?(\w+)')),
            ("scanf", re.compile(r'\b(scanf|sscanf|fscanf)\s*\([^,]*,\s*&?(\w+)')),
            ("getenv", re.compile(r'\b(\w+)\s*=\s*(getenv)\s*\(')),
        ]
        for family, rx in taint_patterns:
            for m in rx.finditer(code):
                if family == "getenv":
                    add_event(m.start(), m.group(1), "tainted", m.group(2))
                else:
                    add_event(m.start(), m.group(2), "tainted", m.group(1))

        for m in re.finditer(r'\b(\w+)\s*->\s*\w+', code):
            add_event(m.start(), m.group(1), "dereferenced", "source_code")
        for m in re.finditer(r'\b(\w+)\s*\[[^\]]+\]', code):
            add_event(m.start(), m.group(1), "indexed", "source_code")
            add_event(m.start(), m.group(1), "dereferenced", "source_code")
        for m in re.finditer(r'(?<![\w)])\*\s*(\w+)', code):
            line_start = code.rfind("\n", 0, m.start()) + 1
            prefix = code[line_start:m.start()]
            if not re.search(r'\b(?:char|int|void|long|short|float|double|struct\s+\w+)\s*$', prefix):
                add_event(m.start(), m.group(1), "dereferenced", "source_code")

        null_rx = re.compile(
            r'\b(\w+)\s*(?:==|!=)\s*(?:NULL|0)\b|!\s*(\w+)\b|'
            r'\b(\w+)\s*\?')
        for m in null_rx.finditer(code):
            add_event(m.start(), next(g for g in m.groups() if g),
                      "null-checked", "source_code")

        cmp_rx = re.compile(r'\b(\w+)\s*(>=|<=|>|<|==|!=)\s*(-?\d+|NULL)')
        for m in cmp_rx.finditer(code):
            op, val = m.group(2), m.group(3)
            if op in ("==", "!=") and val in ("0", "NULL"):
                state = "null-checked"
            elif op in ("<", ">", "<=", ">=") and val in ("0", "-1"):
                state = "error-checked"
            else:
                state = "checked"
            add_event(m.start(), m.group(1), state, f"{op} {val}")

        for m in re.finditer(r'\b(\w+)\s*=(?!=)', code):
            # 同一源码位置的普通赋值先于更具体的 allocated/tainted 事件，
            # 避免 `p = malloc(...)` 的最终状态被泛化的 assigned 覆盖。
            add_event(m.start(), m.group(1), "assigned", "source_code", priority=0)

        # Preserve actual source order; this is essential for UAF and null-deref checks.
        for _, _, var, state, source in sorted(events, key=lambda x: (x[0], x[1])):
            self.states[var].append({"state": state, "source": source, "step": 0})
