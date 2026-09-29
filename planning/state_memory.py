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

        # 1) 提取所有声明：包括 typedef 类型、struct、uintX_t 等
        #    匹配: TYPE *name; , TYPE *name = ..., TYPE name[N], TYPE name = ...
        local_vars = re.findall(
            r'(?:\b(?:int|char|void|float|double|long|short|unsigned|signed|size_t|uint\d+_t|int\d+_t|uintptr_t|ssize_t|off_t|bool|FILE|struct\s+\w+|union\s+\w+|const)\s+\*?)\s*(\w+)\s*(?:\[[^\]]*\])?\s*(?:[=;])',
            code
        )
        # 补充: 匹配带初始化的复杂声明: type *name = (type *)malloc(...)
        local_vars += re.findall(
            r'\*?\s*(\w+)\s*=\s*(?:\(\s*\w+\s*\*\s*\)\s*)?(?:malloc|calloc|realloc|av_malloc|kmalloc)\(',
            code
        )

        for var in local_vars:
            if var in {"if", "else", "while", "for", "return", "sizeof",
                       "switch", "case", "struct", "static", "const",
                       "typedef", "enum", "union", "break", "continue",
                       "goto", "do", "extern", "volatile", "inline"}:
                continue
            if var not in self.states and len(var) > 0:
                self.states[var] = []

        # 2) 函数参数：从函数定义中提取
        func_params = re.findall(
            r'\b\w+\s+\w+\s*\(([^)]*)\)\s*\{',
            code, re.DOTALL
        )
        for params_str in func_params:
            # 末尾支持 $ 以匹配单参数无逗号/无右括号的情况
            params = re.findall(
                r'(?:const\s+)?(?:\w+(?:\s+\w+)?(?:\s*\*)?)\s+(\w+)\s*(?:\[[^\]]*\])?\s*(?:,|\)|$)',
                params_str
            )
            for var in params:
                if var not in self.states and len(var) > 0 and var not in {"void"}:
                    self.states[var] = []

        # 3) 追踪结构体成员访问
        struct_deref = re.findall(r'(\w+)->(\w+)', code)
        tracked_vars = set(self.states.keys())
        for parent, member in struct_deref:
            full_path = f"{parent}->{member}"
            if parent in tracked_vars and full_path not in self.states:
                self.states[full_path] = [{
                    "state": "dereferenced",
                    "source": "source_code",
                    "step": 0,
                }]

        # 4) 追踪分配：支持强制类型转换和更灵活的模式
        alloc_call = re.findall(
            r'(?P<var>\w+)\s*=\s*(?:\([^)]*\)\s*)?(?P<func>malloc|calloc|realloc|alloca|mmap|av_malloc|av_calloc|av_mallocz|av_malloc_array|kmalloc|kzalloc)\s*\(',
            code
        )
        for var, func in alloc_call:
            if var not in self.states:
                self.states[var] = []
            self.states[var].append({
                "state": "allocated",
                "source": func,
                "step": 0,
            })

        # 5) 追踪释放
        free_call = re.findall(r'\b(free|av_free|kfree|av_freep|munmap)\s*\(\s*(\w+)\s*\)', code)
        for func, var in free_call:
            if var not in self.states:
                self.states[var] = []
            self.states[var].append({
                "state": "freed",
                "source": func,
                "step": 0,
            })

        # 6) 追踪污点源：recv/read/scanf 等
        for source in ["recv", "read", "scanf", "fgets", "getenv", "argv", "recvfrom", "recvmsg"]:
            taint_call = re.findall(
                rf'(?:{source})\s*\([^)]*(?:,\s*((?:&)?\w+)\s*[,)])',
                code
            )
            for var in taint_call:
                var = var.lstrip("&")
                if var not in self.states:
                    self.states[var] = []
                self.states[var].append({
                    "state": "tainted",
                    "source": source,
                    "step": 0,
                })

        # 7) 追踪解引用
        deref_calls = re.findall(r'\*(\w+)\s*(?:=|\[)', code)
        for var in deref_calls:
            if var and var in self.states:
                self.states[var].append({
                    "state": "dereferenced",
                    "source": "source_code",
                    "step": 0,
                })

        # 8) 追踪空指针检查
        null_checks = re.findall(r'(\w+)\s*(?:!=\s*NULL|==\s*NULL|==\s*0)', code)
        null_checks += re.findall(r'!\s*(\w+)(?:\s*\()', code)
        for var in null_checks:
            if var in self.states:
                self.states[var].append({
                    "state": "null-checked",
                    "source": "source_code",
                    "step": 0,
                })

        # 9) 追踪数组/指针索引访问
        index_access = re.findall(r'(\w+)\s*\[\s*\w+\s*\]', code)
        for var in index_access:
            if var in self.states:
                self.states[var].append({
                    "state": "indexed",
                    "source": "source_code",
                    "step": 0,
                })

        # 10) 追踪所有赋值操作（为已捕获变量记录 assigned）
        # (?!=) 排除 == 比较，避免把 if (x == NULL) 记成赋值（原 \w+\s*= 会命中）
        all_assigns = re.findall(r'\b(\w+)\s*=(?!=)', code)
        for var in all_assigns:
            if var in self.states and var not in {"if", "for", "while", "switch", "else"}:
                self.states[var].append({
                    "state": "assigned",
                    "source": "source_code",
                    "step": 0,
                })

        # 11) 追踪返回值检查模式（研究计划 Stage 6: Program State Memory）
        #     识别变量是否在赋值后被用于条件检查
        for var in list(self.states.keys()):
            # 跳过太短的变量名（通常是关键字误匹配）
            if len(var) <= 1:
                continue
            # 检查变量是否被用于比较检查
            if re.search(rf'\b{re.escape(var)}\s*(>=|<=|>|<|==|!=)\s*(-?\d+|NULL)', code):
                comparison = re.search(rf'\b{re.escape(var)}\s*(>=|<=|>|<|==|!=)\s*(-?\d+|NULL)', code)
                if comparison:
                    op = comparison.group(1)
                    val = comparison.group(2)
                    # 分类检查类型
                    if op in ('==', '!=') and val in ('0', 'NULL'):
                        check_type = "null-checked"
                    elif op in ('<', '>', '<=', '>=') and val in ('0', '-1'):
                        check_type = "error-checked"
                    else:
                        check_type = "checked"
                    self.states[var].append({
                        "state": check_type,
                        "source": f"{op} {val}",
                        "step": 0,
                    })