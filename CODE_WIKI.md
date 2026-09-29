# HGL-Vul Code Wiki

> **HGL-Vul** (Hierarchical Graph Linearization for Vulnerability Reasoning)
> 面向长距离漏洞推理的分层图线性化框架 v2.0

---

## 1. 项目概述

HGL-Vul 是一个基于**代码属性图（CPG）+ 大语言模型（LLM）**的长距离程序漏洞检测框架。其核心思想是：不直接将完整 CPG 展平为 token 序列，而是通过**层次化图压缩 + 局部子图动态展开 + 受限图推理**，在有限上下文预算下保留漏洞相关的关键程序依赖信息。

### 核心创新点

1. **漏洞感知图压缩**（Vulnerability-aware Graph Summarization）：动态 Token 预算感知的自适应图压缩，保留高价值依赖结构。
2. **层次化图线性化**（Hierarchical Graph Linearization）：函数级摘要 → 基本块级摘要 → 类型化依赖路径，三层表示。
3. **受限图推理**（Constraint-Guided Reasoning）：LLM 仅通过预定义动作集合与图引擎交互，避免推理漂移。
4. **程序状态记忆**（Program State Memory）：显式跟踪变量生命周期，降低长距离推理中的状态遗忘。

### 支持的漏洞类型

| 漏洞类型 | 说明 |
|---------|------|
| Use-After-Free (UAF) | 内存释放后再次解引用 |
| Double Free | 同一内存被释放两次 |
| Buffer Overflow | 不安全的内存拷贝（无边界检查） |
| Taint-style | 用户输入到达危险函数 |
| Null Pointer Dereference | 空指针解引用 |
| Memory Leak | 分配的内存未在所有路径释放 |

---

## 2. 整体架构

系统采用**六阶段流水线**架构：

```
Source Code
    │
    ▼
┌─────────────────────────┐
│  (1) CPG Construction   │  Joern 解析 → AST+CFG+DFG+CALL 统一图
└─────────────────────────┘
    │
    ▼
┌─────────────────────────┐
│  (2) Graph Summarization│  漏洞感知压缩 + 动态 Token 预算
└─────────────────────────┘
    │
    ▼
┌─────────────────────────┐
│  (3) Path Retrieval     │  候选路径提取 + Top-K 智能排序
└─────────────────────────┘
    │
    ▼
┌─────────────────────────┐
│  (4) Hierarchical Lin.  │  函数摘要 + 块摘要 + 类型化路径
└─────────────────────────┘
    │
    ▼
┌─────────────────────────┐
│  (5) Adaptive Planning  │  受限动作集合 + 程序状态记忆
└─────────────────────────┘
    │
    ▼
┌─────────────────────────┐
│  (6) Reasoning & Report │  LLM 多轮推理 + 证据链生成
└─────────────────────────┘
    │
    ▼
Vulnerability Report (JSON)
```

### 推理状态机

推理循环采用**五阶段状态机**：

1. **漏洞类型假设**（HYPOTHESIS）
2. **数据传播分析**（ExpandDFG）
3. **控制流可达性验证**（ExpandCFG）
4. **危险操作关联分析**（ExpandCALL / RetrieveAlias）
5. **漏洞结论生成**（SummarizeEvidence）

---

## 3. 目录结构

```
HGL-Vul/
├── config.py                     # 全局配置（Joern/LLM/API 集合/数据集）
├── main.py                       # 入口：模式分发
├── requirements.txt              # Python 依赖
│
├── graph/                        # 阶段 1-2：图构建与压缩
│   ├── build_cpg.py              # Joern CPG 构建
│   ├── load_graph.py             # 图加载（JSON/DOT 双格式）
│   ├── summarize_graph.py        # 漏洞感知图压缩 v2.0
│   └── graph_engine.py           # 受限图查询引擎
│
├── retrieval/                    # 阶段 3：智能路径检索
│   ├── candidate_paths.py        # 候选路径提取（两阶段 API 映射）
│   ├── path_ranker.py            # 切片感知路径排序 v2.0
│   └── retrieve_topk.py          # Top-K 路径检索
│
├── linearization/                # 阶段 4：层次化线性化
│   ├── function_summary.py       # 函数级摘要
│   ├── block_summary.py          # 基本块级摘要
│   └── typed_paths.py            # 类型化依赖路径 + 紧凑上下文
│
├── planning/                     # 阶段 5：自适应检索调度
│   ├── actions.py                # 预定义动作集合
│   ├── planner.py                # 检索规划器（JSON/关键词双模式）
│   └── state_memory.py           # 程序状态记忆
│
├── reasoning/                    # 阶段 6：受限漏洞推理
│   ├── prompts.py                # LLM Prompt 模板
│   ├── llm_api.py                # LLM API 封装（含重试）
│   ├── reasoning_loop.py         # 推理主循环 + 漏洞检测入口
│   └── explanation.py            # 漏洞证据链生成
│
├── modes/                        # 运行模式入口
│   ├── analyze.py                # 单文件漏洞分析
│   ├── evaluate_hgl.py           # HGL-Vul 完整评测（跳数分层）
│   ├── evaluate_devign.py        # Devign 数据集评测
│   ├── evaluate_direct_llm.py    # Direct LLM 基线
│   ├── compare_devign.py         # 三组对比实验
│   ├── ablation.py               # 消融实验
│   ├── robustness_eval.py        # 鲁棒性评估
│   └── generate_synthetic.py     # 合成数据集生成
│
├── evaluation/                   # 评测指标
│   ├── metrics.py                # 标准 + 长距离指标
│   ├── ablation.py               # 消融实验逻辑
│   ├── robustness.py             # 鲁棒性评估逻辑
│   └── compare_direct_vs_hgl.py  # 对比逻辑
│
├── data/                         # 数据集
│   ├── synthetic/                # 合成 C 代码样本
│   ├── synthetic_generator.py    # 合成数据生成器
│   ├── vuln_dataset_loader.py    # 通用漏洞数据集加载
│   └── devign_loader.py          # Devign 数据集加载
│
└── output/                       # 运行输出（CPG/报告/结果）
```

---

## 4. 主要模块职责

### 4.1 `graph/` — 图构建与压缩

| 文件 | 职责 |
|------|------|
| `build_cpg.py` | 调用 Joern 将 C 源码解析为 CPG（`cpg.bin`），再导出为 DOT/JSON |
| `load_graph.py` | 从 Joern 导出的 `nodes.json/edges.json` 或 `export.dot` 加载 `networkx.MultiDiGraph` |
| `summarize_graph.py` | 漏洞感知图压缩：节点/边重要性打分、动态 Token 预算调整、切片感知压缩 |
| `graph_engine.py` | `GraphEngine` 类：封装受限图遍历（数据流/控制流/调用/别名/可达性） |

### 4.2 `retrieval/` — 智能路径检索

| 文件 | 职责 |
|------|------|
| `candidate_paths.py` | 从安全相关节点出发提取候选依赖路径（支持 Joern 4.x DOT 两阶段映射） |
| `path_ranker.py` | 切片感知路径排序：生命周期完整度、source-sink 完整性、控制条件覆盖度 |
| `retrieve_topk.py` | 调用 `rank_paths` 返回 Top-K 漏洞相关路径 |

### 4.3 `linearization/` — 层次化线性化

| 文件 | 职责 |
|------|------|
| `function_summary.py` | 函数级摘要：SINK/SOURCE/ALLOC/FREE 标注 + 条件释放/循环危险检测 |
| `block_summary.py` | 基本块级摘要：单行紧凑输出，标签优先突出内存/安全操作 |
| `typed_paths.py` | 类型化依赖路径序列化 + `build_hierarchical_context`/`build_compact_context` |

### 4.4 `planning/` — 自适应检索调度

| 文件 | 职责 |
|------|------|
| `actions.py` | 预定义动作集合 `ACTIONS` 及关键词映射 `ACTION_KEYWORDS` |
| `planner.py` | `RetrievalPlanner` 类：JSON Action 解析 + 关键词回退 + Agent 守卫 |
| `state_memory.py` | `ProgramState` 类：变量生命周期跟踪 + UAF/DoubleFree/Taint 模式检测 |

### 4.5 `reasoning/` — 受限漏洞推理

| 文件 | 职责 |
|------|------|
| `prompts.py` | `SYSTEM_PROMPT` + `build_user_prompt` + 扁平化 prompt（消融用） |
| `llm_api.py` | `query_llm` / `query_llm_with_retry`，OpenAI 兼容接口 |
| `reasoning_loop.py` | `reasoning_loop` 多轮推理状态机 + `run_vuln_detection` 轻量入口 |
| `explanation.py` | `generate_explanation` 生成完整漏洞证据链报告 |

---

## 5. 关键类与函数说明

### 5.1 图模块

#### `build_cpg(code_path, output_dir) -> str`
- **位置**: `graph/build_cpg.py`
- **功能**: 使用 Joern 构建 CPG。在无空格临时目录构建以避免路径/编码问题。
- **返回**: 导出目录路径（含 `export.dot`）。

#### `load_graph(nodes_file, edges_file) -> nx.MultiDiGraph`
- **位置**: `graph/load_graph.py`
- **功能**: 自动识别 JSON 或 DOT 格式加载 CPG。支持 Joern 4.x DOT 解析（正则提取 label/CODE/LINE_NUMBER 等）。
- **节点属性**: `code`, `node_type`, `name`, `line_number`, `method`
- **边属性**: `edge_type`

#### `summarize_graph(G, token_budget=None, source_code="") -> nx.MultiDiGraph`
- **位置**: `graph/summarize_graph.py`
- **功能**: 漏洞感知图压缩。
  - `detect_vuln_type_hint(code)` 检测漏洞类型（UAF/DoubleFree/Overflow/NullDeref/FmtStr/Generic）
  - `score_node(G, node_id, vuln_type)` 六维节点打分（节点类型/危险API/污点源/内存操作/度中心性/DFG-CFG参与度）
  - `score_edge(G, u, v, key)` 边重要性打分（REACHING_DEF/DFG 优先级最高）
  - `_adjust_threshold_for_budget(...)` 二分查找动态调整阈值以适配 Token 预算
- **返回**: 压缩子图，附带 `reduction_stats`（节点/边/token 缩减率）。

#### `class GraphEngine`
- **位置**: `graph/graph_engine.py`
- **核心方法**:
  - `expand_dataflow(node_id, max_hop=6)`: 沿 DFG/REACHING_DEF 双向扩展
  - `expand_controlflow(node_id, max_hop=6)`: 沿 CFG 双向扩展
  - `expand_call(node_id, max_hop=4)`: 沿 CALL 双向扩展（跨函数）
  - `retrieve_alias(node_id, max_hop=4)`: 沿 ALIAS_OF/REF 扩展
  - `check_reachability(source, sink) -> bool`: 可达性检查
  - `find_path(source, sink) -> list`: 最短路径

### 5.2 检索模块

#### `extract_all_candidate_paths(G, source_code=None, max_hop=MAX_PATH_HOP) -> list`
- **位置**: `retrieval/candidate_paths.py`
- **功能**: 两阶段起点识别：
  1. 从源码正则提取安全 API 调用名
  2. 映射到 Joern DOT 节点（POST_DOMINATE/BINDS/DOMINATE）
  3. 回退：按 DOT `node_type` 筛选
- 按边类型优先级遍历（数据流 > 控制流 > 调用 > AST）。

#### `rank_paths(G, paths, top_k=0, vuln_type="Generic") -> list`
- **位置**: `retrieval/path_ranker.py`
- **功能**: 切片感知路径排序。维度：
  1. 变量生命周期完整度（UAF/DF 模式匹配）
  2. source-sink 完整性
  3. 危险 API 密度 / 数据流密度 / 控制流密度
  4. 跨函数加分
  5. 控制条件覆盖度
  6. 路径多样性惩罚
- `vuln_type` 控制各维度权重（`RANK_WEIGHTS`）。

### 5.3 线性化模块

#### `typed_dependency_path(G, path, api_hints=None) -> str`
- **位置**: `linearization/typed_paths.py`
- **功能**: 类型化依赖路径序列化。输出格式：
  ```
  ## Path Context: [SINK=memcpy] [ALLOC=malloc]
  [ALLOC] [CALL:p = malloc(100)]
    --REACHING_DEF-->
  [FREE] [CALL:free(p)]
  ```
- 节点级安全标签：SINK > ALLOC > FREE > SOURCE。

#### `build_hierarchical_context(...) -> str`
- **位置**: `linearization/typed_paths.py`
- **功能**: 构建四层上下文：函数摘要 → 基本块 → 类型化路径 → 程序状态。
- 支持两种调用方式（GraphEngine 版 / 已序列化字符串版）。

#### `build_compact_context(G, function_code, ...) -> str`
- **位置**: `linearization/typed_paths.py`
- **功能**: 紧凑上下文，包含 `[HINT]` 漏洞预检测、`[SAFE]` 良性证据、`[DATAFLOW]` 数据流关系、`[PATHS]` 路径摘要、`[CODE]` 安全关键区域实际代码。

### 5.4 规划模块

#### `class RetrievalPlanner`
- **位置**: `planning/planner.py`
- **核心方法**:
  - `parse_json_action(llm_output) -> (action, reason)`: 解析 JSON 动作
  - `decide_action(llm_output) -> str`: 决策下一步动作（JSON 优先 → 关键词回退 → Agent 守卫）
  - `get_exploration_state() -> str`: 导出探索状态供 LLM 参考
- Agent 模式：仅做最小安全检查（重复动作 ≤ 6 次、最大步数 10），不强制覆盖 LLM 决策。

#### `class ProgramState`
- **位置**: `planning/state_memory.py`
- **有效状态**: `allocated`, `freed`, `tainted`, `dereferenced`, `alias-propagated`, `null-checked`, `bounds-checked`, `error-checked`, `checked`, `indexed`, `assigned`
- **核心方法**:
  - `update(var, state, source_node, step)`: 更新变量状态
  - `track_vars(code)`: 从源码初始化所有变量状态
  - `is_freed_and_used(var) -> bool`: UAF 检测
  - `is_double_free(var) -> bool`: Double Free 检测
  - `is_taint_propagation(var) -> bool`: 污点传播检测
  - `dump() / serialize() -> str`: 导出状态供 LLM 消费

### 5.5 推理模块

#### `reasoning_loop(G, initial_paths, function_code, ...) -> dict`
- **位置**: `reasoning/reasoning_loop.py`
- **功能**: 受限推理主循环（最多 `MAX_REASONING_STEPS=5` 步）。
  - 每步：构建 prompt → 调用 LLM → 提取漏洞类型 → 更新程序状态 → 规划动作 → 执行图扩展
  - 提前终止：连续 3 步无漏洞证据，或动作 = Stop/SummarizeEvidence
- **返回**: `{vulnerability_type, conclusion, evidence_paths, program_state, explanation, steps, tokens_used}`

#### `_extract_vulnerability_type(llm_output, is_final=False) -> str`
- **位置**: `reasoning/reasoning_loop.py`
- **功能**: 从 LLM 输出的 `HYPOTHESIS:` 行提取漏洞类型。
  - 含否定短语 → Unknown
  - 含不确定性词汇且无确认词汇 → Unknown（`is_final=True` 时放宽）
  - 识别：Use-After-Free / Double Free / Buffer Overflow / Taint-style / Null Pointer / Memory Leak

#### `run_vuln_detection(client, model, hierarchical_context, ...) -> int`
- **位置**: `reasoning/reasoning_loop.py`
- **功能**: 轻量级单次 LLM 调用包装器，返回 0（良性）或 1（有漏洞）。供评测模式统一调用。

#### `generate_explanation(G, vulnerability_type, evidence_paths, state, llm_conclusion) -> str`
- **位置**: `reasoning/explanation.py`
- **功能**: 生成完整漏洞报告：漏洞类型 + source-sink 路径 + 变量生命周期 + LLM 结论 + 触发条件分析。

---

## 6. 依赖关系

### 模块间依赖图

```
main.py
├── config.py
├── graph/
│   ├── build_cpg.py      → config (JOERN_*)
│   ├── load_graph.py
│   ├── summarize_graph.py → config (DANGEROUS_APIS, TAINT_SOURCES, MEMORY_OPS)
│   └── graph_engine.py
├── retrieval/
│   ├── candidate_paths.py → config
│   ├── path_ranker.py     → config
│   └── retrieve_topk.py   → path_ranker, config
├── linearization/
│   ├── function_summary.py → config
│   ├── block_summary.py   → config
│   └── typed_paths.py     → config, planning.state_memory
├── planning/
│   ├── actions.py
│   ├── planner.py         → actions
│   └── state_memory.py
└── reasoning/
    ├── prompts.py
    ├── llm_api.py         → config, prompts
    ├── reasoning_loop.py  → graph.graph_engine, linearization, planning, llm_api, prompts, explanation
    └── explanation.py     → linearization, planning.state_memory
```

### 外部依赖（requirements.txt）

| 包 | 版本 | 用途 |
|----|------|------|
| networkx | >=3.2 | 图数据结构与遍历 |
| openai | >=1.0.0 | LLM API 调用 |
| numpy | >=1.24 | 数值计算 |
| scikit-learn | >=1.3 | 评测指标 |
| matplotlib | >=3.5 | 可视化 |
| tqdm | >=4.60 | 进度条 |

### 外部工具

| 工具 | 用途 | 配置项 |
|------|------|--------|
| **Joern** (>=4.x) | CPG 构建 | `config.JOERN_DIR` |
| **JDK** (>=17) | Joern 运行时 | 环境变量 `JAVA_HOME` |
| **LLM API** (OpenAI 兼容) | 漏洞推理 | `config.LLM_API_KEY / LLM_BASE_URL / LLM_MODEL` |

---

## 7. 配置说明（config.py）

### Joern 配置
```python
JOERN_DIR = r"D:\浏览器下载\joern-cli4.1.6"  # 或环境变量 JOERN_DIR
JOERN_PARSE_CMD  = .../joern-parse(.bat)
JOERN_EXPORT_CMD = .../bin/joern-export(.bat)
```

### 安全 API 集合
- `DANGEROUS_APIS`: 危险操作（malloc, free, memcpy, strcpy, system, ...）
- `TAINT_SOURCES`: 污点源（recv, read, scanf, gets, ...）
- `MEMORY_OPS`: 内存操作（malloc, free, mmap, kmalloc, ...）

### 路径检索配置
- `MAX_PATH_HOP = 5`: 候选路径最大跳数
- `TOP_K_PATHS = 15`: Top-K 路径数
- `MAX_REASONING_STEPS = 5`: 推理最大步数

### LLM 配置
```python
LLM_MODEL    = "deepseek-chat"  # 或环境变量 LLM_MODEL
LLM_API_KEY  = os.environ.get("OPENAI_API_KEY", "")
LLM_BASE_URL = "https://api.deepseek.com/v1"
```

### 长距离漏洞划分（跳数）
| 层级 | 跳数范围 |
|------|---------|
| short | 1-2 |
| medium | 3-4 |
| long | 5-7 |
| very_long | 8-15 |

---

## 8. 运行方式

### 安装依赖

```bash
pip install -r requirements.txt
```

### 设置环境变量

```bash
# Windows PowerShell
$env:JOERN_DIR = "D:\浏览器下载\joern-cli4.1.6"
$env:OPENAI_API_KEY = "your-api-key"
$env:OPENAI_BASE_URL = "https://api.deepseek.com/v1"
$env:LLM_MODEL = "deepseek-chat"
```

### 运行模式

```bash
cd HGL-Vul

# 1. 单文件漏洞分析
python main.py analyze <file.c> [output_dir] [token_budget]
# 例: python main.py analyze test.c ./cpg_output 4096

# 2. 生成合成数据集
python main.py generate-synthetic [output_dir]

# 3. HGL-Vul 完整评测（跳数分层 + 缩减率统计）
python main.py evaluate [data_dir] [max_samples] [token_budget]
# 例: python main.py evaluate ./data/synthetic 50 4096

# 4. Devign 数据集评测
python main.py evaluate-devign [fold] [max_samples]
# 例: python main.py evaluate-devign 0 200

# 5. Direct LLM 基线
python main.py direct-llm [fold] [max_samples]

# 6. 三组对比实验（Direct LLM vs HGL-Vul vs VulnSC）
python main.py compare [fold] [max_samples]

# 7. 消融实验
python main.py ablation [data_dir] [max_samples]

# 8. 鲁棒性评估
python main.py robustness-eval [data_dir] [max_samples]

# 9. 帮助
python main.py help
```

### 单文件分析输出

执行 `analyze` 模式后，输出目录包含：
- `export/export.dot`: Joern 导出的 CPG
- `vulnerability_report.json`: 漏洞报告（预测结果、缩减率统计、路径数）

---

## 9. 数据流详解（analyze 模式）

```
code_path
  │
  ├─ Phase 1: build_cpg(code_path, output_dir)
  │     └─ joern-parse → cpg.bin → joern-export --repr all → export/
  │
  ├─ Phase 2: load_graph(nodes_file, edges_file)
  │     └─ nx.MultiDiGraph (G)
  │
  ├─ Phase 3: summarize_graph(G, token_budget=...)
  │     ├─ detect_vuln_type_hint(source_code)
  │     ├─ score_node(...) for all nodes
  │     ├─ _adjust_threshold_for_budget(...)
  │     └─ SG (compressed subgraph + reduction_stats)
  │
  ├─ Phase 4: extract_all_candidate_paths(SG, source_code)
  │     └─ retrieve_topk(SG, candidate_paths) → topk_paths
  │
  ├─ Phase 5: 
  │     ├─ summarize_function(code)          → func_summary
  │     ├─ summarize_block(block)            → block_summaries
  │     ├─ extract_api_hints(code)           → api_hints
  │     ├─ typed_dependency_path(...)        → paths_context
  │     └─ ProgramState().track_vars(code)   → state
  │
  ├─ Phase 6: reasoning_loop(SG, topk_paths, code, ...)
  │     └─ 多轮 LLM 推理 → {vulnerability_type, explanation, ...}
  │
  └─ Phase 7: vulnerability_report.json
```

---

## 10. 已修复的 Bug 记录

| # | 文件 | Bug 描述 | 修复方式 |
|---|------|---------|---------|
| 1 | `graph/summarize_graph.py` | `detect_vuln_type_hint` 中使用 `re.escape()`，但模块以 `import re as _re` 导入，导致 `NameError` | 将 3 处 `re.escape` 改为 `_re.escape` |
| 2 | `reasoning/reasoning_loop.py` | `reasoning_loop` 调用 `_extract_vulnerability_type(result, is_final=...)`，但函数签名无 `is_final` 参数，导致 `TypeError` | 为函数添加 `is_final: bool = False` 参数，并在最后一步放宽不确定性词汇限制 |
| 3 | `linearization/typed_paths.py` | `extract_api_hints` 将 `malloc/free` 归入 `sink_apis`（因 `DANGEROUS_APIS` 包含它们），语义错误 | 从 `sink_apis` 中排除 alloc/free API，仅保留真正的 sink（strcpy/system/memcpy 等） |
| 4 | `planning/state_memory.py` | 函数参数提取正则 `(?:,|\))` 无法匹配无逗号的单参数（如 `int n`），导致参数变量未被跟踪 | 改为 `(?:,|\)|$)` |
| 5 | `planning/state_memory.py` | `track_vars` 产生 `error-checked`/`checked` 状态，但不在 `VALID_STATES` 中，与 `update()` 验证逻辑不一致 | 将这两个状态加入 `VALID_STATES` |

---

## 11. 设计要点与扩展指南

### 新增漏洞类型检测

1. 在 `config.py` 的 `DANGEROUS_APIS`/`TAINT_SOURCES`/`MEMORY_OPS` 中添加相关 API。
2. 在 `summarize_graph.py` 的 `VULN_CONDITIONAL_WEIGHTS` 中添加条件权重。
3. 在 `path_ranker.py` 的 `RANK_WEIGHTS` 中添加排序权重。
4. 在 `reasoning/prompts.py` 的 `SYSTEM_PROMPT` 中添加漏洞类型说明。
5. 在 `reasoning_loop.py` 的 `_extract_vulnerability_type` 中添加类型识别关键词。

### 新增图扩展动作

1. 在 `planning/actions.py` 的 `ACTIONS` 和 `ACTION_KEYWORDS` 中添加动作。
2. 在 `graph/graph_engine.py` 的 `GraphEngine` 中实现对应扩展方法。
3. 在 `planning/planner.py` 的 `RetrievalPlanner.VALID_ACTIONS` 和 `_update_expansion_state` 中注册。
4. 在 `reasoning/reasoning_loop.py` 的 `_execute_action` 中调用引擎方法。

### 添加新评测模式

1. 在 `modes/` 下创建新文件，实现 `mode_xxx()` 函数。
2. 在 `main.py` 中导入并添加命令行分支。

---

*文档生成时间: 2026-09-15 | HGL-Vul v2.0*
