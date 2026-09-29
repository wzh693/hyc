import os

# ============================================================
# Joern 配置
# ============================================================
# Joern 安装目录（build_cpg.py 中会引用此路径）
JOERN_DIR = os.environ.get(
    "JOERN_DIR",
    r"D:\浏览器下载\joern-cli4.1.6"
)
JOERN_PARSE_CMD = os.path.join(JOERN_DIR, "joern-parse.bat") if os.name == "nt" else os.path.join(JOERN_DIR, "joern-parse")
JOERN_EXPORT_CMD = os.path.join(JOERN_DIR, "bin", "joern-export.bat") if os.name == "nt" else os.path.join(JOERN_DIR, "bin", "joern-export")

# ============================================================
# 危险 API 与污点源定义
# ============================================================
DANGEROUS_APIS = {
    # 标准 C 内存/字符串操作
    "malloc", "free", "realloc", "calloc",
    "memcpy", "memmove", "memset", "strcpy", "strcat", "sprintf",
    "gets", "scanf", "recv", "read", "fread",
    "system", "execve", "popen",
    "strncpy", "strncat", "snprintf",
    "alloca", "mmap", "munmap",
    # FFmpeg/libav 危险操作
    "av_malloc", "av_free", "av_realloc", "av_calloc",
    "av_mallocz", "av_freep", "av_malloc_array", "av_image_copy",
    "av_strtok", "av_strdup",
    # 通用危险模式
    "strdup", "atoi", "strtol",
    # Linux 内核常见 unsafe 操作
    "copy_from_user", "copy_to_user",
    "kfree", "kmalloc", "kzalloc", "kcalloc",
    # 文件/网络操作
    "fopen", "fclose", "fwrite", "fgets",
    # 格式字符串等
    "printf", "fprintf",
}

# v10: 兜底信号专用"写型 sink"（语义分层）
# 离线分析（v10_signal_classes.json）证明：free/alloc 族、转换（atoi/strtol）、
# 污点源（recv/read）出现在 topk 路径时对漏洞判定几乎无区分度——
# 兜底 15 样本中弱信号组 5 FP + 1 TP，写型 sink 组 7 TP + 2 FP。
# 因此兜底/早停/跳步三类信号判定只用写型 sink，图压缩评分仍用完整 DANGEROUS_APIS。
BACKSTOP_SINK_APIS = DANGEROUS_APIS - {
    # free 族（资源释放是良性清理代码的常态）
    "free", "av_free", "av_freep", "kfree", "munmap", "fclose",
    # alloc 族（分配本身不是漏洞，需配合使用错误才成立）
    "malloc", "calloc", "realloc", "av_malloc", "av_calloc", "av_realloc",
    "av_mallocz", "av_malloc_array", "av_strdup", "strdup", "alloca",
    "mmap", "kmalloc", "kzalloc", "kcalloc",
    # 转换（纯数值转换，非内存写）
    "atoi", "strtol", "av_strtok",
    # 污点源（输入本身不是漏洞，缺危险写操作时无意义）
    "recv", "read", "fread", "scanf", "gets", "fgets", "fopen",
    # BUG-06（2026-09-17 审查报告）：安全变体不是"写型 sink"。
    # 离线交叉表（v10_signal_classes.json strong 组逐 API 复核）：
    #   snprintf/strncpy 仅出现在 1 个 TP（idx=3959，同时含 fprintf，
    #   剔除后信号不丢）；printf/fprintf 为 TP 3 : FP 1（保留）；
    #   fwrite 零出现（保留，无实证伤害）。FFmpeg/QEMU 良性代码大量
    #   使用 snprintf/strncpy 做有界拷贝，保留会把良性样本兜底成 FP。
    "snprintf", "strncpy", "strncat",
}

TAINT_SOURCES = {
    "recv", "read", "fread", "scanf", "gets", "fgets",
    "recvfrom", "recvmsg", "argv", "getenv",
    "cin", "getchar", "getc",
    # 内核
    "copy_from_user",
    # 文件
    "fopen", "open",
}

MEMORY_OPS = {
    "malloc", "free", "realloc", "calloc",
    "memcpy", "memmove", "memset",
    "alloca", "mmap", "munmap",
    "av_malloc", "av_free", "av_realloc", "av_calloc",
    "kfree", "kmalloc", "kzalloc",
}

# ============================================================
# 路径检索配置
# ============================================================
MAX_PATH_HOP = 5
TOP_K_PATHS = 15

# ============================================================
# 推理配置
# ============================================================
# 多步受限推理（论文核心创新：受限图推理状态机）
# token 控制：Step 2+ 仅发送增量上下文（新增路径 + 上轮结论摘要），
# 且收敛即停/良性早停使多数样本 1~2 步即终止
# v6: 3→2。离线验证（v5 日志 39 个 3 步样本）：截断到 2 步标签 35/39 不变，
# 正确数 23=23 持平，指标中性；每省一步 ~700 tok。
MAX_REASONING_STEPS = 2

# v21（Step1 确认即停）：Step1 给出具体漏洞类型即终止，不再要求图危险信号
# 双确认。v20 全量日志实证：1524 个 ConvergeStop 样本付了 Step2 全价只为在
# temperature=0 下重复 Step1 结论（确认后精度 45.4%，未过滤任何 FP），
# 纯冗余 ~52 万 token。关闭此开关可回退旧行为做消融。
STEP1_CONFIRM_STOP = os.environ.get("STEP1_CONFIRM_STOP", "1") == "1"

# ============================================================
# LLM 配置
# ============================================================
# 优先级: 环境变量 > .env 文件 > 默认值
# .env 文件不提交到版本库（已在 .gitignore 中）
try:
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"), encoding="utf-8") as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ.setdefault(_k.strip(), _v.strip())
except FileNotFoundError:
    pass

_DEFAULT_BASE_URL = "https://api.deepseek.com/v1"
_DEFAULT_MODEL = "deepseek-chat"

LLM_MODEL = os.environ.get("LLM_MODEL", _DEFAULT_MODEL)
LLM_API_KEY = os.environ.get("OPENAI_API_KEY", "")
LLM_BASE_URL = os.environ.get("OPENAI_BASE_URL", _DEFAULT_BASE_URL)

# ============================================================
# 数据集配置
# ============================================================
DATASET_DIR = "data/datasets"
SYNTHETIC_DIR = "data/synthetic"
CPG_CACHE_DIR = "data/cpg_cache"

# 数据集下载 URL
DATASET_URLS = {
    "devign": "https://github.com/microsoft/CodeXGLUE/raw/main/Code-Code/Defect-detection/dataset.zip",
    "big-vul": "https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset",
    "diversevul": "https://github.com/wagner-group/diversevul",
    "primevul": "https://github.com/YYSUK/PrimeVul",
}

# 长距离漏洞划分（依赖跳数）
HOP_SPLITS = {
    "short": (1, 2),
    "medium": (3, 4),
    "long": (5, 7),
    "very_long": (8, 15),
}

# 漏洞类型标签
VULNERABILITY_TYPES = [
    "CWE-416", "CWE-415", "CWE-119", "CWE-120", "CWE-121",
    "CWE-122", "CWE-125", "CWE-787", "CWE-476", "CWE-401",
    "CWE-190", "CWE-362",
]

# 合成数据集配置
SYNTHETIC_CONFIG = {
    "num_samples_per_type": 50,
    "num_benign_samples": 100,
    "min_hop": 2,
    "max_hop": 12,
    "vulnerability_types": [
        "use_after_free", "double_free", "buffer_overflow",
        "taint_style", "memory_leak", "null_pointer_deref",
    ],
}

# ============================================================
# 技术点①②：学习式节点重要性（Learning-based Node Importance）
# ============================================================
# ① 压缩打分加成 / ② 路径排序加成 共用同一弱监督模型
# 单变量实验纪律：v12a 只开①；v12b 开①+②
# 环境变量覆盖：USE_LEARNED_SUMMARIZE=0 / USE_LEARNED_PATH_RANK=0
USE_LEARNED_NODE_IMPORTANCE = os.environ.get("USE_LEARNED_NODE_IMPORTANCE", "1") == "1"
# v13（2026-09-18）：关闭①权重。离线决策依据 train_report.json——
# BUG-20 重训完成（n=582）后三候选 anchor_separation 仍≈0
# （lr -0.0245 / gbdt 0.0108 / mlp_gpu 0.0182），学习式加分无区分度，
# 关闭以验证 v13 路径证据恢复修复本身的收益（相对 v12g 单变量）。
USE_LEARNED_SUMMARIZE = os.environ.get("USE_LEARNED_SUMMARIZE", "0") == "1"
USE_LEARNED_PATH_RANK = os.environ.get("USE_LEARNED_PATH_RANK", "0") == "1"  # v12a 最优: 只开①
NODE_IMPORTANCE_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "learning", "model", "node_importance.joblib"
)
# ① 压缩：非 force_keep 背景 node_score += WEIGHT * (rank-1) ∈ [-WEIGHT, 0]
# （纯惩罚模式 v2.4：force_keep 豁免，压缩图为基线近似子集，证据保留单调）
LEARNED_NODE_WEIGHT = 1.0
# ② 路径排序：path_score += WEIGHT * min(sum(z_learned), 4.0)
LEARNED_PATH_WEIGHT = 2.0

# ============================================================
# 实验配置
# ============================================================
EXPERIMENT_DIR = "experiments"
SEED = 42
N_RUNS = 3  # 多次运行用于稳定性评估