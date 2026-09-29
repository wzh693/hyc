import os
import re
import shutil
import subprocess
import json
import glob as glob_mod
import tempfile
import uuid
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config import JOERN_DIR, JOERN_PARSE_CMD, JOERN_EXPORT_CMD

# 临时目录（无空格），避免 joern batch 文件的编码问题
TEMP_CPG_DIR = os.path.join(os.environ.get("TEMP", os.path.expanduser("~")), "joern_cpg")

# ── Joern 兼容性清洗（v12e+: 修复空骨架图 bug）──
# FFmpeg/QEMU 的 GCC 属性宏出现在函数签名位置时，Joern NewC 前端会静默跳过
# 整个函数体，只导出 <global> 骨架（18 节点空图）。实测 12% 评测样本受害。
_ATTR_MACROS = re.compile(
    r'\b(?:av_always_inline|av_cold|av_noinline|av_unused|av_pure|av_const|'
    r'av_flatten|av_restrict|av_nonnull_all|av_format|coroutine_fn|'
    r'__always_inline|__cold|__unused|__pure|__const|__deprecated|__malloc|'
    r'asmlinkage|fastcall|noinline|__init|__exit)\b'
)
_ATTR_GCC = re.compile(r'\b__attribute__\s*\(\(\s*[^)]*\)\)')
_FUNC_METHOD = re.compile(r'\[label="METHOD"[^\]]*NAME="(?!<global>)[^"]*"')


def _sanitize_for_joern(code: str) -> str:
    """移除 GCC 属性宏（仅影响 Joern 输入，不影响 LLM 看到的源码）。"""
    code = _ATTR_GCC.sub('', code)
    return _ATTR_MACROS.sub('', code)


def _dot_has_func_method(dot_path: str) -> bool:
    """验证导出 DOT 含真正的函数 METHOD 节点（防静默空图）。"""
    try:
        with open(dot_path, encoding="utf-8", errors="ignore") as f:
            return bool(_FUNC_METHOD.search(f.read()))
    except OSError:
        return False


def build_cpg(code_path: str, output_dir: str) -> str:
    """
    使用 Joern 构建代码属性图 (CPG)。
    使用无空格的临时目录构建，避免 batch 文件中文注释乱码和路径空格问题。
    参数:
        code_path: 源代码文件路径
        output_dir: 输出目录路径
    返回：
        导出目录路径（包含 export.dot 或 nodes.json/edges.json）
    """
    abs_code = os.path.abspath(code_path)
    abs_out = os.path.abspath(output_dir)

    # v20：CPG 缓存短路——sample_dir 下已有通过空图校验的 export.dot 直接
    # 复用（idx→代码确定性，同键必同图）。全集 2406 样本时 Joern 重建是
    # 主要耗时项；缓存副本在写入前均经 _dot_has_func_method 校验，此处
    # 复用时再校验一次以防中断残留的半成品目录。
    cached_dot = os.path.join(abs_out, "export", "export.dot")
    if os.path.exists(cached_dot) and _dot_has_func_method(cached_dot):
        print(f"[Joern] 缓存命中: {cached_dot}")
        return os.path.dirname(cached_dot)

    joern_parse = JOERN_PARSE_CMD

    # 在无空格临时目录下构建 CPG
    os.makedirs(TEMP_CPG_DIR, exist_ok=True)
    build_id = uuid.uuid4().hex[:8]
    work_dir = os.path.join(TEMP_CPG_DIR, f"build_{build_id}")
    os.makedirs(work_dir, exist_ok=True)

    cpg_bin = os.path.join(work_dir, "cpg.bin")

    # v12e+: 属性宏清洗副本（仅作 Joern 输入；LLM 源码不受影响）
    with open(abs_code, "r", encoding="utf-8", errors="ignore") as f:
        raw_code = f.read()
    sanitized = _sanitize_for_joern(raw_code)
    if sanitized != raw_code:
        joern_input = os.path.join(work_dir, "input_sanitized.c")
        with open(joern_input, "w", encoding="utf-8") as f:
            f.write(sanitized)
        print(f"[Joern] 属性宏清洗: {len(raw_code) - len(sanitized)} 字符被移除")
    else:
        joern_input = abs_code

    # 环境变量：最小化 PATH（避免 PowerShell 环境变量污染）+ Joern 路径 + JAVA_HOME
    path_sep = ";" if os.name == "nt" else ":"
    if os.name == "nt":
        system_paths = path_sep.join([r"C:\Windows\System32", r"C:\Windows", r"C:\Windows\System32\Wbem"])
        default_java = r"C:\Program Files\Java\jdk-23"
        default_system_root = r"C:\Windows"
    else:
        system_paths = path_sep.join(["/usr/bin", "/usr/local/bin", "/bin"])
        default_java = "/usr/lib/jvm/java-23"
        default_system_root = ""
    env = {
        "PATH": JOERN_DIR + path_sep + system_paths,
        "JAVA_HOME": os.environ.get("JAVA_HOME", default_java),
        "SystemRoot": os.environ.get("SystemRoot", default_system_root),
        "TEMP": os.environ.get("TEMP", TEMP_CPG_DIR),
        "TMP": os.environ.get("TMP", TEMP_CPG_DIR),
    }

    # Step 1: joern-parse（使用 list 参数，不使用 shell=True；v12e+: 用清洗后输入）
    parse_cmd = [joern_parse, joern_input, "--output", cpg_bin]
    print(f"[Joern] 解析命令: {' '.join(parse_cmd)}")

    result = subprocess.run(
        parse_cmd, capture_output=True, text=True,
        encoding="utf-8", errors="replace", env=env
    )
    if result.returncode != 0:
        print(f"[Error] Joern parse failed. returncode={result.returncode}")
        print(f"[Error] stderr: {result.stderr[:500] if result.stderr else 'empty'}")
        raise RuntimeError(f"Joern parse failed: {result.stderr or 'unknown error'}")

    if not os.path.exists(cpg_bin):
        raise FileNotFoundError(f"cpg.bin not created at {cpg_bin}")

    # Step 2: joern-export（使用内层 bin\joern-export.bat，传递 JVM 参数）
    joern_export = JOERN_EXPORT_CMD
    log4j_config = os.path.join(JOERN_DIR, "conf", "log4j2.xml")
    export_work = os.path.join(work_dir, "export")
    export_cmd = [
        joern_export,
        "-J-XX:+UseG1GC", "-J-XX:CompressedClassSpaceSize=128m",
        f"-Dlog4j.configurationFile={log4j_config}",
        cpg_bin, "--repr", "all", "--out", export_work
    ]
    print(f"[Joern] 导出命令: {' '.join(export_cmd)}")

    result = subprocess.run(
        export_cmd, capture_output=True, text=True,
        encoding="utf-8", errors="replace", env=env
    )
    if result.returncode != 0:
        print(f"[Warning] Joern export failed: {result.stderr[:200] if result.stderr else 'unknown'}")
        if os.path.exists(cpg_bin):
            raise RuntimeError(f"Joern export failed: {result.stderr[:100] if result.stderr else 'unknown'}")
        raise RuntimeError(f"Joern export failed: {result.stderr[:100] if result.stderr else 'unknown'}")

    # 检查导出结果，复制到目标目录
    export_dot = os.path.join(export_work, "export.dot")
    if os.path.exists(export_dot):
        # v12e+: 防静默空图 — 无函数 METHOD 节点视为解析失败
        if not _dot_has_func_method(export_dot):
            raise RuntimeError(
                "Joern exported DOT has no function METHOD node (silent empty graph). "
                "Check source for unsupported syntax."
            )
        os.makedirs(abs_out, exist_ok=True)
        target_export = os.path.join(abs_out, "export")
        if os.path.exists(target_export):
            shutil.rmtree(target_export)
        shutil.copytree(export_work, target_export)
        print(f"[Joern] DOT 导出成功: {target_export}")
        return target_export

    # 也检查其他位置
    for root, dirs, files in os.walk(work_dir):
        for f in files:
            if f == "export.dot":
                os.makedirs(abs_out, exist_ok=True)
                target_export = os.path.join(abs_out, "export")
                os.makedirs(target_export, exist_ok=True)
                shutil.move(os.path.join(root, f), os.path.join(target_export, "export.dot"))
                print(f"[Joern] DOT 导出成功: {target_export}")
                return target_export

    raise FileNotFoundError(f"No export.dot found in {work_dir}")


def find_export_files(export_dir: str) -> tuple:
    """
    在 Joern 导出目录中定位 nodes.json/edges.json 或 export.dot。
    Joern 4.x 使用 DOT 格式，旧版本使用 JSON 格式。
    返回:
        (nodes_file_path, edges_file_path)
        对于 DOT 格式，nodes_file 为 DOT 文件路径，edges_file 为 None
    """
    nodes_file = os.path.join(export_dir, "nodes.json")
    edges_file = os.path.join(export_dir, "edges.json")

    if not os.path.exists(nodes_file):
        candidates = glob_mod.glob(
            os.path.join(export_dir, "**", "nodes.json"), recursive=True
        )
        if candidates:
            nodes_file = candidates[0]

    if not os.path.exists(edges_file):
        candidates = glob_mod.glob(
            os.path.join(export_dir, "**", "edges.json"), recursive=True
        )
        if candidates:
            edges_file = candidates[0]

    if not os.path.exists(nodes_file) or not os.path.exists(edges_file):
        export_dot = os.path.join(export_dir, "export.dot")
        if os.path.exists(export_dot):
            print(f"[Info] 检测到 Joern 4.x DOT 格式: {export_dot}")
            return export_dot, export_dot
        raise FileNotFoundError(
            f"nodes.json/edges.json or export.dot not found in {export_dir}\n"
            f"  nodes_file: {nodes_file} (exists={os.path.exists(nodes_file)})\n"
            f"  edges_file: {edges_file} (exists={os.path.exists(edges_file)})"
        )
    return nodes_file, edges_file