"""测试 Joern 解析包装后的 SVEN 切片。"""
import os
import sys
import subprocess

# 用 HGL-Vul 的 config
HGL_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, HGL_ROOT)
from config import JOERN_DIR, JOERN_PARSE_CMD, JOERN_EXPORT_CMD

src_dir = os.environ.get("SVEN_SRC_DIR", os.path.join(HGL_ROOT, "sven_eval", "src_c"))
test_dir = os.environ.get("SVEN_JOERN_TEST_DIR", os.path.join(HGL_ROOT, "sven_eval", "cpg_test"))
os.makedirs(test_dir, exist_ok=True)

# 取前 20 个样本测试
files = sorted(os.listdir(src_dir))[:20]
ok = 0
fail = 0
errors = []
for fn in files:
    src = os.path.join(src_dir, fn)
    sample_dir = os.path.join(test_dir, os.path.splitext(fn)[0])
    os.makedirs(sample_dir, exist_ok=True)
    # joern-parse
    try:
        result = subprocess.run(
            [JOERN_PARSE_CMD, src, '-o', sample_dir],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            ok += 1
            print(f"OK   {fn}")
        else:
            fail += 1
            err = result.stderr[:200] if result.stderr else result.stdout[:200]
            errors.append((fn, err))
            print(f"FAIL {fn}: {err[:120]}")
    except Exception as e:
        fail += 1
        errors.append((fn, str(e)))
        print(f"EXC  {fn}: {e}")

print(f"\n=== joern-parse: OK={ok}, FAIL={fail} ===")
