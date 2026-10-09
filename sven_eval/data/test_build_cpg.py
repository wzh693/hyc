"""测试 HGL-Vul 的 build_cpg 在 SVEN 包装样本上的成功率。"""
import os
import sys

HGL_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, HGL_ROOT)
from graph.build_cpg import build_cpg, find_export_files
from graph.load_graph import load_graph

src_dir = os.environ.get("SVEN_SRC_DIR", os.path.join(HGL_ROOT, "sven_eval", "src_c"))
test_dir = os.environ.get("SVEN_CPG_TEST_DIR", os.path.join(HGL_ROOT, "sven_eval", "cpg_test2"))

# 取 20 个跨类型的样本
files = sorted(os.listdir(src_dir))[::12][:20]
os.makedirs(test_dir, exist_ok=True)

ok = 0
fail = 0
errors = []
node_counts = []
for fn in files:
    src = os.path.join(src_dir, fn)
    sample_dir = os.path.join(test_dir, os.path.splitext(fn)[0])
    os.makedirs(sample_dir, exist_ok=True)
    try:
        export_dir = build_cpg(src, sample_dir)
        nodes_file, edges_file = find_export_files(export_dir)
        G = load_graph(nodes_file, edges_file)
        n_nodes = G.number_of_nodes()
        n_edges = G.number_of_edges()
        ok += 1
        node_counts.append(n_nodes)
        print(f"OK   {fn}: nodes={n_nodes}, edges={n_edges}")
    except Exception as e:
        fail += 1
        err = f"{type(e).__name__}: {str(e)[:200]}"
        errors.append((fn, err))
        print(f"FAIL {fn}: {err}")

print(f"\n=== build_cpg: OK={ok}, FAIL={fail} ===")
if node_counts:
    print(f"node count: min={min(node_counts)}, max={max(node_counts)}, avg={sum(node_counts)/len(node_counts):.1f}")
if errors:
    print("\nError samples:")
    for fn, err in errors[:5]:
        print(f"  {fn}: {err[:200]}")
