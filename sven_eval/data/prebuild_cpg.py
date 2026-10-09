"""批量预构建 SVEN 切片 CPG（4 进程并行）。"""
import os
import sys
import json
import time
from multiprocessing import Pool

HGL_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, HGL_ROOT)
from graph.build_cpg import build_cpg, find_export_files
from graph.load_graph import load_graph

SRC_DIR = os.environ.get("SVEN_SRC_DIR", os.path.join(HGL_ROOT, "sven_eval", "src_c"))
CACHE_DIR = os.environ.get("SVEN_CPG_CACHE", os.path.join(HGL_ROOT, "sven_eval", "cpg_cache"))
LOG_DIR = os.environ.get("SVEN_DATA_DIR", os.path.join(HGL_ROOT, "sven_eval", "data"))
os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)


def build_one(fn):
    src = os.path.join(SRC_DIR, fn)
    sample_dir = os.path.join(CACHE_DIR, os.path.splitext(fn)[0])
    os.makedirs(sample_dir, exist_ok=True)
    try:
        # build_cpg performs source/tool/config fingerprint validation itself.
        # Checking only for export.dot here reused stale graphs whenever wrapped
        # source changed, pushing expensive rebuilds into the serial evaluator.
        existed = os.path.exists(os.path.join(sample_dir, 'export', 'export.dot')) or \
                  os.path.exists(os.path.join(sample_dir, 'nodes.json'))
        export_dir = build_cpg(src, sample_dir)
        nodes_file, edges_file = find_export_files(export_dir)
        G = load_graph(nodes_file, edges_file)
        return (fn, 'validated' if existed else 'ok',
                G.number_of_nodes(), G.number_of_edges())
    except Exception as e:
        err = f"{type(e).__name__}: {str(e)[:200]}"
        return (fn, f'fail:{err}', 0, 0)


def main():
    files = sorted([f for f in os.listdir(SRC_DIR) if f.endswith('.c')])
    print(f"Total {len(files)} samples to build")
    t0 = time.time()
    results = []
    with Pool(processes=4) as pool:
        for i, res in enumerate(pool.imap_unordered(build_one, files, chunksize=1)):
            results.append(res)
            elapsed = time.time() - t0
            done = i + 1
            rate = done / elapsed if elapsed > 0 else 0
            eta = (len(files) - done) / rate if rate > 0 else 0
            fn, status, n, e = res
            print(f"[{done}/{len(files)}] {rate:.1f}/s eta={eta:.0f}s {fn} {status} n={n} e={e}")

    ok = sum(1 for r in results if r[1] in ('ok', 'validated'))
    fail = sum(1 for r in results if r[1].startswith('fail'))
    print(f"\n=== Done in {time.time()-t0:.1f}s: OK={ok}, FAIL={fail} ===")

    log_path = os.path.join(LOG_DIR, 'prebuild_log.json')
    with open(log_path, 'w', encoding='utf-8') as f:
        json.dump([{'file': r[0], 'status': r[1], 'nodes': r[2], 'edges': r[3]}
                   for r in results], f, indent=2)
    print(f"Log: {log_path}")


if __name__ == '__main__':
    main()
