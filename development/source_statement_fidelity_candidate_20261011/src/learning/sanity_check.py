"""
离线 sanity check：训练好的节点重要性模型在 100 个评测缓存 CPG 上的区分度。

不调用 LLM。回答三个问题（在线实验前必查）：
  1. 证据保留：开启①后，启发式锚点在压缩图中的存活率是否 >= 基线
     （硬约束：证据保留优先于 token 削减）
  2. 压缩效果：良性 vs 漏洞样本的压缩节点数/token 估计差
     （期望：良性压缩更狠 → FP 抑制 + token 下降；漏洞保留证据）
  3. 分数区分度：漏洞 vs 良性样本的 top 节点学习式分数分布

用法: python -m learning.sanity_check
"""

import os
import sys
import io
import json
import contextlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graph.load_graph import load_graph
from graph.summarize_graph import summarize_graph
from retrieval.candidate_paths import extract_all_candidate_paths
from retrieval.retrieve_topk import retrieve_topk
from learning.scorer import score_nodes
from learning.dataset import heuristic_anchor_nodes, _ANCHOR_RES

R = os.path.join("output", "devign_comparison")


def main():
    results = json.load(open(
        os.path.join(R, "results", "evaluation_results_v10_100.json"), encoding="utf-8"))
    hgl = [r for r in results if r.get("mode") == "hgl_vul"]

    stats = {0: [], 1: []}       # target -> per-sample dict
    for r in hgl:
        sid = "sample_%06d" % r["idx"]
        dot = os.path.join(R, "cpg", sid, "export", "export.dot")
        code_path = os.path.join(R, "samples", sid + ".c")
        if not os.path.exists(dot):
            continue
        G = load_graph(dot, dot)
        code = open(code_path, encoding="utf-8", errors="ignore").read()

        learned = score_nodes(G, code)
        if learned is None:
            print("[Sanity] 模型未加载，退出")
            return

        with contextlib.redirect_stdout(io.StringIO()):
            SG_base = summarize_graph(G, token_budget=4096, verbose=False)
            paths_b = extract_all_candidate_paths(
                SG_base, source_code=code, verbose=False,
                max_total_paths=8000, max_paths_per_node=800)
            if not paths_b:
                paths_b = extract_all_candidate_paths(
                    G, source_code=code, verbose=False,
                    max_total_paths=8000, max_paths_per_node=800)
            topk_b = retrieve_topk(SG_base if paths_b else G, paths_b) if paths_b else []
            anchors = heuristic_anchor_nodes(SG_base, topk_b)

            SG_learn = summarize_graph(G, token_budget=4096, verbose=False,
                                       learned_scores=learned)

        anchor_alive = sum(1 for a in anchors if a in SG_learn) / max(len(anchors), 1)
        # 定义级证据 = 危险 API 节点（force_keep，硬约束）
        danger_anchors = {a for a in anchors
                          if any(rx.search((SG_base.nodes[a].get("code") or "").lower())
                                 for rx in _ANCHOR_RES.values())} if anchors else set()
        danger_alive = (sum(1 for a in danger_anchors if a in SG_learn)
                        / max(len(danger_anchors), 1)) if danger_anchors else 1.0
        d = {
            "idx": r["idx"],
            "n_base": SG_base.number_of_nodes(),
            "n_learn": SG_learn.number_of_nodes(),
            "anchors": len(anchors),
            "anchor_alive": round(anchor_alive, 3),
            "danger_alive": round(danger_alive, 3),
            "top5_p": sorted(learned.values(), reverse=True)[:5],
            "mean_top10_p": (lambda v: round(sum(v) / len(v), 3))(
                sorted(learned.values(), reverse=True)[:10]),
        }
        stats[r["target"]].append(d)

    import numpy as np
    for t in (1, 0):
        ds = stats[t]
        name = "漏洞" if t else "良性"
        if not ds:
            continue
        print(f"\n=== {name}样本 (n={len(ds)}) ===")
        print(f"  压缩节点: base={np.mean([d['n_base'] for d in ds]):.0f} "
              f"-> learned={np.mean([d['n_learn'] for d in ds]):.0f} "
              f"(Δ{np.mean([d['n_learn']-d['n_base'] for d in ds]):+.0f})")
        print(f"  危险锚点存活率: {np.mean([d['danger_alive'] for d in ds])*100:.1f}% "
              f"(硬约束门控)")
        print(f"  路径锚点存活率: {np.mean([d['anchor_alive'] for d in ds])*100:.1f}% "
              f"(参考; 服务时 topk 在新图上重算)")

    vuln_danger = np.mean([d["danger_alive"] for d in stats[1]])
    vuln_alive = np.mean([d["anchor_alive"] for d in stats[1]])
    verdict = "PASS" if vuln_danger >= 0.98 else "FAIL(<98%, 危险锚点丢失, 违反证据保留约束)"
    print(f"\n[Sanity] 漏洞危险锚点存活率 {vuln_danger*100:.1f}% —— {verdict}")
    print(f"[Sanity] 漏洞路径锚点存活率 {vuln_alive*100:.1f}% (参考)")


if __name__ == "__main__":
    main()
