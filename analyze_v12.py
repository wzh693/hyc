"""
v12 指标分析：对比 v10 定稿与当前实验结果。
用法: python analyze_v12.py [current_json] [baseline_json]
默认 current=evaluation_results.json, baseline=evaluation_results_v10_100.json
"""
import json
import sys
import os
from collections import defaultdict

R = os.path.join("output", "devign_comparison", "results")


def compute_metrics(records, mode):
    recs = [r for r in records if r.get("mode") == mode]
    tp = fp = tn = fn = 0
    toks = []
    for r in recs:
        t = r["target"]
        p = r["prediction"]
        if t == 1 and p == 1:
            tp += 1
        elif t == 0 and p == 1:
            fp += 1
        elif t == 0 and p == 0:
            tn += 1
        else:
            fn += 1
        toks.append(r.get("tokens_used", 0))
    n = tp + fp + tn + fn
    acc = (tp + tn) / n * 100 if n else 0
    pre = tp / (tp + fp) * 100 if (tp + fp) else 0
    rec = tp / (tp + fn) * 100 if (tp + fn) else 0
    f1 = 2 * pre * rec / (pre + rec) if (pre + rec) else 0
    avg_tok = sum(toks) / len(toks) if toks else 0
    max_tok = max(toks) if toks else 0
    over = sum(1 for t in toks if t > 1043)
    return dict(n=n, tp=tp, fp=fp, tn=tn, fn=fn,
                acc=round(acc, 2), pre=round(pre, 2), rec=round(rec, 2),
                f1=round(f1, 2), avg_tok=round(avg_tok, 1),
                max_tok=max_tok, over_1043=over)


def pred_map(records, mode):
    return {r["idx"]: r["prediction"] for r in records if r.get("mode") == mode}


def main():
    cur_file = sys.argv[1] if len(sys.argv) > 1 else "evaluation_results.json"
    base_file = sys.argv[2] if len(sys.argv) > 2 else "evaluation_results_v10_100.json"
    cur = json.load(open(os.path.join(R, cur_file), encoding="utf-8"))
    base = json.load(open(os.path.join(R, base_file), encoding="utf-8"))

    print(f"=== 当前实验 ({cur_file}) ===")
    for mode in ["direct_llm", "hgl_vul"]:
        m = compute_metrics(cur, mode)
        print(f"  {mode:12s}: Acc={m['acc']:5.1f} Pre={m['pre']:5.1f} "
              f"Rec={m['rec']:5.1f} F1={m['f1']:5.1f} "
              f"tok_avg={m['avg_tok']:6.1f} tok_max={m['max_tok']} "
              f"over1043={m['over_1043']}  "
              f"CM: TN={m['tn']} FP={m['fp']} FN={m['fn']} TP={m['tp']}")

    print(f"\n=== v10 定稿基线 ({base_file}) ===")
    for mode in ["direct_llm", "hgl_vul"]:
        m = compute_metrics(base, mode)
        print(f"  {mode:12s}: Acc={m['acc']:5.1f} Pre={m['pre']:5.1f} "
              f"Rec={m['rec']:5.1f} F1={m['f1']:5.1f} "
              f"tok_avg={m['avg_tok']:6.1f} tok_max={m['max_tok']} "
              f"over1043={m['over_1043']}  "
              f"CM: TN={m['tn']} FP={m['fp']} FN={m['fn']} TP={m['tp']}")

    # 翻转矩阵（HGL-Vul 的 HGL 预测对比）
    cur_hgl = pred_map(cur, "hgl_vul")
    base_hgl = pred_map(base, "hgl_vul")
    common = set(cur_hgl) & set(base_hgl)
    print(f"\n=== 翻转矩阵 (v10→当前, HGL-Vul, 共 {len(common)} 样本) ===")
    # (base_pred, cur_pred) -> count, 按 target 分组
    flip = defaultdict(lambda: {"vul": 0, "ben": 0, "idxs": []})
    for idx in common:
        bp = base_hgl[idx]
        cp = cur_hgl[idx]
        tgt = next(r["target"] for r in cur if r["idx"] == idx and r["mode"] == "hgl_vul")
        key = (bp, cp)
        flip[key]["vul" if tgt else "ben"] += 1
        if len(flip[key]["idxs"]) < 10:
            flip[key]["idxs"].append(idx)
    for (bp, cp), d in sorted(flip.items()):
        label = {0: "BEN", 1: "VUL"}
        arrow = f"{label[bp]}→{label[cp]}"
        total = d["vul"] + d["ben"]
        print(f"  {arrow:10s}: {total:3d}  (VUL={d['vul']}, BEN={d['ben']})  "
              f"sample={d['idxs'][:5]}")

    # 达标判定
    cur_hgl_m = compute_metrics(cur, "hgl_vul")
    print("\n=== 达标判定 (Acc>=60 Rec>=75 F1>=63 tok<1043) ===")
    ok_acc = cur_hgl_m["acc"] >= 60
    ok_rec = cur_hgl_m["rec"] >= 75
    ok_f1 = cur_hgl_m["f1"] >= 63
    ok_tok = cur_hgl_m["avg_tok"] < 1043
    all_ok = ok_acc and ok_rec and ok_f1 and ok_tok
    print(f"  Acc={cur_hgl_m['acc']:5.1f} {'PASS' if ok_acc else 'FAIL'}")
    print(f"  Rec={cur_hgl_m['rec']:5.1f} {'PASS' if ok_rec else 'FAIL'}")
    print(f"  F1 ={cur_hgl_m['f1']:5.1f} {'PASS' if ok_f1 else 'FAIL'}")
    print(f"  tok_avg={cur_hgl_m['avg_tok']:6.1f} (<1043) {'PASS' if ok_tok else 'FAIL'}  (over1043={cur_hgl_m['over_1043']})")
    print(f"  >>> 整体: {'ALL PASS -> 可跑全集' if all_ok else '未达标 -> 需 v12b 或调参'}")


if __name__ == "__main__":
    main()
