"""
离线构建 train fold CPG 缓存（弱监督训练数据预处理）。

用法:
  python -m learning.build_train_cache [n_vuln] [n_benign]

- 只用 fold 0 train split（与评测 fold 一致，杜绝测试集泄漏）
- 只用 >=1500 字节样本（项目硬约束）
- 断点续跑：已有 export.dot 的样本跳过
- 输出: output/train_cpg/sample_XXXXXX/export/export.dot + meta.json
"""

import os
import sys
import json
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import SEED
from graph.build_cpg import build_cpg, find_export_files

DEVIGN_JSON = r"C:\Users\wzh13\Desktop\Network Security Research\devign\function.json"

CACHE_DIR = os.path.join("output", "train_cpg")
MIN_BYTES = 1500


def main(n_vuln=300, n_benign=300):
    from data.devign_loader import DevignLoader

    os.makedirs(CACHE_DIR, exist_ok=True)
    meta_path = os.path.join(CACHE_DIR, "meta.json")
    meta = {}
    if os.path.exists(meta_path):
        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)

    loader = DevignLoader(DEVIGN_JSON)
    loader.load(fold_indices=None)
    train = loader.get_fold(fold=0, split="train")
    train = [s for s in train if len(s.func) >= MIN_BYTES]
    vuln = [s for s in train if s.target == 1]
    ben = [s for s in train if s.target == 0]
    print(f"[TrainCache] fold0 train >= {MIN_BYTES}B: {len(vuln)} 漏洞 / {len(ben)} 良性")

    rng = random.Random(SEED)
    selected = rng.sample(vuln, min(n_vuln, len(vuln))) + rng.sample(ben, min(n_benign, len(ben)))
    print(f"[TrainCache] 目标: {len(selected)} 个样本 (缓存已有 {len(meta)})")

    done = 0
    for i, s in enumerate(selected):
        sample_id = f"sample_{s.idx:06d}"
        export_dot = os.path.join(CACHE_DIR, sample_id, "export", "export.dot")
        if os.path.exists(export_dot) and meta.get(sample_id, {}).get("target") is not None:
            done += 1
            continue
        tmp_c = os.path.join(CACHE_DIR, sample_id + ".c")
        with open(tmp_c, "w", encoding="utf-8") as f:
            f.write(s.func)
        try:
            sample_dir = os.path.join(CACHE_DIR, sample_id)
            build_cpg(tmp_c, sample_dir)
            meta[sample_id] = {"idx": s.idx, "target": s.target,
                               "project": s.project, "fold": s.fold}
            done += 1
        except Exception as e:
            print(f"[TrainCache] {sample_id} 失败: {e}")
            meta[sample_id] = {"idx": s.idx, "target": s.target,
                               "project": s.project, "fold": s.fold, "error": str(e)}
        finally:
            if os.path.exists(tmp_c):
                os.remove(tmp_c)
        # 每个样本都落盘（防崩）
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, ensure_ascii=False)
        if (i + 1) % 20 == 0:
            print(f"[TrainCache] 进度 {i+1}/{len(selected)} (ok={done})")

    print(f"[TrainCache] 完成: {done}/{len(selected)} 成功 → {CACHE_DIR}")


if __name__ == "__main__":
    nv = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    nb = int(sys.argv[2]) if len(sys.argv) > 2 else 300
    main(nv, nb)
