"""
GAT MIL 训练脚本（导师版 Method 3.2.4：多实例学习弱监督）。

用法:
  python -m learning.train_gat [epochs] [batch_accum]

流程:
  1. 复用 train_node_importance 的骨架缓存（skeleton.pkl: 锚点/背景选择）
     与函数源码读取（train fold，无测试泄漏）
  2. 每函数 CPG → npz 图缓存（x/edge_index/edge_type/tok/anchor_rows，
     按相关源码内容哈希版本化，特征迭代自动重算）
  3. 按代码/提交/近克隆组划分训练、选轮验证与阈值校准
  4. MIL 训练: 包级 BCE + β·注意力熵正则，梯度累积
  5. holdout 评估:
     - bag AUC（函数级漏洞/良性判别）
     - anchor_sep = E[s|漏洞函数锚点] - E[s|良性函数锚点]
       （s = MIL readout 注意力，并按图大小归一到均匀注意力基线 1）
     - 未训练对照（随机初始化）: sep 应 ≈ 0
  6. 保存独立候选目录，不覆盖既有模型
"""

import os
import sys
import io
import json
import math
import random
import contextlib
import hashlib

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import torch

from config import SEED
from graph.load_graph import load_graph
from graph.build_cpg import _dot_has_func_method
from learning.gat_model import GATMIL, graph_to_arrays
from learning.features import NODE_FEATURE_NAMES
from learning.train_node_importance import (
    CACHE_DIR, _load_or_build_skeleton, _load_func_source,
)

MODEL_DIR = os.path.join("learning", "model")
GAT_MODEL_PATH = os.path.join(MODEL_DIR, "gat_mil.pt")
GAT_REPORT_PATH = os.path.join(MODEL_DIR, "gat_report.json")


def _content_hash(*paths):
    h = hashlib.sha256()
    for path in paths:
        with open(path, "rb") as f:
            h.update(f.read())
    return h.hexdigest()[:12]


GRAPH_CACHE_VER = "gat_v2_" + _content_hash(
    os.path.join(os.path.dirname(__file__), "gat_model.py"),
    os.path.join(os.path.dirname(__file__), "features.py"),
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "graph", "load_graph.py"),
)

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"


# ── 图缓存 ──────────────────────────────────────────────────

def _load_or_build_graphs(meta, skeleton, cache_dir=None):
    """{fid: dict(arrays..., target)}，npz 缓存。"""
    graphs = {}
    cache_dir = cache_dir or CACHE_DIR
    todo = []
    valid_fids = set()
    for fid, info in meta.items():
        if info.get("error"):
            continue
        dot = os.path.join(cache_dir,fid,'export','export.dot')
        if not _dot_has_func_method(dot):
            continue  # Legacy npz may exist for a silently empty Joern graph.
        valid_fids.add(fid)
        target = int(info["target"])
        selected, n_anchors = [], 0
        if fid in skeleton:
            _, selected, _, n_anchors = skeleton[fid]
        npz = os.path.join(cache_dir, fid, f"{GRAPH_CACHE_VER}.npz")
        if os.path.exists(npz):
            continue
        if not os.path.exists(os.path.join(cache_dir, fid, "export", "export.dot")):
            continue
        todo.append((fid, target, selected[:n_anchors]))
    if todo:
        print(f"[GAT] 图缓存缺失 {len(todo)} 个，构建中（首次 ~2-4s/图）...")
        for i, (fid, target, anchor_nids) in enumerate(todo):
            code = _load_func_source(meta[fid]["idx"])
            dot = os.path.join(cache_dir, fid, "export", "export.dot")
            npz_path = os.path.join(cache_dir, fid, f"{GRAPH_CACHE_VER}.npz")
            try:
                G = load_graph(dot, dot)
                arr = graph_to_arrays(G, code, anchor_nids=set(anchor_nids))
            except Exception:
                arr = None
            if arr is None:
                skeleton[fid] = (target, [], [], 0)  # 标记失败，跳过
                continue
            arr["target"] = target
            np.savez(npz_path, **arr)
            if (i + 1) % 50 == 0:
                print(f"  图缓存 {i+1}/{len(todo)}")

    # 全量加载（含已缓存）
    for fid, info in meta.items():
        if fid not in valid_fids:
            continue
        target = int(info["target"])
        npz = os.path.join(cache_dir, fid, f"{GRAPH_CACHE_VER}.npz")
        if not os.path.exists(npz):
            continue
        z = np.load(npz)
        if int(z['target']) != target:
            raise ValueError(f'Graph cache target mismatch: {fid}')
        graphs[fid] = {
            "x": z["x"], "edge_index": z["edge_index"],
            "edge_type": z["edge_type"], "tok_flat": z["tok_flat"],
            "tok_offsets": z["tok_offsets"], "anchor_rows": z["anchor_rows"],
            "target": int(z["target"]),
        }
    return graphs


def load_cache_sources(cache_dirs, collect_anchors=False):
    """Merge explicit caches; duplicate function IDs are a hard error."""
    metadata, graphs, receipts = {}, {}, []
    for directory in cache_dirs:
        meta_path = os.path.join(directory,'meta.json')
        with open(meta_path,encoding='utf8') as handle:
            part=json.load(handle)
        if metadata.keys() & part.keys():
            raise ValueError('Duplicate function IDs across graph caches')
        if collect_anchors and os.path.abspath(directory)!=os.path.abspath(CACHE_DIR):
            raise ValueError('Legacy anchor diagnostics support only the original cache')
        skeleton=_load_or_build_skeleton(part) if collect_anchors else {}
        graphs.update(_load_or_build_graphs(part,skeleton,directory))
        metadata.update(part)
        with open(meta_path,'rb') as handle:
            digest=hashlib.sha256(handle.read()).hexdigest()
        receipts.append({'directory':os.path.abspath(directory),'metadata_sha256':digest,
                         'requested_rows':len(part)})
    return metadata, graphs, receipts


def _to_tensors(g, device):
    return (
        torch.from_numpy(g["x"]).to(device),
        torch.from_numpy(g["tok_flat"]).to(device),
        torch.from_numpy(g["tok_offsets"]).to(device),
        torch.from_numpy(g["edge_index"]).to(device),
        torch.from_numpy(g["edge_type"]).to(device),
    )


# ── 评估 ──────────────────────────────────────────────────

@torch.no_grad()
def eval_holdout(model, graphs, fids):
    """返回 (bag_auc, anchor_sep, detail dict)。"""
    from sklearn.metrics import roc_auc_score
    model.eval()
    ys, ps = [], []
    s_vuln_anchor, s_benign_anchor = [], []
    for fid in fids:
        g = graphs[fid]
        x, tok, tokoff, ei, et = _to_tensors(g, DEVICE)
        logit, s = model(x, tok, tokoff, ei, et)
        ps.append(torch.sigmoid(logit).item())
        ys.append(g["target"])
        if len(g["anchor_rows"]):
            # Softmax attention sums to one per graph. Compare against the graph's
            # uniform baseline (N*s), then macro-average one value per function.
            sv = (s[torch.from_numpy(g["anchor_rows"]).to(DEVICE)] * len(s)).cpu().numpy()
            (s_vuln_anchor if g["target"] == 1 else s_benign_anchor).append(float(np.mean(sv)))
    auc = roc_auc_score(ys, ps) if len(set(ys)) == 2 else float("nan")
    mv = float(np.mean(s_vuln_anchor)) if s_vuln_anchor else float("nan")
    mb = float(np.mean(s_benign_anchor)) if s_benign_anchor else float("nan")
    sep = mv - mb if not (math.isnan(mv) or math.isnan(mb)) else float("nan")
    detail = {
        "n_funcs": len(fids),
        "mean_s_vuln_anchor": round(mv, 4) if not math.isnan(mv) else None,
        "mean_s_benign_anchor": round(mb, 4) if not math.isnan(mb) else None,
    }
    return float(auc), float(sep), detail


# ── 训练 ──────────────────────────────────────────────────

def train(epochs=150, accum=16, lr=1e-3, beta_ent=0.01, patience=30, output_dir=None, collect_anchors=False, cache_dirs=None):
    if epochs <= 0 or accum <= 0 or patience <= 0:
        raise ValueError("epochs, accum and patience must all be positive")
    torch.manual_seed(SEED)
    np.random.seed(SEED)

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    destination = output_dir or os.path.join(root,'learning','model','gat_grouped_candidate')
    if os.path.exists(destination):
        raise FileExistsError('Refusing to overwrite candidate directory')
    # Anchor heuristics are a diagnostic only, not an input to MIL training.
    # Avoid rebuilding the full legacy retrieval pipeline just to train bags.
    meta,graphs,cache_receipts=load_cache_sources(cache_dirs or [CACHE_DIR],collect_anchors)
    print(f"[GAT] 可用函数图: {len(graphs)}")

    # Code/commit/near-clone groups stay together. This is internal model
    # selection, not the final HGL evaluation split.
    from config import DEVIGN_JSON_PATH
    from learning.grouped_split import grouped_split, split_holdout
    train_fids, hold_fids, group_membership = grouped_split(
        meta, graphs.keys(), DEVIGN_JSON_PATH,
        os.path.join(root,'evaluation','protocol_clone_v2_20261005'),SEED)
    hold_fids, calibration_fids = split_holdout(group_membership, hold_fids, SEED)
    rng = random.Random(SEED)
    if (not train_fids
            or len({graphs[f]["target"] for f in hold_fids}) < 2
            or len({graphs[f]["target"] for f in train_fids}) < 2):
        raise ValueError("GAT training requires both classes in train and holdout splits")
    if len({graphs[f]['target'] for f in calibration_fids}) < 2:
        raise ValueError('Calibration split requires both classes')
    print(f"[GAT] train {len(train_fids)} / selection {len(hold_fids)} / calibration {len(calibration_fids)} 函数")

    os.makedirs(destination,exist_ok=False)  # Never overwrite a prior model.
    split_manifest = {'seed':SEED,'train':train_fids,'holdout':hold_fids,
                      'calibration':calibration_fids,'group_membership':group_membership,
                      'graph_cache_sources':cache_receipts}
    with open(os.path.join(destination,'split.json'),'w',encoding='utf8') as handle:
        json.dump(split_manifest,handle,indent=2)
    with open(os.path.join(destination,'split.json'),'rb') as handle:
        split_sha256 = hashlib.sha256(handle.read()).hexdigest()
    model = GATMIL().to(DEVICE)
    opt = torch.optim.Adam(model.parameters(), lr=lr)

    # 未训练对照（随机初始化的 anchor_sep 应 ≈ 0）
    _, sep0, det0 = eval_holdout(model, graphs, hold_fids)
    print(f"[GAT] 未训练对照: anchor_sep={sep0:+.4f} {det0}")

    best_auc, best_state, best_epoch = -1.0, None, -1
    epochs_completed = 0
    for epoch in range(1, epochs + 1):
        epochs_completed = epoch
        model.train()
        rng.shuffle(train_fids)
        tot_loss, tot_bce, tot_ent, n_seen = 0.0, 0.0, 0.0, 0
        opt.zero_grad()
        for bi, fid in enumerate(train_fids):
            g = graphs[fid]
            x, tok, tokoff, ei, et = _to_tensors(g, DEVICE)
            y = torch.tensor(float(g["target"]), device=DEVICE)
            logit, s = model(x, tok, tokoff, ei, et)
            bce = F_bce(logit, y)
            ent = -(s * torch.log(s.clamp_min(1e-9))).sum()   # 注意力熵
            loss = bce + beta_ent * ent
            group_start = bi - (bi % accum)
            group_size = min(accum, len(train_fids) - group_start)
            (loss / group_size).backward()
            tot_loss += loss.item(); tot_bce += bce.item(); tot_ent += ent.item()
            n_seen += 1
            if (bi + 1) % accum == 0 or (bi + 1) == len(train_fids):
                opt.step()
                opt.zero_grad()
        auc, sep, _ = eval_holdout(model, graphs, hold_fids)
        print(f"[GAT] epoch {epoch:3d}: loss={tot_loss/max(n_seen,1):.4f} "
              f"(bce={tot_bce/max(n_seen,1):.4f} ent={tot_ent/max(n_seen,1):.3f}) "
              f"bagAUC={auc:.4f} anchor_sep={sep:+.4f}")
        if auc > best_auc:
            best_auc, best_epoch = auc, epoch
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        elif epoch - best_epoch >= patience:
            print(f"[GAT] early stop (patience={patience})")
            break

    # 恢复最优权重做最终评估
    if best_state is not None:
        model.load_state_dict(best_state)
    auc, sep, det = eval_holdout(model, graphs, hold_fids)
    print(f"\n[GAT] 最终 holdout: bagAUC={auc:.4f} anchor_sep={sep:+.4f} {det}")

    checkpoint_path = os.path.join(destination,'gat_mil.pt')
    report_path = os.path.join(destination,'gat_report.json')
    torch.save({"state_dict": model.state_dict(),
                "config": {"d_feat": len(NODE_FEATURE_NAMES), "d_tok": 32,
                           "hidden": 128, "heads": 4, "n_edge_types": 5,
                           "edge_dim": 16, "d_attn": 64, "dropout": 0.1},
                "feature_names": NODE_FEATURE_NAMES,
                "graph_cache_ver": GRAPH_CACHE_VER,
                "split_manifest_sha256": split_sha256},
               checkpoint_path)
    report = {
        "model": "GATMIL (2-layer GATv2 + edge-type emb + gated MIL readout)",
        "n_functions": len(graphs),
        "n_requested_functions": len(meta),
        "n_unavailable_functions": len(meta)-len(graphs),
        "graph_cache_sources":cache_receipts,
        "graph_cache_ver": GRAPH_CACHE_VER,
        "epochs_run": epochs_completed,
        "best_epoch": best_epoch,
        "untrained_anchor_sep": round(sep0, 4) if not math.isnan(sep0) else None,
        "bag_auc": round(auc, 4) if not math.isnan(auc) else None,
        "anchor_separation": round(sep, 4) if not math.isnan(sep) else None,
        "holdout_detail": det,
        "anchor_metric": "macro mean of N * MIL attention on anchor nodes" if collect_anchors else "not collected",
        "split_manifest_sha256": split_sha256,
        "split_protocol": "Fixed clone/commit grouped internal holdout; not final system test",
        "training_parameters": {"lr":lr,"beta_ent":beta_ent,"accum":accum,"seed":SEED},
        "partition_class_counts": {name:{str(y):sum(graphs[f]['target']==y for f in values) for y in (0,1)}
                                   for name,values in [('train',train_fids),('selection',hold_fids),('calibration',calibration_fids)]},
    }
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"[GAT] 模型 → {checkpoint_path}\n[GAT] 报告 → {report_path}")
    return report


def F_bce(logit, y):
    return torch.nn.functional.binary_cross_entropy_with_logits(logit, y)


if __name__ == "__main__":
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('epochs',type=int,nargs='?',default=150)
    parser.add_argument('accum',type=int,nargs='?',default=16)
    parser.add_argument('--output-dir')
    parser.add_argument('--beta-ent',type=float,default=.01)
    parser.add_argument('--patience',type=int,default=30)
    parser.add_argument('--threads',type=int,default=4)
    parser.add_argument('--with-anchors',action='store_true')
    parser.add_argument('--cache-dir',action='append',help='Repeat to merge disjoint explicit graph caches')
    args=parser.parse_args()
    if args.threads<=0: parser.error('--threads must be positive')
    torch.set_num_threads(args.threads)
    train(epochs=args.epochs,accum=args.accum,beta_ent=args.beta_ent,
          patience=args.patience,output_dir=args.output_dir,collect_anchors=args.with_anchors,cache_dirs=args.cache_dir)
