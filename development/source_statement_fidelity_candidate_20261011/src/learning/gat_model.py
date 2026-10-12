"""
GAT 注意力共享评分模型（导师版 Method 3.2 的实现基座）。

设计（与论文叙事对齐）:
  - 输入: CPG 节点特征 = 43 维启发式特征（节点类型 one-hot + 属性 + 上下文，
    复用 features.py）+ 32 维 code token hash 嵌入（EmbeddingBag mean-pool）
  - 编码器: 2 层 GATv2Conv，edge-type embedding (edge_dim) 注入注意力
  - 隐藏 128，4 头
  - MIL readout: 门控注意力池化 a_n = softmax(w^T (tanh(V h_n) ⊙ σ(U h_n)))
  - s(n) := a_n —— 节点级重要性，同时服务压缩（summarize_graph）与
    路径排序（retrieve_topk），这是"共享评分"的严格含义
  - bag logit = Linear(Σ_n a_n · h_n)，bag = 一个函数的 CPG

训练（train_gat.py）: MIL 弱监督
  - 包 = 函数 CPG；标签 = 函数级漏洞标签；无节点级标注
  - 损失 = 包级 BCE + β·注意力熵正则（鼓励注意力集中而非弥散）
  - Adam lr=1e-3

技术注记: GATv2 的层内注意力是边级的（per-edge α_{ij}）；本实现的 s(n)
取 MIL readout 的节点级注意力——它是训练目标直接优化的量，语义即
"该节点对函数级判分的贡献"，且天然 ∈ [0,1]、全图 Σ s(n) = 1。
"""

import re
import zlib
import numpy as np
import networkx as nx
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATv2Conv

from learning.features import graph_feature_matrix, NODE_FEATURE_NAMES

# ── 边类型归类（与 features._edge_stats 的分类口径一致）──
EDGE_TYPES = ["AST", "CFG", "DFG", "CALL", "OTHER"]
_ET_AST, _ET_CFG, _ET_DFG, _ET_CALL, _ET_OTHER = range(5)

# token hash 词表（crc32 稳定 hash，不受 PYTHONHASHSEED 影响）
TOK_VOCAB = 8192
TOK_DIM = 32
_MAX_TOKS = 48
_TOK_RE = re.compile(r'\w+|[^\w\s]')


def classify_edge_type(edata: dict) -> int:
    et = edata.get("edge_type", "") or edata.get("label", "") or ""
    if "REACHING_DEF" in et or "DFG" in et or "DEF" in et:
        return _ET_DFG
    if "CFG" in et or "CONTROL" in et or "CDG" in et:
        return _ET_CFG
    if "CALL" in et:
        return _ET_CALL
    if "AST" in et:
        return _ET_AST
    return _ET_OTHER


def node_token_ids(code: str) -> list:
    """节点 code → 稳定 token id 列表（至少 1 个，避开 padding 0）。"""
    toks = _TOK_RE.findall((code or ""))[:_MAX_TOKS]
    return [(zlib.crc32(t.encode("utf-8")) % (TOK_VOCAB - 1)) + 1 for t in toks] or [0]


def graph_to_arrays(G: nx.MultiDiGraph, code: str, anchor_nids=None):
    """CPG → (x, edge_index, edge_type, tok_flat, tok_offsets, anchor_rows)。

    anchor_nids: 弱监督锚点节点 ID 集（dataset.sample_selection 的锚点），
    用于 anchor_separation 评估；传 None 则 anchor_rows 为空数组。
    """
    nids, X, row_of = graph_feature_matrix(G, code)
    if len(nids) == 0:
        return None
    row_of = row_of if row_of else {n: i for i, n in enumerate(nids)}

    # token embedding 输入（flat + offsets，EmbeddingBag 用）
    tok_lists = [node_token_ids(G.nodes[n].get("code") or "") for n in nids]
    tok_flat = [t for toks in tok_lists for t in toks]
    tok_offsets = np.zeros(len(nids) + 1, dtype=np.int64)
    for i, toks in enumerate(tok_lists):
        tok_offsets[i + 1] = tok_offsets[i] + len(toks)

    # 边（MultiDiGraph 保留平行边）
    src, dst, etypes = [], [], []
    for u, v, edata in G.edges(data=True):
        src.append(row_of[u])
        dst.append(row_of[v])
        etypes.append(classify_edge_type(edata))
    edge_index = np.asarray([src, dst], dtype=np.int64) if src else \
        np.zeros((2, 0), dtype=np.int64)
    edge_type = np.asarray(etypes, dtype=np.int64)

    anchor_rows = (np.asarray(sorted(row_of[a] for a in anchor_nids if a in row_of),
                               dtype=np.int64)
                   if anchor_nids else np.zeros(0, dtype=np.int64))

    return dict(
        x=X.astype(np.float32),
        edge_index=edge_index,
        edge_type=edge_type,
        tok_flat=np.asarray(tok_flat, dtype=np.int64),
        tok_offsets=tok_offsets,
        anchor_rows=anchor_rows,
    )


class GATMIL(nn.Module):
    """2 层 GATv2 + edge-type embedding + 门控 MIL 注意力 readout。"""

    def __init__(self, d_feat=len(NODE_FEATURE_NAMES), d_tok=TOK_DIM, hidden=128, heads=4,
                 n_edge_types=len(EDGE_TYPES), edge_dim=16, d_attn=64,
                 dropout=0.1):
        super().__init__()
        self.tok_emb = nn.EmbeddingBag(TOK_VOCAB, d_tok, mode="mean",
                                       padding_idx=0)
        self.in_proj = nn.Linear(d_feat + d_tok, hidden)
        self.edge_emb = nn.Embedding(n_edge_types, edge_dim)
        self.conv1 = GATv2Conv(hidden, hidden // heads, heads=heads,
                               edge_dim=edge_dim, add_self_loops=True,
                               fill_value="mean")
        self.conv2 = GATv2Conv(hidden, hidden // heads, heads=heads,
                               edge_dim=edge_dim, add_self_loops=True,
                               fill_value="mean")
        self.dropout = nn.Dropout(dropout)
        # 门控 MIL 注意力（Ilse et al. 2018）
        self.V = nn.Linear(hidden, d_attn)
        self.U = nn.Linear(hidden, d_attn)
        self.w = nn.Linear(d_attn, 1)
        self.clf = nn.Linear(hidden, 1)

    def encode(self, x, tok_flat, tok_offsets, edge_index, edge_type):
        # tok_offsets 存 N+1 累积边界；EmbeddingBag 1D 模式只需 N 个
        # bag 起点（末 bag 自动延伸至 input 末尾）
        tok = self.tok_emb(tok_flat, tok_offsets[:-1])      # (N, d_tok)
        h = self.in_proj(torch.cat([x, tok], dim=-1))       # (N, hidden)
        e = self.edge_emb(edge_type)                        # (E, edge_dim)
        h = F.elu(self.conv1(h, edge_index, e))
        h = self.dropout(h)
        h = F.elu(self.conv2(h, edge_index, e))
        return h                                              # (N, hidden)

    def _attn_logits(self, h):
        """门控 MIL 注意力 logits（softmax 前，逐节点）。"""
        g = torch.tanh(self.V(h)) * torch.sigmoid(self.U(h))
        return self.w(g).squeeze(-1)

    def forward(self, x, tok_flat, tok_offsets, edge_index, edge_type):
        """单图前向。返回 (bag_logit, s)。"""
        h = self.encode(x, tok_flat, tok_offsets, edge_index, edge_type)
        a_logits = self._attn_logits(h)                     # (N,)
        s = torch.softmax(a_logits, dim=0)                  # 节点级重要性
        bag = (s.unsqueeze(-1) * h).sum(dim=0)              # (hidden,)
        logit = self.clf(bag).squeeze(0)                    # 标量
        return logit, s
