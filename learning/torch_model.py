"""
GPU 节点重要性模型（RTX 4060, torch CUDA）。

sklearn 风格包装器（fit / predict_proba），可直接作为
train_node_importance.py 的候选模型并经 joblib 序列化。
"""

import numpy as np
import torch
import torch.nn as nn


class NodeMLP(nn.Module):
    def __init__(self, d_in, d_hidden=64):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(d_in, d_hidden), nn.ReLU(), nn.Dropout(0.1),
            nn.Linear(d_hidden, 32), nn.ReLU(),
            nn.Linear(32, 1),
        )

    def forward(self, x):
        return self.net(x).squeeze(-1)


class TorchMLPClassifier:
    """fit(X, y) / predict_proba(X) -> (n, 2)。GPU 可用则自动用 CUDA。"""

    def __init__(self, epochs=150, lr=1e-3, batch_size=2048, weight_decay=1e-4):
        self.epochs = epochs
        self.lr = lr
        self.batch_size = batch_size
        self.weight_decay = weight_decay
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.model = None
        self.classes_ = np.array([0, 1])

    def fit(self, X, y):
        X = np.asarray(X, dtype=np.float32)
        y = np.asarray(y, dtype=np.float32)
        self.model = NodeMLP(X.shape[1]).to(self.device)
        opt = torch.optim.AdamW(self.model.parameters(), lr=self.lr,
                                weight_decay=self.weight_decay)

        # 类别不平衡加权 BCE（正: 漏洞锚点）
        n_pos = max(float(y.sum()), 1.0)
        n_neg = max(float(len(y) - y.sum()), 1.0)
        pos_weight = torch.tensor(n_neg / n_pos, device=self.device)

        xt = torch.from_numpy(X).to(self.device)
        yt = torch.from_numpy(y).to(self.device)
        n = len(yt)
        self.model.train()
        for _ in range(self.epochs):
            perm = torch.randperm(n, device=self.device)
            for s in range(0, n, self.batch_size):
                idx = perm[s:s + self.batch_size]
                opt.zero_grad()
                logits = self.model(xt[idx])
                loss = nn.functional.binary_cross_entropy_with_logits(
                    logits, yt[idx], pos_weight=pos_weight)
                loss.backward()
                opt.step()
        return self

    def predict_proba(self, X):
        X = np.asarray(X, dtype=np.float32)
        self.model.eval()
        with torch.no_grad():
            xt = torch.from_numpy(X).to(self.device)
            p1 = torch.sigmoid(self.model(xt)).cpu().numpy()
        p1 = p1.reshape(-1)
        return np.stack([1 - p1, p1], axis=1)

    def __sklearn_is_fitted__(self):
        return self.model is not None
