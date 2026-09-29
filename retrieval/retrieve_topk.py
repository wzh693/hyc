import networkx as nx
from retrieval.path_ranker import rank_paths
from config import TOP_K_PATHS


def retrieve_topk(
    G: nx.MultiDiGraph,
    candidate_paths: list,
    k: int = TOP_K_PATHS,
    vuln_type: str = "Generic",
    learned_scores: dict = None,
) -> list:
    """
    从候选路径中检索 Top-K 漏洞相关路径。

    流程:
      1. 对所有候选路径进行结构化特征编码
      2. 基于加权特征评分排序（漏洞类型条件权重）
      3. 返回 Top-K 路径

    learned_scores: 技术点②学习式节点重要性（None = 关闭）
    """
    scored = rank_paths(G, candidate_paths, top_k=k, vuln_type=vuln_type, learned_scores=learned_scores)
    topk = [path for _, path in scored]
    print(
        f"[RetrieveTopK] 从 {len(candidate_paths)} 条候选路径中选出 Top-{len(topk)}"
    )
    for i, (s, p) in enumerate(scored[:k]):
        print(f"  #{i+1}: score={s:.2f}, 长度={len(p)}")
    return topk