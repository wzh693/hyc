import networkx as nx


class GraphEngine:
    """
    图查询引擎，封装所有受限的图遍历操作。

    LLM 不直接执行图遍历，而是通过本引擎执行预定义动作集合。
    这是 HGL-Vul "受限推理" 机制的核心 —— 模型只做决策，引擎执行实际图操作。
    """

    def __init__(self, G: nx.MultiDiGraph):
        self.G = G

    def expand_dataflow(self, node_id: str, max_hop: int = 6, max_paths: int = 200) -> list:
        """
        沿数据流边（DFG/REACHING_DEF）双向扩展。
        返回从 node_id 出发/到达、长度不超过 max_hop 的数据流路径（每方向截断至 max_paths）。
        支持双向扩展：前向（out_edges）和后向（in_edges）。
        max_paths: 防爆上限——稠密图 hop=6 可枚举出数十万条路径而下游只用前 20 条。
        """
        paths = []
        # 前向扩展
        self._dfs_typed(node_id, [node_id], max_hop, {"REACHING_DEF", "DFG"}, paths, direction="out", max_paths=max_paths)
        # 后向扩展（反向数据流，如赋值语句的左侧变量溯源）
        self._dfs_typed(node_id, [node_id], max_hop, {"REACHING_DEF", "DFG"}, paths, direction="in", max_paths=max_paths)
        return paths

    def expand_controlflow(self, node_id: str, max_hop: int = 6, max_paths: int = 200) -> list:
        """
        沿控制流边（CFG）双向扩展。
        """
        paths = []
        self._dfs_typed(node_id, [node_id], max_hop, {"CFG"}, paths, direction="out", max_paths=max_paths)
        self._dfs_typed(node_id, [node_id], max_hop, {"CFG"}, paths, direction="in", max_paths=max_paths)
        return paths

    def expand_call(self, node_id: str, max_hop: int = 4, max_paths: int = 200) -> list:
        """
        沿调用边（CALL）双向扩展，用于跨函数分析。
        """
        paths = []
        self._dfs_typed(node_id, [node_id], max_hop, {"CALL"}, paths, direction="out", max_paths=max_paths)
        self._dfs_typed(node_id, [node_id], max_hop, {"CALL"}, paths, direction="in", max_paths=max_paths)
        return paths

    def retrieve_alias(self, node_id: str, max_hop: int = 4, max_paths: int = 200) -> list:
        """
        检索别名传播路径（ALIAS_OF / REF），双向扩展。

        max_paths: 与其他动作一致的上限（审查报告性能项：原无上限，
        双向扩展在 REF 密集图上可组合爆炸）。
        """
        paths = []
        self._dfs_typed(node_id, [node_id], max_hop, {"ALIAS_OF", "REF"}, paths, direction="out")
        if len(paths) < max_paths:
            self._dfs_typed(node_id, [node_id], max_hop, {"ALIAS_OF", "REF"}, paths, direction="in")
        return paths[:max_paths]

    def check_reachability(self, source: str, sink: str) -> bool:
        """
        检查两个节点之间是否存在任意类型的可达路径。
        """
        if not self.G.has_node(source) or not self.G.has_node(sink):
            return False
        return nx.has_path(self.G, source, sink)

    def find_path(self, source: str, sink: str) -> list:
        """
        查找 source 到 sink 的最短路径。
        """
        try:
            return nx.shortest_path(self.G, source, sink)
        except nx.NetworkXNoPath:
            return []

    def find_all_paths(self, source: str, sink: str, cutoff: int = 5) -> list:
        """
        查找 source 到 sink 的所有简单路径（限制长度）。
        """
        try:
            return list(nx.all_simple_paths(self.G, source, sink, cutoff=cutoff))
        except nx.NetworkXNoPath:
            return []

    def get_neighbors(self, node_id: str, edge_types: set = None) -> list:
        """
        获取邻居节点，可按边类型过滤。
        """
        neighbors = []
        for _, nxt, edata in self.G.out_edges(node_id, data=True):
            if edge_types is None or edata.get("edge_type") in edge_types:
                neighbors.append(nxt)
        return neighbors

    def get_node_info(self, node_id: str) -> dict:
        """
        获取节点详细信息。
        """
        if self.G.has_node(node_id):
            return dict(self.G.nodes[node_id])
        return {}

    def _dfs_typed(
        self,
        node: str,
        current_path: list,
        remaining_hop: int,
        edge_types: set,
        results: list,
        direction: str = "out",
        _visited: set = None,
        max_paths: int = 0,
    ):
        """
        内部 DFS：沿指定类型的边进行深度优先遍历。

        参数:
            direction: "out" 表示前向扩展（out_edges），"in" 表示后向扩展（in_edges）
                       双向扩展可捕获更完整的传播链，如赋值语句的左侧变量溯源。
            _visited: 已访问节点集合，防止在有环图上产生指数级路径
            max_paths: 结果数上限（0 = 不限）。DFS 顺序确定，截断保留前缀，
                       与调用方 new_paths[:20] 的选取完全一致，仅消除枚举浪费。
        """
        if remaining_hop <= 0:
            return
        if max_paths and len(results) >= max_paths:
            return

        if _visited is None:
            _visited = set()
        if node in _visited:
            return
        _visited = _visited | {node}
        
        if direction == "out":
            edges = self.G.out_edges(node, data=True)
        else:
            edges = self.G.in_edges(node, data=True)
            
        for src, dst, edata in edges:
            if edata.get("edge_type") in edge_types:
                nxt = dst if direction == "out" else src
                # 后向扩展时前驱插到路径头部，保证相邻节点间的边在图中真实存在；
                # 否则追加到尾部会导致 get_edge_data 反查失败，序列化时边全部显示 "?"
                if direction == "out":
                    new_path = current_path + [nxt]
                else:
                    new_path = [nxt] + current_path
                results.append(new_path)
                self._dfs_typed(nxt, new_path, remaining_hop - 1, edge_types, results, direction, _visited, max_paths)