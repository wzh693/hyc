"""
跨函数漏洞数据集加载器 (Cross-Function Vuln Dataset Loader)。

加载 vuln-dataset-main 的 JSONL 格式数据，转换为 HGL-Vul 的 NetworkX CPG 格式。

数据集结构:
  - nodes.jsonl:   CPG 节点（含内联边: CFG/DFG/CALL/PARAM_BIND）
  - edges.jsonl:   显式边 (src, dst, edge_type)
  - functions.jsonl: 函数级元数据
  - sinks.jsonl:   漏洞 sink 标注
  - manifest.json: 数据集统计信息

关键特性:
  - 真实 CVE 漏洞（glibc, krb5, uzbl 等）
  - 跨函数调用边（CALL + PARAM_BIND）
  - 精确的 sink 标注（cwe_api:free, cwe_api:strncpy 等）
  - patch-related 节点标记
  - 跳数距离信息
"""

import os
import json
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class VulnSample:
    """单个漏洞样本。"""
    sample_id: str
    patch_id: str
    cve_id: str
    version: str          # "vulnerable" | "fixed" | "benign"
    label: int            # 0=benign, 1=vulnerable
    functions: List[dict] = field(default_factory=list)
    num_nodes: int = 0
    num_edges: int = 0
    num_sinks: int = 0
    hop_distance: int = 0
    vul_type: str = ""
    source_code: str = ""
    metadata: dict = field(default_factory=dict)


class VulnDatasetLoader:
    """
    vuln-dataset-main JSONL 数据集加载器。

    用法:
        loader = VulnDatasetLoader("path/to/vuln-dataset-main")
        samples = loader.load(max_samples=50)
        G = loader.build_graph(samples[0])  # 构建 NetworkX CPG（JSONL 直建，保留完整 API 信息）
    """

    def __init__(self, dataset_dir: str):
        self.dataset_dir = dataset_dir
        self._nodes = {}       # node_id -> node_data
        self._edges = {}       # (patch_id, version) -> [(src, dst, edge_type)]
        self._functions = {}   # (patch_id, version) -> [functions]
        self._sinks = {}       # (patch_id, version) -> [(node_id, sink_data)]
        self._nodes_by_sample = defaultdict(dict)  # (patch_id, version) -> {node_id: data}
        self._edges_by_sample = defaultdict(list)

    def load_manifest(self) -> dict:
        """加载数据集清单。"""
        path = os.path.join(self.dataset_dir, "manifest.json")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def _parse_patch_id(self, patch_id: str) -> str:
        """从 patch_id 提取 CVE 编号。"""
        match = re.search(r'CVE-\d{4}-\d+', patch_id, re.IGNORECASE)
        return match.group(0) if match else patch_id.split("/")[-1]

    def load(self, max_samples: int = None, versions: list = None) -> List[VulnSample]:
        """
        加载数据集，返回 VulnSample 列表。

        参数:
            max_samples: 最大样本数
            versions: 过滤版本，默认 ['vulnerable', 'fixed']（二分类）
        """
        if versions is None:
            versions = ["vulnerable", "fixed"]

        print(f"[DatasetLoader] 加载目录: {self.dataset_dir}")

        # Step 1: 加载所有数据到内存
        self._load_nodes()
        self._load_edges()
        self._load_functions()
        self._load_sinks()

        # Step 2: 按 (patch_id, version) 分组构建样本
        all_keys = set(self._nodes_by_sample.keys())
        print(f"[DatasetLoader] 发现 {len(all_keys)} 个 (patch_id, version) 组合")

        samples = []
        for key in sorted(all_keys):
            patch_id, version = key
            if version not in versions:
                continue

            cve_id = self._parse_patch_id(patch_id)
            nodes = self._nodes_by_sample[key]
            edges = self._edges_by_sample.get(key, [])
            funcs = self._functions.get(key, [])
            sinks = self._sinks.get(key, [])

            # 从 sinks 确定标签（任一 sink 的 label==1 则该样本有漏洞）
            sink_labels = [s.get("label", 0) for s in sinks]
            label = 1 if 1 in sink_labels else 0

            # 确定漏洞类型（从 sink_reason 提取 CWE 信息）
            vul_type = ""
            for s in sinks:
                if s.get("label") == 1:
                    reason = s.get("sink_reason", "")
                    reason_upper = reason.upper()
                    if "FREE" in reason_upper:
                        vul_type = "use_after_free" if label else ""
                    elif "STRNCPY" in reason_upper or "MEMCPY" in reason_upper:
                        vul_type = "buffer_overflow"
                    elif "SYSTEM" in reason_upper or "EXEC" in reason_upper:
                        vul_type = "taint_style"
                    elif "PRINTF" in reason_upper or "FORMAT" in reason_upper:
                        vul_type = "format_string"
                    else:
                        vul_type = reason.replace("cwe_api:", "")
                    break

            # 计算跳数距离
            hop_distances = [f.get("hop_distance", 0) for f in funcs]
            max_hop = max(hop_distances) if hop_distances else 0

            # 构建源代码摘要（从节点拼接）
            code_lines = []
            for nid in sorted(nodes.keys()):
                stmt = nodes[nid].get("statement", "")
                if stmt and stmt not in ("<empty>", ""):
                    code_lines.append(stmt)

            sample = VulnSample(
                sample_id=f"{cve_id}:{version}",
                patch_id=patch_id,
                cve_id=cve_id,
                version=version,
                label=label,
                functions=funcs,
                num_nodes=len(nodes),
                num_edges=len(edges),
                num_sinks=len(sinks),
                hop_distance=max_hop,
                vul_type=vul_type,
                source_code="\n".join(code_lines) if code_lines else "(no source available)",
                metadata={
                    "patch_id": patch_id,
                    "version": version,
                    "num_functions": len(funcs),
                    "sink_reasons": [s.get("sink_reason") for s in sinks],
                    "patch_related_nodes": sum(
                        1 for n in nodes.values() if n.get("is_patch_related")
                    ),
                },
            )
            samples.append(sample)

        if max_samples:
            samples = samples[:max_samples]

        # 统计
        vul_count = sum(1 for s in samples if s.label == 1)
        benign_count = sum(1 for s in samples if s.label == 0)
        cross_func_count = sum(
            1 for s in samples if any(f.get("role") == "callee" for f in s.functions)
        )
        print(f"[DatasetLoader] 加载完成: {len(samples)} 样本 "
              f"(漏洞={vul_count}, 良性={benign_count}, 跨函数={cross_func_count})")

        return samples

    def _load_nodes(self):
        """加载 nodes.jsonl，按 (patch_id, version) 分组。"""
        path = os.path.join(self.dataset_dir, "nodes.jsonl")
        if not os.path.exists(path):
            return

        count = 0
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    node = json.loads(line)
                    patch_id = node.get("patch_id", "unknown")
                    version = node.get("version", "unknown")
                    nid = node.get("id", "")
                    key = (patch_id, version)
                    self._nodes_by_sample[key][nid] = node
                    self._nodes[nid] = node
                    count += 1
                except json.JSONDecodeError:
                    continue
        print(f"  [Nodes] 已加载 {count} 个节点")

    def _load_edges(self):
        """加载 edges.jsonl，按 (patch_id, version) 分组。"""
        path = os.path.join(self.dataset_dir, "edges.jsonl")
        if not os.path.exists(path):
            return

        count = 0
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    edge = json.loads(line)
                    patch_id = edge.get("patch_id", "unknown")
                    version = edge.get("version", "unknown")
                    key = (patch_id, version)
                    self._edges_by_sample[key].append(edge)
                    count += 1
                except json.JSONDecodeError:
                    continue
        print(f"  [Edges] 已加载 {count} 条边")

    def _load_functions(self):
        """加载 functions.jsonl。"""
        path = os.path.join(self.dataset_dir, "functions.jsonl")
        if not os.path.exists(path):
            return

        count = 0
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    func = json.loads(line)
                    patch_id = func.get("patch_id", "unknown")
                    version = func.get("version", "unknown")
                    key = (patch_id, version)
                    if key not in self._functions:
                        self._functions[key] = []
                    self._functions[key].append(func)
                    count += 1
                except json.JSONDecodeError:
                    continue
        print(f"  [Functions] 已加载 {count} 个函数")

    def _load_sinks(self):
        """加载 sinks.jsonl。"""
        path = os.path.join(self.dataset_dir, "sinks.jsonl")
        if not os.path.exists(path):
            return

        count = 0
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    sink = json.loads(line)
                    patch_id = sink.get("patch_id", "unknown")
                    version = sink.get("version", "unknown")
                    key = (patch_id, version)
                    if key not in self._sinks:
                        self._sinks[key] = []
                    self._sinks[key].append(sink)
                    count += 1
                except json.JSONDecodeError:
                    continue
        print(f"  [Sinks] 已加载 {count} 个 sink")

    def build_graph(self, sample: VulnSample) -> "nx.MultiDiGraph":
        """
        将 VulnSample 转换为 HGL-Vul 兼容的 NetworkX CPG 图。

        返回包含以下属性的 MultiDiGraph:
          - 节点: code, node_type, function, is_sink, is_patch_related, label
          - 边: edge_type (CFG/DFG/CALL/PARAM_BIND)
          - 图属性: patch_id, cve_id, hop_distance
        """
        import networkx as nx

        G = nx.MultiDiGraph()
        patch_id = sample.patch_id
        version = sample.version
        key = (patch_id, version)

        # 获取节点和边数据
        nodes = self._nodes_by_sample.get(key, {})
        edges = self._edges_by_sample.get(key, [])

        # 添加节点
        for nid, node_data in nodes.items():
            G.add_node(
                nid,
                code=node_data.get("statement", ""),
                node_type=node_data.get("type", "UNKNOWN"),
                function=node_data.get("function", ""),
                is_sink=node_data.get("is_sink", False),
                sink_reason=node_data.get("sink_reason", ""),
                is_patch_related=node_data.get("is_patch_related", False),
                distance_to_patch=node_data.get("distance_to_patch", 0),
                is_cross_function=node_data.get("is_cross_function", False),
                label=node_data.get("label", 0),
                line=node_data.get("line", 0),
            )

        # 添加显式边（from edges.jsonl）
        for e in edges:
            G.add_edge(e["src"], e["dst"], edge_type=e.get("edge_type", "?"))

        # 同时从节点内联边补充（如果 edges.jsonl 不完整）
        # 有些边直接存储在节点的 *_successors / *_predecessors 字段中
        edge_types_ref = [
            ("CFG_successors", "CFG"),
            ("DFG_successors", "DFG"),
            ("CALL_edges", "CALL"),
            ("PARAM_BIND_edges", "PARAM_BIND"),
        ]
        for nid, node_data in nodes.items():
            for field, edge_type in edge_types_ref:
                successors = node_data.get(field, [])
                for succ in successors:
                    if succ and succ in nodes:
                        # 检查边是否已存在
                        if not G.has_edge(nid, succ):
                            G.add_edge(nid, succ, edge_type=edge_type)

        # 图级元数据
        G.graph["patch_id"] = patch_id
        G.graph["cve_id"] = sample.cve_id
        G.graph["hop_distance"] = sample.hop_distance
        G.graph["label"] = sample.label

        return G

    def build_all_graphs(self, samples: List[VulnSample]) -> List["nx.MultiDiGraph"]:
        """批量构建所有样本的 CPG 图。"""
        graphs = []
        for i, sample in enumerate(samples):
            print(f"\r  [GraphBuild] {i+1}/{len(samples)}: {sample.sample_id}...", end="")
            G = self.build_graph(sample)
            graphs.append(G)
        print()
        return graphs


if __name__ == "__main__":
    # 快速测试
    import sys
    dataset_dir = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\wzh13\Desktop\Network Security Research\vuln-dataset-main"
    loader = VulnDatasetLoader(dataset_dir)
    manifest = loader.load_manifest()
    print(f"  Manifest: {manifest.get('totals', {})}")
    samples = loader.load(max_samples=5)
    for s in samples:
        print(f"\n  {s.sample_id}: label={s.label}, type={s.vul_type}, "
              f"nodes={s.num_nodes}, edges={s.num_edges}, sinks={s.num_sinks}, "
              f"hop={s.hop_distance}, funcs={len(s.functions)}")
        G = loader.build_graph(s)
        print(f"    Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")