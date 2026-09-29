import json
import networkx as nx
import re
import os


def load_graph(nodes_file: str, edges_file: str) -> nx.MultiDiGraph:
    """
    从 Joern 导出的 nodes.json/edges.json 或 DOT 文件加载 CPG。
    返回 networkx.MultiDiGraph（支持多重边，即同一对节点间可存在多条不同类型的边）。
    """
    if nodes_file.endswith(".dot") or not os.path.exists(nodes_file):
        return load_graph_from_dot(edges_file if edges_file.endswith(".dot") else None)
    return load_graph_from_json(nodes_file, edges_file)


def load_graph_from_json(nodes_file: str, edges_file: str) -> nx.MultiDiGraph:
    """从 Joern 导出的 nodes.json / edges.json 加载 CPG。"""
    G = nx.MultiDiGraph()

    with open(nodes_file, "r", encoding="utf-8") as f:
        nodes = json.load(f)

    with open(edges_file, "r", encoding="utf-8") as f:
        edges = json.load(f)

    for n in nodes:
        node_id = str(n["id"])
        G.add_node(
            node_id,
            code=n.get("code", ""),
            node_type=n.get("_label", n.get("type", "")),
            name=n.get("name", ""),
            line_number=n.get("lineNumber", n.get("line", None)),
            column_number=n.get("columnNumber", n.get("column", None)),
            method=n.get("method", ""),
            file=n.get("file", ""),
        )

    for e in edges:
        src = str(e["outNode"])
        dst = str(e["inNode"])
        label = e.get("label", e.get("edge_type", ""))
        G.add_edge(src, dst, edge_type=label)

    print(f"[Graph] 加载完成: {G.number_of_nodes()} 节点, {G.number_of_edges()} 边")
    return G


def load_graph_from_dot(dot_file: str) -> nx.MultiDiGraph:
    """
    从 Joern 4.x 导出的 DOT 文件加载 CPG。
    DOT 格式示例:
        "30064771074" [label="CALL" CODE="malloc(256)" LINE_NUMBER=3 ...]
        "30064771074" -> "30064771075" [label="CFG"]
    """
    G = nx.MultiDiGraph()

    if not dot_file or not os.path.exists(dot_file):
        raise FileNotFoundError(f"DOT file not found: {dot_file}")

    with open(dot_file, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # 属性段需感知引号：CODE="a[i] = x" 中的 ] 不能截断属性串，
    # 否则其后 LINE_NUMBER/NAME/METHOD_FULL_NAME 全部丢失（数组操作节点系统性缺属性）
    # (?<!-> ) 排除边行目标端：边 "A" -> "B" [label="AST"] 中 "B" [ 同样匹配节点正则,
    # add_node 会用边类型覆盖节点真实 node_type（v1 起的系统性 bug, 已修复）
    node_pattern = r'(?<!-> )"(\d+)"\s*\[\s*((?:"[^"]*"|[^\]])*)\]'
    edge_pattern = r'"(\d+)"\s*->\s*"(\d+)"\s*\[\s*label="([^"]+)"'

    for match in re.finditer(node_pattern, content):
        node_id = match.group(1)
        attrs_str = match.group(2)

        attrs = {}

        label_match = re.search(r'label="([^"]*)"', attrs_str)
        if label_match:
            attrs["node_type"] = label_match.group(1)

        code_match = re.search(r'CODE="([^"]*)"', attrs_str)
        if code_match:
            attrs["code"] = code_match.group(1)

        line_match = re.search(r'LINE_NUMBER=(\d+)', attrs_str)
        if line_match:
            attrs["line_number"] = int(line_match.group(1))

        method_match = re.search(r'METHOD_FULL_NAME="([^"]*)"', attrs_str)
        if method_match:
            attrs["method"] = method_match.group(1)

        name_match = re.search(r'NAME="([^"]*)"', attrs_str)
        if name_match:
            attrs["name"] = name_match.group(1)

        G.add_node(node_id, **attrs)

    for match in re.finditer(edge_pattern, content):
        src = match.group(1)
        dst = match.group(2)
        label = match.group(3)
        G.add_edge(src, dst, edge_type=label)

    print(f"[Graph] 从 DOT 加载完成: {G.number_of_nodes()} 节点, {G.number_of_edges()} 边")
    return G