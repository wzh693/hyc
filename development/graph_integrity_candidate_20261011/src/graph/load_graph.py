import json
import networkx as nx
import re
import os


def load_graph(nodes_file: str, edges_file: str = None) -> nx.MultiDiGraph:
    """
    从 Joern 导出的 nodes.json/edges.json 或 DOT 文件加载 CPG。
    返回 networkx.MultiDiGraph（支持多重边，即同一对节点间可存在多条不同类型的边）。
    """
    if nodes_file and nodes_file.endswith(".dot"):
        return load_graph_from_dot(nodes_file)
    if not nodes_file or not os.path.exists(nodes_file):
        dot_file = edges_file if edges_file and edges_file.endswith(".dot") else None
        return load_graph_from_dot(dot_file)
    if not edges_file:
        raise FileNotFoundError("edges_file is required when loading JSON exports")
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
        if G.has_node(src) and G.has_node(dst):
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
    node_pattern = r'(?m)^\s*"(\d+)"\s*\[\s*((?:"(?:\\.|[^"\\])*"|[^\]])*)\]\s*;?'
    edge_pattern = r'"(\d+)"\s*->\s*"(\d+)"\s*\[\s*label="([^"]+)"'

    def attribute_values(attrs_str):
        # Consume whole quoted values, including CODE, before numeric attrs.
        # Otherwise LINE_NUMBER text inside a string literal can spoof metadata.
        pattern = r'(\w+)\s*=\s*(?:"((?:\\.|[^"\\])*)"|([^"\s]+))'
        return {m.group(1): (m.group(2) if m.group(2) is not None else m.group(3))
                for m in re.finditer(pattern, attrs_str)}

    def quoted_attr(values: dict, name: str):
        value = values.get(name)
        if value is None:
            return None
        return (value.replace(r'\"', '"').replace(r'\n', '\n')
                .replace(r'\t', '\t').replace(r'\\', '\\'))

    for match in re.finditer(node_pattern, content):
        node_id = match.group(1)
        attrs_str = match.group(2)
        values = attribute_values(attrs_str)

        attrs = {}

        label = quoted_attr(values, "label")
        if label is not None:
            attrs["node_type"] = label

        code_value = quoted_attr(values, "CODE")
        if code_value is not None:
            attrs["code"] = code_value

        for attribute, key in (("LINE_NUMBER", "line_number"),
                               ("COLUMN_NUMBER", "column_number")):
            value = values.get(attribute, "")
            if value.isdecimal():
                attrs[key] = int(value)

        method = quoted_attr(values, "METHOD_FULL_NAME")
        if method is not None:
            attrs["method"] = method

        name = quoted_attr(values, "NAME")
        if name is not None:
            attrs["name"] = name

        for field, key in (("FILENAME", "file"), ("TYPE_FULL_NAME", "type_full_name")):
            value = quoted_attr(values, field)
            if value is not None:
                attrs[key] = value
        if "IS_EXTERNAL" in values:
            attrs["is_external"] = values["IS_EXTERNAL"].lower() == "true"

        G.add_node(node_id, **attrs)

    for match in re.finditer(edge_pattern, content):
        src = match.group(1)
        dst = match.group(2)
        label = match.group(3)
        if G.has_node(src) and G.has_node(dst):
            G.add_edge(src, dst, edge_type=label)

    print(f"[Graph] 从 DOT 加载完成: {G.number_of_nodes()} 节点, {G.number_of_edges()} 边")
    return G
