"""Only node type, code length and token hashes; no API/CWE/context heuristics."""
import math
import numpy as np
from learning.gat_model import node_token_ids, classify_edge_type

NODE_TYPES = ('CALL', 'METHOD', 'CONTROL_STRUCTURE', 'IDENTIFIER', 'LITERAL', 'BLOCK')
FEATURE_NAMES = ['type_' + kind for kind in NODE_TYPES] + ['log_code_chars']


def graph_to_arrays(graph):
    nodes = list(graph)
    if not nodes:
        return None
    row_of = {node: i for i, node in enumerate(nodes)}
    x = np.asarray([[float(kind in (graph.nodes[n].get('node_type') or '')) for kind in NODE_TYPES]
        + [math.log1p(len(graph.nodes[n].get('code') or ''))] for n in nodes], dtype=np.float32)
    tokens = [node_token_ids(graph.nodes[n].get('code') or '') for n in nodes]
    offsets = [0]
    for values in tokens:
        offsets.append(offsets[-1] + len(values))
    edges = list(graph.edges(data=True))
    return dict(x=x, tok_flat=np.asarray([v for values in tokens for v in values], dtype=np.int64),
        tok_offsets=np.asarray(offsets, dtype=np.int64),
        edge_index=np.asarray([[row_of[u] for u, _, _ in edges],
                               [row_of[v] for _, v, _ in edges]], dtype=np.int64).reshape(2, -1),
        edge_type=np.asarray([classify_edge_type(attrs) for _, _, attrs in edges], dtype=np.int64))
