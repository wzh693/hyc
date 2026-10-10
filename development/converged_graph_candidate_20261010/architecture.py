"""Shared MIL scores -> graph evidence -> bounded reasoning -> shadow verifier.

No client creation, training, implicit heuristic fallback or dataset-label access.
Attention is a selection score, not a causal explanation or vulnerability proof.
"""
from collections import deque
from dataclasses import asdict, dataclass
import hashlib
import json
import math
from pathlib import Path
import re

from config import DANGEROUS_APIS
from linearization.backward_slice import backward_evidence_slice
from planning.observed_state import ObservedProgramState

DEPENDENCIES = frozenset({'REACHING_DEF', 'DFG', 'CDG', 'CONTROL_DEPENDENCE'})
PATH_EDGES = DEPENDENCIES | {'CFG', 'CALL', 'AST'}
DEREFS = {'<operator>.indirection', '<operator>.indexAccess',
          '<operator>.indirectIndexAccess', '<operator>.indirectFieldAccess'}
CALL_PATTERN = re.compile(r'\b(?:' + '|'.join(map(re.escape, sorted(DANGEROUS_APIS))) + r')\s*\(')
SYSTEM = '''Analyze only the supplied C graph/source evidence. Dangerous API presence
and attention scores do not prove a vulnerability. STATE entries are unordered MAY
observations, not execution states. Missing source bounds, guards, aliases or helper
contracts remain unknown. Return one JSON object with verdict (Vulnerable, Benign,
Uncertain), hypothesis, reason, action (Stop or Query), and optionally target (exact
graph node id) and edge_types (DFG, REACHING_DEF, CDG, CONTROL_DEPENDENCE).
Query only to resolve a named missing dependence. Do not invent graph edges.'''


@dataclass(frozen=True)
class Settings:
    graph_budget: int = 4096
    top_k: int = 15
    max_steps: int = 3
    output_tokens: int = 150
    source_chars: int = 1100
    path_chars: int = 1000
    state_chars: int = 300
    max_path_nodes: int = 6
    candidate_cap: int = 512
    slice_nodes: int = 2048
    structure_weight: float = 0.1
    minimum_nodes: int = 8

    def __post_init__(self):
        if not 1 <= self.max_steps <= 3:
            raise ValueError('Reasoning cap must be 1..3')
        if min(self.graph_budget, self.top_k, self.output_tokens, self.source_chars,
               self.path_chars, self.state_chars, self.max_path_nodes,
               self.candidate_cap, self.slice_nodes) <= 0:
            raise ValueError('Positive budgets required')
        if self.minimum_nodes < 0 or not math.isfinite(self.structure_weight) or self.structure_weight < 0:
            raise ValueError('Invalid structural settings')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def sink(attrs):
    # Exclude METHOD/BLOCK containers containing descendant text.
    return attrs.get('node_type') == 'CALL' and bool(CALL_PATTERN.search(attrs.get('code') or ''))


def criterion(attrs):
    return sink(attrs) or (attrs.get('node_type') == 'CALL' and attrs.get('name') in DEREFS)


def node_cost(attrs):
    # Explicit estimate, NOT a tokenizer count or a claim about API token usage.
    return max(1, math.ceil(len(attrs.get('code') or '') / 4)) + 4


class SharedGATScorer:
    def __init__(self, checkpoint_path, split_path):
        import torch
        from learning.gat_model import GATMIL
        from learning.features import NODE_FEATURE_NAMES
        self.torch = torch
        self.checkpoint_path = Path(checkpoint_path)
        self.model_sha256 = hashlib.sha256(self.checkpoint_path.read_bytes()).hexdigest()
        checkpoint = torch.load(self.checkpoint_path, map_location='cpu', weights_only=True)
        if checkpoint.get('split_manifest_sha256') != hashlib.sha256(Path(split_path).read_bytes()).hexdigest():
            raise ValueError('Model/split binding mismatch')
        if checkpoint.get('feature_names') != NODE_FEATURE_NAMES:
            raise ValueError('Feature schema mismatch')
        split = json.loads(Path(split_path).read_text(encoding='utf-8-sig'))
        membership = split['group_membership']
        groups = [{membership[f] for f in split[k]} for k in ('train', 'holdout', 'calibration')]
        if not all(groups) or any(groups[i] & groups[j] for i in range(3) for j in range(i)):
            raise ValueError('Invalid grouped training split')
        self.model = GATMIL(**checkpoint['config'])
        self.model.load_state_dict(checkpoint['state_dict'])
        self.model.eval()
        self.calls = 0

    def __call__(self, graph, source):
        from learning.gat_model import graph_to_arrays
        from learning.features import graph_feature_matrix
        arrays = graph_to_arrays(graph, source)
        if arrays is None:
            raise ValueError('Cannot score empty graph')
        nodes, _, _ = graph_feature_matrix(graph, source)
        with self.torch.no_grad():
            _, attention = self.model(*(self.torch.from_numpy(arrays[k]) for k in
                ('x', 'tok_flat', 'tok_offsets', 'edge_index', 'edge_type')))
        self.calls += 1
        scores = dict(zip(nodes, map(float, attention.cpu().tolist())))
        validate_scores(graph, scores)
        return scores


def validate_scores(graph, scores):
    if set(scores) != set(graph) or any(not math.isfinite(v) or v < 0 for v in scores.values()):
        raise ValueError('Missing/nonfinite/negative shared scores; no fallback permitted')
    if not math.isclose(sum(scores.values()), 1.0, abs_tol=1e-5):
        raise ValueError('Expected globally normalized MIL attention')


def compress(graph, scores, cfg):
    validate_scores(graph, scores)
    mandatory = {n for n, a in graph.nodes(data=True) if sink(a)}
    costs = {n: node_cost(a) for n, a in graph.nodes(data=True)}
    spent = sum(costs[n] for n in mandatory)
    if spent > cfg.graph_budget:
        raise ValueError('Force-keep exceeds estimated graph budget; do not silently drop sinks')
    kept = set(mandatory)
    ordered = sorted(graph, key=lambda n: (-scores[n], str(n)))
    # Largest score-sorted prefix fitting the residual budget (threshold by rank).
    for node in ordered:
        if node in kept:
            continue
        if spent + costs[node] > cfg.graph_budget:
            break
        kept.add(node)
        spent += costs[node]
    degree_fill = []
    if len(kept) < min(cfg.minimum_nodes, len(graph)):
        for node in sorted(graph, key=lambda n: (-graph.degree(n), str(n))):
            if node not in kept and spent + costs[node] <= cfg.graph_budget:
                kept.add(node)
                degree_fill.append(str(node))
                spent += costs[node]
            if len(kept) >= min(cfg.minimum_nodes, len(graph)):
                break
    return graph.subgraph(kept).copy(), dict(estimated_tokens=spent,
        token_estimator='ceil(node_code_chars/4)+4; not exact API tokens',
        force_kept=sorted(map(str, mandatory)), degree_fill=degree_fill,
        original_nodes=len(graph), kept_nodes=len(kept), kept_node_ids=sorted(map(str, kept)),
        score_sha256=digest({str(n): s for n, s in scores.items()}))


def paths_to(graph, targets, cfg, allowed=PATH_EDGES):
    queue = deque((node,) for node in sorted(set(targets), key=str) if node in graph)
    result, visited = [], set()
    while queue and len(result) < cfg.candidate_cap:
        path = queue.popleft()
        if path in visited:
            continue
        visited.add(path)
        result.append(path)
        if len(path) >= cfg.max_path_nodes:
            continue
        predecessors = {a for a, _, attrs in graph.in_edges(path[0], data=True)
                        if attrs.get('edge_type') in allowed and a not in path}
        for node in sorted(predecessors, key=str):
            queue.append((node,) + path)
    return result, bool(queue)


def edge_types(graph, path):
    return {attrs.get('edge_type', 'OTHER') for a, b in zip(path, path[1:])
            for attrs in graph.get_edge_data(a, b, default={}).values()}


def rank_paths(graph, paths, scores, cfg):
    def score(path):
        structural = len(edge_types(graph, path) & PATH_EDGES) / len(PATH_EDGES) - len(path) / 64
        return sum(scores[n] for n in set(path)) + cfg.structure_weight * structural
    return sorted(paths, key=lambda p: (-score(p), tuple(map(str, p))))[:cfg.top_k]


def serialize_paths(graph, paths, max_chars):
    units, displayed = [], []
    for path in paths:
        nodes = []
        for i, node in enumerate(path):
            attrs = graph.nodes[node]
            nodes.append({'id': str(node), 'code': attrs.get('code') or '',
                          'line': attrs.get('line_number'),
                          'incoming_edge_types': sorted(edge_types(graph, path[i-1:i+1])) if i else []})
        unit = json.dumps(nodes, ensure_ascii=False, separators=(',', ':'))
        if len('\n'.join(units + [unit])) <= max_chars:
            units.append(unit)
            displayed.append(path)
    # Whole path units only. No clipped node text or invented connecting arrows.
    return '\n'.join(units), displayed


def context(graph, paths, source, offset, cfg, state, step, previous=None):
    if previous is None:
        src, audit = backward_evidence_slice(graph, paths, source, line_offset=offset,
            max_chars=cfg.source_chars, max_nodes=cfg.slice_nodes)
    else:
        src, audit = '', dict(source_lines=[], enabled=False, reason='incremental paths only')
    path_text, displayed = serialize_paths(graph, paths, cfg.path_chars)
    for node in {n for path in displayed for n in path}:
        state.observe_graph_node(node, graph.nodes[node], step)
    state_text = state.render(cfg.state_chars)
    if previous is None:
        text = f'SRC:\n{src}\n\nPATHS:\n{path_text}\n\nSTATE:\n{state_text}'
    else:
        # Incremental context, preserving the three labels, no full source resend.
        text = f'PRIOR:\n{previous[:300]}\n\nSRC:\n\nPATHS:\n{path_text}\n\nSTATE:\n{state_text}'
    audit.update(displayed_paths=[list(map(str, p)) for p in displayed],
                 source_chars=len(src), path_chars=len(path_text), state_chars=len(state_text))
    return text, audit


def danger_signal(compressed, topk, retained_lines, offset):
    anchors = {n for p in topk for n in p}
    dangerous = {n for n, attrs in compressed.nodes(data=True) if sink(attrs)}
    selected = dangerous & anchors
    mapped = set()
    for node in selected:
        try:
            if int(compressed.nodes[node].get('line_number')) - offset in retained_lines:
                mapped.add(node)
        except (TypeError, ValueError):
            pass
    count, anchored = len(selected), bool(mapped)
    density = len(dangerous) / len(compressed) if len(compressed) else 0.0
    return dict(sink_count=count, sink_anchored=anchored, danger_density=density,
                score=count + int(anchored) + density,
                sink_ids=sorted(map(str, selected)), anchored_sink_ids=sorted(map(str, mapped)),
                meaning='risk proxy only; not structural or semantic vulnerability proof')


def verify(prediction, signal, calibration, model_sha256, policy_sha256):
    if calibration is None:
        return prediction, dict(mode='shadow', flipped=False, audit_tokens=0,
                                reason='No separately validated graph-net calibration')
    if (calibration.get('model_sha256') != model_sha256 or
            calibration.get('policy_sha256') != policy_sha256 or
            calibration.get('status') != 'passed' or
            calibration.get('scope') != 'development' or
            calibration.get('calibration_groups', 0) < 1):
        raise ValueError('Calibration does not bind this model/policy/development scope')
    threshold = calibration.get('threshold')
    if not isinstance(threshold, (int, float)) or not math.isfinite(threshold) or threshold <= 0:
        raise ValueError('Invalid calibration threshold')
    flipped = prediction in {0, None} and signal['sink_anchored'] and signal['score'] >= threshold
    return (1 if flipped else prediction), dict(mode='calibrated', flipped=flipped,
        threshold=threshold, audit_tokens=0, signal=signal,
        limitation='Risk-based override, not a proof that LLM reasoning is wrong')


def decode(text):
    # Fail closed on truncation/non-JSON/unknown verdict; no keyword fallback.
    try:
        value = json.loads(text)
        if not isinstance(value, dict) or value.get('verdict') not in {'Vulnerable', 'Benign', 'Uncertain'}:
            raise ValueError('Invalid verdict')
        if value.get('action', 'Stop') not in {'Query', 'Stop'}:
            raise ValueError('Invalid action')
        if any(not isinstance(value.get(k, ''), str) for k in ('hypothesis', 'reason')):
            raise ValueError('Invalid textual fields')
        return value
    except (ValueError, TypeError):
        return dict(verdict='Uncertain', reason='Malformed or incomplete response', action='Stop')


def run(graph, source, offset, scorer, invoke, cfg=Settings(), calibration=None):
    scores = scorer(graph, source)  # Exactly one global forward; reuse same dictionary.
    compressed, compression = compress(graph, scores, cfg)
    candidates, capped = paths_to(compressed, [n for n, a in compressed.nodes(data=True) if criterion(a)], cfg)
    topk = rank_paths(compressed, candidates, scores, cfg)
    state, trace, seen, predictions = ObservedProgramState(), [], set(), []
    current_graph, pending, prior = compressed, topk, None
    first_lines = []
    for step in range(1, cfg.max_steps + 1):
        prompt, evidence = context(current_graph, pending[:cfg.top_k if step == 1 else 5],
                                   source, offset, cfg, state, step, prior)
        if step == 1:
            first_lines = evidence['source_lines']
        visible_ids = evidence['displayed_paths']
        seen.update(tuple(str(n) for n in p) for p in visible_ids)
        request = dict(messages=[{'role': 'system', 'content': SYSTEM},
                                 {'role': 'user', 'content': prompt}], max_tokens=cfg.output_tokens)
        response = invoke(**request)
        output = decode(response.get('text', ''))
        if response.get('finish_reason') == 'length':
            output = dict(verdict='Uncertain', reason='Output truncated', action='Stop')
        predictions.append(output)
        trace.append(dict(step=step, request=request, response=response, parsed=output, evidence=evidence))
        same_vulnerability = (len(predictions) >= 2 and output['verdict'] == 'Vulnerable' and
            predictions[-2]['verdict'] == 'Vulnerable' and bool(output.get('hypothesis')) and
            output.get('hypothesis') == predictions[-2].get('hypothesis'))
        if same_vulnerability or output.get('action') != 'Query' or step == cfg.max_steps:
            break
        # Explicit, graph-bound query; no unconstrained tool execution.
        node_of = {str(n): n for n in graph}
        target = node_of.get(str(output.get('target')))
        allowed_targets = {node_of[n] for p in visible_ids for n in p}
        kinds = output.get('edge_types')
        if (target not in allowed_targets or not isinstance(kinds, list) or not kinds or
                not all(isinstance(k, str) for k in kinds) or
                not set(kinds) <= DEPENDENCIES or not output.get('reason')):
            trace[-1]['query_rejected'] = 'Invalid target/dependence/gap'
            break
        expanded, query_capped = paths_to(graph, [target], cfg, set(kinds))
        new = [p for p in expanded if tuple(map(str, p)) not in seen]
        pending = rank_paths(graph, new, scores, cfg)[:5]
        trace[-1]['query'] = dict(target=str(target), edge_types=kinds,
                                 new_paths=len(pending), capped=query_capped)
        if not pending:
            break
        current_graph = graph
        prior = json.dumps(output, ensure_ascii=False)[:300]
    main = {'Vulnerable': 1, 'Benign': 0, 'Uncertain': None}[predictions[-1]['verdict']]
    signal = danger_signal(compressed, topk, set(first_lines), offset)
    policy = digest(dict(settings=asdict(cfg), code_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()))
    final, net = verify(main, signal, calibration, getattr(scorer, 'model_sha256', None), policy)
    return dict(main_pred=main, final_pred=final, trace=trace, compression=compression,
        candidate_cap_hit=capped, topk=[list(map(str, p)) for p in topk],
        shared_scores_sha256=compression['score_sha256'], graph_signal=signal, security_net=net,
        policy_sha256=policy, shared_scorer_invocations=1)
