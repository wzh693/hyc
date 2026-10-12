"""Atomic incoming-dependence groups. AST ownership is not data reachability."""
import networkx as nx

DEPENDENCE = frozenset({'REACHING_DEF','DFG','DDG','PDG','CDG','CONTROLS','CONTROL_DEPENDENCE'})
OPERATIONS = frozenset({'CALL','RETURN','CONTROL_STRUCTURE'})


def original_node(attrs):
    # No provenance supplied is allowed for synthetic standalone graphs only.
    return attrs.get('source_origin','original_line_range') == 'original_line_range'


def dependency_group(graph, seed):
    seen={seed}; queue=[seed]; excluded=set()
    witnesses=set()
    while queue:
        node=queue.pop()
        for parent,_,edge in graph.in_edges(node,data=True):
            kind=edge.get('edge_type')
            attrs=graph.nodes[parent]
            assignment_owner=(kind=='AST' and attrs.get('node_type')=='CALL'
                              and (attrs.get('name') or attrs.get('method') or '').startswith('<operator>.assignment'))
            if kind not in DEPENDENCE and not assignment_owner:
                continue
            if not original_node(attrs):
                excluded.add(parent); continue
            witnesses.add((parent,node,kind))
            if parent not in seen:
                seen.add(parent); queue.append(parent)
    return seen, sorted(witnesses,key=str), sorted(excluded,key=str)


def compress_dependencies(graph, token_budget, scores, dangerous):
    from graph.summarize_graph import estimate_token_usage
    limit=int(token_budget*1.2) if token_budget and token_budget>0 else None
    seeds=[n for n,a in graph.nodes(data=True) if original_node(a) and a.get('node_type') in OPERATIONS
           and not a.get('is_external',False)]
    # No BLOCK/METHOD code-content protection and no ID-direction path search.
    seeds.sort(key=lambda n:(-int(n in dangerous),-scores.get(n,0),str(n)))
    selected=set(); accepted=[]; omitted=[]
    for seed in seeds:
        group,witnesses,excluded=dependency_group(graph,seed)
        proposed=selected|group
        cost=estimate_token_usage(graph.subgraph(proposed))
        record=dict(seed=seed,nodes=sorted(group,key=str),dependence_witnesses=witnesses,
                    excluded_unmapped_nodes=excluded,group_cost=estimate_token_usage(graph.subgraph(group)))
        if limit is not None and cost>limit:
            record['reason']='whole_group_exceeds_remaining_estimated_budget'
            omitted.append(record)
        else:
            selected=proposed; accepted.append(record)
    compressed=graph.subgraph(selected).copy()
    compressed.graph.update(graph.graph)
    final_nodes=set(compressed)
    if any(not set(g['nodes'])<=final_nodes for g in accepted):
        raise AssertionError('Accepted dependence group was split')
    if limit is not None and estimate_token_usage(compressed)>limit:
        raise AssertionError('Final estimated graph budget exceeded')
    compressed.graph['dependency_compression']=dict(accepted_groups=accepted,omitted_groups=omitted,
        seed_count=len(seeds),accepted_count=len(accepted),omitted_count=len(omitted),
        estimated_limit=limit,closure_scope='incoming typed dependencies plus assignment ownership inside mapped original lines',
        limitation='Not execution/dominance proof; CFG is not control dependence; omitted/unmapped contracts remain unknown')
    return compressed
