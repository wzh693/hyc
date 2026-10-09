"""Offline label-blind source/response audit. Never calls a model or changes predictions."""
import argparse
from collections import defaultdict
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
from evaluation.audit_evidence_preservation import classify_lines, src_segment, visible_lines, CATEGORIES

POSITIVE_TYPES = {'uaf', 'use-after-free', 'double free', 'buffer overflow',
                  'out-of-bounds read', 'integer overflow', 'taint', 'null deref', 'memory leak'}


def response_facts(answer):
    # Horizontal whitespace only: an empty HYPOTHESIS must not absorb REASONING.
    hypothesis=re.search(r'^\s*HYPOTHESIS:[ \t]*([^\r\n]*)',answer,re.M|re.I)
    action=re.search(r'\bACTION:[ \t]*(.*)',answer,re.S|re.I)
    payload=None
    if action:
        try:
            payload=json.JSONDecoder().raw_decode(action.group(1).lstrip())[0]
        except (ValueError,TypeError):
            pass
    h=hypothesis.group(1).strip() if hypothesis else ''
    return {'hypothesis_present':bool(h),'hypothesis_header_present':hypothesis is not None,
            'hypothesis_text':h,'unqualified_positive':h.lower() in POSITIVE_TYPES,
            'action_marker_present':action is not None,
            'action_json_complete':isinstance(payload,dict) and isinstance(payload.get('action'),str),
            'hypothesis_line_has_terminator':bool(hypothesis and
                hypothesis.end()<len(answer) and answer[hypothesis.end()] in '\r\n')}


def source_visibility(source, segment, receipt):
    audit=receipt.get('arbitrate',{}).get('module_audit',{}).get('backward_slice',{})
    if audit.get('enabled') and not audit.get('fallback'):
        ids=set(audit['source_lines'])
        if any(not 1<=n<=len(source.splitlines()) for n in ids):raise ValueError('Invalid recorded line')
        rendered='\n'.join(source.splitlines()[n-1] for n in sorted(ids))
        if rendered.strip()!=segment.strip():raise ValueError('Slice receipt differs from actual SRC')
        return ids,set(),'recorded_exact_ids'
    visible,ambiguous=visible_lines(source,segment)
    return visible,ambiguous,'unique_whole_line_proxy'


def audit(run):
    root=Path(__file__).resolve().parents[1]
    manifest=json.loads((run/'manifest.json').read_text(encoding='utf-8'))
    for name,digest in manifest['code_hashes'].items():
        if hashlib.sha256((root/name).read_bytes()).hexdigest()!=digest:
            raise ValueError('Prediction code differs from frozen run: '+name)
    os.environ.update(manifest['settings'])
    from graph.load_graph import load_graph
    module=importlib.import_module('reasoning.reasoning_loop')
    rows=[json.loads(line) for line in (run/'results.jsonl').read_text(encoding='utf-8').splitlines()]
    calls=[json.loads(line) for line in (run/'api_receipts.jsonl').read_text(encoding='utf-8').splitlines()]
    keyed={(r['sample_id'],r['profile'],r['repeat']):r for r in rows}
    expected={(s['sample_id'],p,rep) for s in manifest['samples'] for p in manifest['profiles'] for rep in (1,2)}
    if len(keyed)!=len(rows) or set(keyed)!=expected:raise ValueError('Incomplete/duplicate results')
    successful=defaultdict(list)
    call_rows=[]
    for invocation,call in enumerate(calls):
        key=call['sample_id'],call['profile'],call['repeat']
        if key not in expected:raise ValueError('Unexpected API receipt')
        if call.get('error'):
            call_rows.append(dict(sample_id=key[0],profile=key[1],repeat=key[2],invocation=invocation,
                                  error=True,usage_known=False))
            continue
        successful[key].append(call)
        facts=response_facts(call.get('answer') or '')
        facts['unambiguous_type_parser_miss']=facts['unqualified_positive'] and (
            module._extract_vulnerability_type(call['answer'],is_final=True)=='Unknown')
        call_rows.append(dict(sample_id=key[0],profile=key[1],repeat=key[2],invocation=invocation,
            error=False,finish_reason=call.get('finish_reason'),completion_tokens=call.get('completion_tokens'),**facts))
    for key,row in keyed.items():
        trace=row.get('arbitrate',{}).get('reasoning_trace',[])
        answers=successful[key]
        if len(trace)!=len(answers) or any(t['answer']!=c['answer'] for t,c in zip(trace,answers)):
            raise ValueError('Trace/call receipt mismatch')
    evidence=[]
    for s in manifest['samples']:
        sid=s['sample_id']
        if s.get('error'):
            evidence.append({'sample_id':sid,'preparation_error':True})
            continue
        path=Path(s['source_path'])
        source=path.read_text(encoding='utf-8')
        if hashlib.sha256(source.encode()).hexdigest()!=s['source_raw_sha256']:raise ValueError('Source changed')
        dot=path.parent/'export/export.dot'
        graph=load_graph(str(dot))
        if len(graph)!=s['graph_nodes'] or graph.number_of_edges()!=s['graph_edges']:
            raise ValueError('Graph counts differ from preparation')
        base=keyed[sid,'control',1]['arbitrate']['module_audit']['evidence_lineage']
        def mapped(ids,allow_synthetic=False):
            result=set()
            for node in ids:
                if node not in graph:
                    if allow_synthetic:continue
                    raise ValueError('Receipt node missing from graph')
                try:n=int(graph.nodes[node].get('line_number'))-base['source_line_offset']
                except (TypeError,ValueError):continue
                if 1<=n<=len(source.splitlines()):result.add(n)
            return result
        full=mapped(graph.nodes)
        compressed=mapped(base['compressed_node_ids'],allow_synthetic=True)
        categories=classify_lines(source)
        profiles={}
        for profile in manifest['profiles']:
            key=sid,profile,1
            first=successful[key][0]
            segment=src_segment(next(m['content'] for m in first['request']['messages'] if m['role']=='user'))
            repeat_first=successful[sid,profile,2][0]
            other=src_segment(next(m['content'] for m in repeat_first['request']['messages'] if m['role']=='user'))
            if segment!=other:raise ValueError('SRC changed between repeats')
            shown,ambiguous,kind=source_visibility(source,segment,keyed[key])
            a=keyed[key]['arbitrate']['module_audit']['backward_slice']
            selected=set(a.get('selected_source_lines',[]))
            criteria=mapped(a.get('criteria_node_ids',[]))
            profiles[profile]={'visible_lines':sorted(shown),'ambiguous_lines':sorted(ambiguous),
                'mapping_kind':kind,'src_chars':len(segment),'slice_enabled':a.get('enabled',False),
                'fallback':a.get('fallback',False),'node_cap_hit':a.get('node_cap_hit',False),
                'unmapped_nodes':a.get('unmapped_nodes',0),
                'selected_lines_missing_from_src':sorted(selected-shown-ambiguous),
                'criterion_lines_missing_from_src':sorted(criteria-shown-ambiguous)}
        comparisons={}
        for candidate,baseline in (('slice_only','control'),('grouped_slice','control'),('grouped_slice','slice_only')):
            a,b=profiles[baseline],profiles[candidate]
            comparisons[candidate+'-vs-'+baseline]={name:{
                'lost':sorted((lines & set(a['visible_lines']))-set(b['visible_lines'])-set(b['ambiguous_lines'])),
                'gained':sorted((lines & set(b['visible_lines']))-set(a['visible_lines'])-set(a['ambiguous_lines']))}
                for name,lines in categories.items()}
        evidence.append({'sample_id':sid,'preparation_error':False,
            'compressed_ids_absent_from_full_graph':sum(n not in graph for n in base['compressed_node_ids']),
            'graph_sha256_at_audit':hashlib.sha256(dot.read_bytes()).hexdigest(),
            'graph_line_coverage':{name:{'source':len(lines),'absent_full':len(lines-full),
                'absent_compressed':len((lines & full)-compressed)} for name,lines in categories.items()},
            'profiles':profiles,'comparisons':comparisons})
    valid=[r for r in evidence if not r['preparation_error']]
    totals={comparison:{category:{field:sum(len(r['comparisons'][comparison][category][field]) for r in valid)
        for field in ('lost','gained')} for category in CATEGORIES} for comparison in valid[0]['comparisons']}
    response_summary={}
    for rep in (1,2):
        for profile in manifest['profiles']:
            batch=[c for c in call_rows if c['profile']==profile and c['repeat']==rep and not c['error']]
            response_summary[f'{profile}/r{rep}']={reason:{'calls':len(group),**{
                field:sum(c[field] for c in group) for field in ('hypothesis_present','action_marker_present',
                'action_json_complete','hypothesis_line_has_terminator','unambiguous_type_parser_miss')}}
                for reason in ('length','stop') for group in [[c for c in batch if c['finish_reason']==reason]]}
    slice_summary={p:{'fallback_samples':sum(r['profiles'][p]['fallback'] for r in valid),
        'node_cap_samples':sum(r['profiles'][p]['node_cap_hit'] for r in valid),
        'samples_with_selected_line_loss':sum(bool(r['profiles'][p]['selected_lines_missing_from_src']) for r in valid),
        'samples_with_criterion_line_loss':sum(bool(r['profiles'][p]['criterion_lines_missing_from_src']) for r in valid),
        'unmapped_nodes':sum(r['profiles'][p]['unmapped_nodes'] for r in valid)} for p in manifest['profiles']}
    return {'rows':evidence,'calls':call_rows,'report':{'samples':len(evidence),'valid_graphs':len(valid),
        'preparation_errors':len(evidence)-len(valid),'source_loss_totals':totals,
        'slice_summary':slice_summary,'response_summary':response_summary,'api_calls':0,'prediction_changes':0,
        'input_hashes':{name:hashlib.sha256((run/name).read_bytes()).hexdigest()
            for name in ('manifest.json','results.jsonl','api_receipts.jsonl')},
        'limitations':['No ground-truth labels used; no rule/threshold tuning.',
            'Line/category coverage is not semantic completeness, protection, or absence from PATHS/STATE.',
            'Ambiguous repeated baseline lines excluded from directional loss claims.',
            'Graph bytes were not frozen in run manifest; audit records current hashes and validates counts/IDs.',
            'Length finish or missing ACTION alone does not prove wrong classification or benefit from more tokens.']}}


def main():
    p=argparse.ArgumentParser();p.add_argument('--run',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    if args.output.exists():raise ValueError('New output directory required')
    result=audit(args.run);args.output.mkdir(parents=True)
    for name,payload in result.items():
        (args.output/f'{name}.json').write_text(json.dumps(payload,indent=2),encoding='utf-8')
    print(json.dumps(result['report'],indent=2))


if __name__=='__main__':main()
