"""Full254 graph construction/provenance + atomic compression preflight. Zero API."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import socket
import sys
from unittest.mock import patch
from evaluation.test_graph_guided_foundation import verify_foundation
from evaluation.preflight_graph_display import read,sha,graph_hash

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'development/graph_integrity_candidate_20261011/src'
OUT=ROOT/'output/graph_integrity_preflight_20261011'


def main():
    if OUT.exists(): raise ValueError('Fresh output only')
    base=verify_foundation(); os.environ.update(base['settings'])
    sys.path.insert(0,str(SOURCE))
    from graph.load_graph import load_graph_from_dot
    from graph.quality import annotate_quality
    from graph.summarize_graph import summarize_graph,estimate_token_usage
    from graph.dependency_compression import dependency_group
    from retrieval.candidate_paths import extract_all_candidate_paths
    from evaluation.audit_type_coverage_baseline import memoized_search
    from evaluation.audit_graph_read_evidence import extract_facts,related_facts,matching_nodes
    ref=read(ROOT/'output/sven_complete_src_eval_20261008/manifest.json')
    data=read(ref['dataset'])
    if len(data)!=254 or sha(ref['dataset'])!=ref['dataset_sha256']: raise ValueError('Dataset drift')
    source_hashes={p.relative_to(SOURCE).as_posix():sha(p) for p in SOURCE.rglob('*.py')}
    OUT.mkdir(parents=True)
    manifest=dict(source_hashes=source_hashes,foundation_hashes=base['code_hashes'],settings=base['settings'],
        samples=ref['samples'],dataset=ref['dataset'],dataset_sha256=ref['dataset_sha256'],
        tools={str(Path(__file__).relative_to(ROOT)):sha(__file__),
               'evaluation/test_graph_integrity_20261011.py':sha(ROOT/'evaluation/test_graph_integrity_20261011.py')},
        planned_rows=254,new_api_calls=0,graph_budget=4096,estimated_hard_limit=4915,
        expected_original_bad_indices=[146],quality_evaluation=False)
    (OUT/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf8')
    rows=[];cache={};external=[0]
    def blocked(*a,**k): external[0]+=1; raise RuntimeError('External access forbidden')
    with patch.object(socket.socket,'connect',blocked),patch.object(socket,'create_connection',blocked),patch('subprocess.Popen',blocked),patch.object(re,'search',memoized_search(re.search)):
        for sample in ref['samples']:
            idx=sample['idx'];code=data[idx]['input'];row=dict(idx=idx,error=None)
            try:
                dot=Path(sample['cache_path'])/'export/export.dot'
                if sha(dot)!=sample['cpg_sha256'] or sha(sample['source_path'])!=sample['wrapped_source_sha256'] or hashlib.sha256(code.encode()).hexdigest()!=sample['source_sha256']:
                    raise ValueError('Input drift')
                key=(sample['source_sha256'],sample['cpg_sha256'])
                if key not in cache:
                    with contextlib.redirect_stdout(io.StringIO()): graph=load_graph_from_dot(str(dot))
                    quality=annotate_quality(graph,code,Path(sample['source_path']).read_text(encoding='utf8'))
                    value=dict(quality=quality,original_nodes=len(graph),graph_hash=graph_hash(graph))
                    if quality['usable']:
                        with contextlib.redirect_stdout(io.StringIO()):
                            compressed=summarize_graph(graph,token_budget=4096,source_code=code,verbose=False)
                            paths=extract_all_candidate_paths(compressed,source_code=code)
                        audit=compressed.graph['dependency_compression']
                        for group in audit['accepted_groups']:
                            actual,witnesses,excluded=dependency_group(graph,group['seed'])
                            if actual!=set(group['nodes']) or witnesses!=group['dependence_witnesses'] or excluded!=group['excluded_unmapped_nodes']:
                                raise ValueError('Closure reconstruction mismatch')
                            if not actual<=set(compressed): raise ValueError('Group split')
                        for a,b,k,attrs in compressed.edges(keys=True,data=True):
                            if graph[a][b][k]!=attrs: raise ValueError('Invented edge')
                        if estimate_token_usage(compressed)>4915: raise ValueError('Budget exceeded')
                        reads,updates,guards=extract_facts(code)
                        selected_updates=[];selected_guards=[]
                        for fact in reads:
                            us,gs=related_facts(fact,updates,guards)
                            for u in us:
                                if u not in selected_updates: selected_updates.append(u)
                            for g in gs:
                                if g not in selected_guards: selected_guards.append(g)
                        presence={}
                        for label,values in [('reads',reads),('updates',selected_updates),('guards',selected_guards)]:
                            presence[label]=dict(total=len(values),original=sum(bool(matching_nodes(graph,v,quality['source_line_offset'])) for v in values),
                                compressed=sum(bool(matching_nodes(compressed,v,quality['source_line_offset'])) for v in values))
                        value.update(compressed_nodes=len(compressed),compressed_hash=graph_hash(compressed),estimated_tokens=estimate_token_usage(compressed),
                            candidate_count=len(paths),evidence=presence,dependency_compression=audit)
                    cache[key]=value
                row.update(cache[key])
            except Exception as exc: row['error']=repr(exc)
            rows.append(row)
            with (OUT/'rows.jsonl').open('a',encoding='utf8') as handle:handle.write(json.dumps(row,ensure_ascii=False)+'\n')
            if (idx+1)%20==0: print(f'OFFLINE {idx+1}/254 errors={sum(bool(r["error"]) for r in rows)}',flush=True)
    invalid=[r['idx'] for r in rows if not r.get('quality',{}).get('usable')]
    no_paths=[r['idx'] for r in rows if r.get('quality',{}).get('usable') and not r.get('candidate_count')]
    report=dict(rows=len(rows),errors=[dict(idx=r['idx'],error=r['error']) for r in rows if r['error']],
        invalid_graph_indices=invalid,additional_no_path_indices=no_paths,external_attempts=external[0],new_api_calls=0,
        accepted_groups=sum(r.get('dependency_compression',{}).get('accepted_count',0) for r in rows),
        omitted_groups=sum(r.get('dependency_compression',{}).get('omitted_count',0) for r in rows),
        evidence={c:{s:sum(r.get('evidence',{}).get(c,{}).get(s,0) for r in rows) for s in ('total','original','compressed')} for c in ('reads','updates','guards')},
        pass_invariants=not external[0] and not any(r['error'] for r in rows),
        paid_input_gate=invalid==[146] and not no_paths and not any(r['error'] for r in rows),
        limitation='Structural/source-coordinate checks only; wrappers remain semantically uncertain; no LLM accuracy claim.')
    if {p.relative_to(SOURCE).as_posix():sha(p) for p in SOURCE.rglob('*.py')}!=source_hashes: raise ValueError('Source drift')
    verify_foundation()
    (OUT/'report.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps(report,indent=2),flush=True)


if __name__=='__main__': main()
