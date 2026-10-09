"""Full-source binary baseline versus identical source + bounded graph facts.

Development-only; same output budget, fresh interleaved calls, no safety net.
Graph facts are descriptive, never interpreted as vulnerability proof.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import contextlib
import hashlib
import io
import json
from pathlib import Path
import re
from graph.load_graph import load_graph_from_dot
from graph.security_net import _mask_noncode
from reasoning.llm_api import create_client
from reasoning.reasoning_loop import parse_binary_verdict
from config import LLM_MODEL
from evaluation.evaluate_clean_direct import PROMPT
from evaluation.calibrate_security_net import metrics


def graph_facts(graph,budget=600):
    operations={n:d for n,d in graph.nodes(data=True) if d.get('node_type') in {'CALL','RETURN'}}
    relevant=set()
    for n,d in operations.items():
        code=_mask_noncode(d.get('code','') or '')
        if re.search(r'\b(?:free|av_free|kfree|malloc|calloc|realloc|av_mallocz|memcpy|strcpy|read|recv)\s*\(|\[[^]]+\]|->',code):
            relevant.add(n)
    candidates=set()
    for a,b,data in graph.edges(data=True):
        kind=data.get('edge_type','')
        if kind not in {'CFG','REACHING_DEF','DFG'} or a not in operations or b not in operations:
            continue
        if a not in relevant and b not in relevant: continue
        x,y=operations[a],operations[b]
        if not x.get('line_number') or not y.get('line_number'): continue
        def description(d):
            text=' '.join((d.get('code','') or '').split())
            return f"L{d['line_number']}:{text[:85]}"+('...' if len(text)>85 else '')
        candidates.add(f'{description(x)} --{kind}--> {description(y)}')
    chosen=[]
    # Global lexical order is deterministic and independent of labels/results.
    for line in sorted(candidates):
        if sum(len(s)+1 for s in chosen)+len(line)+1<=budget: chosen.append(line)
    return '\n'.join(chosen)


def pair(meta,source,facts):
    base=PROMPT.format(code=source)
    extra=('\n\nAuxiliary CPG facts (not a vulnerability verdict; CFG reachability '
           'does not prove simultaneous execution or sufficient guards):\n'+facts+
           '\nUse the full source to check branch termination and actual operands. '
           'Answer only vulnerable or benign.') if facts else ''
    prompts=[('control',base),('full_graph',base+extra)]
    if meta['idx']%2: prompts.reverse()
    client=create_client();results=[]
    for variant,prompt in prompts:
        record={'idx':meta['idx'],'target':meta['target'],'group_id':meta['group_id'],
            'variant':variant,'repeat':0,'user_prompt':prompt,'prediction':None,
            'source_sha256':hashlib.sha256(source.encode()).hexdigest(),
            'source_prompt_sha256':hashlib.sha256(base.encode()).hexdigest(),
            'prompt_sha256':hashlib.sha256(prompt.encode()).hexdigest()}
        try:
            response=client.chat.completions.create(model=LLM_MODEL,
                messages=[{'role':'user','content':prompt}],temperature=0,max_tokens=16)
            answer=response.choices[0].message.content or ''
            record.update(raw_answer=answer,model=response.model,
                finish_reason=response.choices[0].finish_reason,
                tokens_used=response.usage.total_tokens if response.usage else None)
            record['prediction']=parse_binary_verdict(answer)
            if record['prediction'] is None: record['error']='ambiguous verdict'
        except Exception as exc: record['error']=str(exc)
        results.append(record)
    return results


def main():
    p=argparse.ArgumentParser();p.add_argument('pilot',type=Path);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    metadata=json.loads((a.pilot/'metadata.json').read_text(encoding='utf8'))['samples']
    sources=json.loads((a.pilot/'sources.json').read_text(encoding='utf8'))
    if len(metadata)!=30: raise ValueError('fixed 30-function scope required')
    a.output.mkdir(parents=True,exist_ok=False)
    prepared={}
    for m in metadata:
        with contextlib.redirect_stdout(io.StringIO()):
            graph=load_graph_from_dot(str(a.pilot/'cpg'/m['sample_id']/'export/export.dot'))
        prepared[m['idx']]=graph_facts(graph)
    if not any(prepared.values()):
        raise ValueError('No graph facts: stop before model calls; inspect loader/evidence coverage')
    protocol={'samples':30,'repeats':1,'planned_api_calls':60,'configured_model':LLM_MODEL,
        'fact_budget_chars':600,'output_budget_tokens':16,'safety_net':False,
        'selection':'same fixed development30; no error-selected sampling',
        'samples_with_facts':sum(bool(s) for s in prepared.values()),
        'scope':'full source plus graph facts, not full adaptive HGL/GAT validation',
        'limitations':'One development pilot and one repeat; no locked-test use.'}
    (a.output/'protocol.json').write_text(json.dumps(protocol,indent=2),encoding='utf8')
    results=[]
    with (a.output/'results.jsonl').open('w',encoding='utf8') as out,ThreadPoolExecutor(max_workers=4) as pool:
        jobs=[pool.submit(pair,m,sources[str(m['idx'])]['input'],prepared[m['idx']]) for m in metadata]
        for job in as_completed(jobs):
            records=job.result();results.extend(records)
            for r in records:out.write(json.dumps(r,ensure_ascii=False)+'\n')
            out.flush();print(f'Completed {len(results)//2}/30 pairs',flush=True)
    # Pairwise complete-case metrics so failure patterns cannot favor a side.
    valid_indices={r['idx'] for r in results if 'error' in r}
    runs=[]
    for variant in ('control','full_graph'):
        group=[r for r in results if r['variant']==variant and r['idx'] not in valid_indices]
        runs.append({'variant':variant,'metrics':metrics(group,[r['prediction'] for r in group]),
            'mean_tokens':sum(r.get('tokens_used') or 0 for r in group)/len(group) if group else None})
    report={**protocol,'n_error_calls':sum('error' in r for r in results),
        'excluded_pair_indices':sorted(valid_indices),'runs':runs,
        'total_reported_tokens':sum(r.get('tokens_used') or 0 for r in results)}
    (a.output/'report.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps(report,indent=2))


if __name__ == '__main__':main()
