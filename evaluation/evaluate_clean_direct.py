"""Full-source pure LLM diagnostic baseline; no graph/verifier/truncation."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path
from reasoning.llm_api import create_client
from reasoning.reasoning_loop import parse_binary_verdict
from config import LLM_MODEL
from evaluation.calibrate_security_net import metrics

PROMPT = ('You are a C/C++ security expert. Analyze the following code and '
          'determine if it contains a vulnerability.\n\nCode:\n```c\n{code}\n```\n\n'
          'Is this code vulnerable? Answer with exactly one word: "vulnerable" or "benign".')


def call(meta,source):
    prompt=PROMPT.format(code=source)
    record={'idx':meta['idx'],'target':meta['target'],'group_id':meta['group_id'],
        'source_sha256':hashlib.sha256(source.encode()).hexdigest(),
        'prompt_sha256':hashlib.sha256(prompt.encode()).hexdigest(),
        'prediction':None,'user_prompt':prompt}
    try:
        response=create_client().chat.completions.create(model=LLM_MODEL,
            messages=[{'role':'user','content':prompt}],temperature=0,max_tokens=16)
        answer=response.choices[0].message.content or ''
        record.update(raw_answer=answer,model=response.model,
            finish_reason=response.choices[0].finish_reason,
            tokens_used=response.usage.total_tokens if response.usage else None)
        record['prediction']=parse_binary_verdict(answer)
        if record['prediction'] is None: record['error']='ambiguous verdict'
    except Exception as exc:
        record['error']=str(exc)
    return record


def main():
    p=argparse.ArgumentParser()
    p.add_argument('pilot',type=Path)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    metadata=json.loads((a.pilot/'metadata.json').read_text(encoding='utf8'))['samples']
    sources=json.loads((a.pilot/'sources.json').read_text(encoding='utf8'))
    if len(metadata)!=30: raise ValueError('fixed 30-function scope required')
    a.output.mkdir(parents=True,exist_ok=False)
    results=[]
    with (a.output/'results.jsonl').open('w',encoding='utf8') as out,ThreadPoolExecutor(max_workers=4) as pool:
        jobs=[pool.submit(call,m,sources[str(m['idx'])]['input']) for m in metadata]
        for job in as_completed(jobs):
            record=job.result();results.append(record)
            out.write(json.dumps(record,ensure_ascii=False)+'\n');out.flush()
            print(f'Completed {len(results)}/30 direct calls',flush=True)
    valid=[r for r in results if r['prediction'] is not None]
    report={'configured_model':LLM_MODEL,'n_total':len(results),'n_errors':len(results)-len(valid),
        'metrics':metrics(valid,[r['prediction'] for r in valid]),
        'all_positive_baseline':metrics(metadata,[1]*len(metadata)),
        'all_negative_baseline':metrics(metadata,[0]*len(metadata)),
        'reported_total_tokens':sum(r.get('tokens_used') or 0 for r in results),
        'mean_tokens_per_attempt':sum(r.get('tokens_used') or 0 for r in results)/len(results),
        'scope':'Fixed new development pilot, full source without character truncation, single pass, no verifier',
        'limitations':'Direct calls occur after HGL calls; not randomized interleaved comparison. '
                       'Different prompts/output budgets are part of the baseline; not a sole graph ablation. '
                       'Development only, one run; not a final benchmark claim.'}
    (a.output/'report.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps(report,indent=2))


if __name__ == '__main__': main()
