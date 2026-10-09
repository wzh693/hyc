"""Forensic development audit, not a benchmark or ground-truth explanation."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path
from reasoning.llm_api import create_client
from config import LLM_MODEL

ROOT = Path(__file__).resolve().parents[1]
SYSTEM = ('Audit C code evidence, not dataset labels. The excerpt is lossy and may '
          'omit guards, returns or operations. Compare it to the full function. '
          'Report at most two concrete candidate issues, citing exact source line '
          'numbers and missing excerpt lines. Explicitly reject double-free claims '
          'on mutually exclusive or terminating branches. Distinguish local evidence '
          'from assumptions about external callees. Do not infer a vulnerability '
          'from missing cleanup alone. State uncertainties. No dataset label is supplied.')


def audit(idx, source, prompt):
    numbered = '\n'.join(f'{i}: {line}' for i,line in enumerate(source.splitlines(),1))
    user = f'FULL FUNCTION (line numbered):\n{numbered}\n\nACTUAL LLM EXCERPT:\n{prompt}'
    response = create_client().chat.completions.create(model=LLM_MODEL,
        messages=[{'role':'system','content':SYSTEM}, {'role':'user','content':user}],
        temperature=0, max_tokens=650)
    return {'idx':idx, 'source_sha256':hashlib.sha256(source.encode()).hexdigest(),
        'system_prompt':SYSTEM, 'user_prompt':user,
        'answer':response.choices[0].message.content, 'model':response.model,
        'finish_reason':response.choices[0].finish_reason,
        'tokens_used':response.usage.total_tokens if response.usage else None}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--output',type=Path,required=True)
    a = p.parse_args()
    folder = ROOT/'sven_eval/external_type_check'
    sources = json.loads((folder/'sources.json').read_text(encoding='utf8'))
    rows = {r['idx']:r for r in map(json.loads,(folder/'prompts.jsonl').read_text(encoding='utf8').splitlines())}
    a.output.mkdir(parents=True,exist_ok=False)
    results = []
    with (a.output/'receipts.jsonl').open('w',encoding='utf8') as out, ThreadPoolExecutor(max_workers=3) as pool:
        jobs = {pool.submit(audit,idx,sources[str(idx)]['input'],
            rows[idx]['arbitrate']['reasoning_trace'][0]['user_prompt']):idx
            for idx in (11346,22923,25952)}
        for job in as_completed(jobs):
            try:
                record = job.result()
            except Exception as exc:
                record = {'idx':jobs[job],'error':str(exc)}
            results.append(record); out.write(json.dumps(record,ensure_ascii=False)+'\n'); out.flush()
            print(json.dumps(record,ensure_ascii=False),flush=True)
    (a.output/'protocol.json').write_text(json.dumps({
        'n':3,'planned_api_calls':3,'configured_model':LLM_MODEL,
        'purpose':'Selected error forensic audit; no F1/Acc estimation; no labels sent.',
        'limitations':'Model explanations are hypotheses, not verified ground truth.',
        'n_errors':sum('error' in r for r in results)},indent=2),encoding='utf8')


if __name__ == '__main__': main()
