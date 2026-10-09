"""Post-preflight decomposition, never quality scoring or candidate tuning."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

def read(path): return json.loads(Path(path).read_text(encoding='utf-8-sig'))
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def analyze(run):
    manifest,report=read(run/'manifest.json'),read(run/'report.json')
    rows=[json.loads(line) for line in (run/'rows.jsonl').read_text(encoding='utf8').splitlines()]
    assert len(rows)==508 and all(not r.get('error') for r in rows)
    indexed={(r['idx'],r['profile']):r for r in rows}
    assert len(indexed)==508
    changed_by_cwe=Counter(); gains={k:Counter() for k in ('reads','updates','guards')}
    lifecycle=Counter()
    for idx in range(254):
        a,b=indexed[idx,'control'],indexed[idx,'display']
        changed_by_cwe[a['cwe']]+=a['request']!=b['request']
        for kind in gains:
            assert [(f['line'],f['expression']) for f in a[kind]]==[(f['line'],f['expression']) for f in b[kind]]
            for af,bf in zip(a[kind],b[kind]):
                ap,bp=af['survival']['dep_exact'],bf['survival']['dep_exact']
                gains[kind]['gained']+=not ap and bp
                gains[kind]['lost']+=ap and not bp
                gains[kind]['retained']+=ap and bp
        # These are unchanged serializer labels, not complete lifecycle proofs.
        for tag in ('FREE','ALLOC'):
            av,bv=f'[{tag}]' in a['dep'],f'[{tag}]' in b['dep']
            lifecycle[f'{tag}_control_rows']+=av; lifecycle[f'{tag}_candidate_rows']+=bv
            lifecycle[f'{tag}_gained_rows']+=not av and bv; lifecycle[f'{tag}_lost_rows']+=av and not bv
    samples={s['idx']:s for s in manifest['samples']}
    executions=Counter()
    characters={p:dict(message_content_chars=sum(len(m.get('content') or '') for r in rows if r['profile']==p for m in r['request']['messages']),
                       dep_chars=sum(len(r['dep']) for r in rows if r['profile']==p)) for p in ('control','display')}
    shard_details=[]
    for shard in sorted(p for p in run.iterdir() if p.is_dir() and (p/'status.json').exists()):
        own=[json.loads(line) for line in (shard/'rows.jsonl').read_text(encoding='utf8').splitlines()]
        status=read(shard/'status.json')
        assert not status['errors'] and not status['blocked_external_attempts'] and len(own)==status['rows']
        # Each successful worker caches exactly one actual mock pipeline per
        # (source hash, CPG hash); identical-row requests are copied, not recalled.
        count=len({(samples[r['idx']]['source_sha256'],samples[r['idx']]['cpg_sha256']) for r in own})
        profile=own[0]['profile']; executions[profile]+=count
        shard_details.append(dict(shard=shard.name,rows=len(own),actual_mock_invocations=count))
    assert len(shard_details)==len(report['shard_exit_codes'])
    result=dict(full_rows_per_profile=254,per_row_first_request_records=508,
                actual_mock_invocations_by_profile=dict(executions),actual_mock_invocations=sum(executions.values()),
                external_model_calls=0,
                terminology='508 request records cover all rows. Actual mock invocations are counted separately per unique source/CPG key within each shard; no external model calls.',
                actual_input_changes_by_cwe=dict(changed_by_cwe),complete_DEP_expression_transitions={k:dict(v) for k,v in gains.items()},
                lifecycle_label_observations=dict(lifecycle),shards=shard_details,
                input_character_totals=characters,character_count_is_not_API_token_usage=True,
                input_rows_sha256=sha(run/'rows.jsonl'),analysis_tool_sha256=sha(__file__),
                quality_evaluation=False,limitations=['Repeated equal expressions cannot distinguish occurrences.',
                    'Read/update/guard lexical presence is not same-path scope or readable-capacity proof.',
                    'FREE/ALLOC legacy labels are heuristic; their loss flags risk, not proven prediction regression.',
                    'Configured display caps stay equal; actual prompt lengths and future paid token usage may differ.'])
    path=run/'coverage_decomposition.json'
    if path.exists(): assert read(path)==result
    else: path.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf8')
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--run',required=True,type=Path)
    analyze(parser.parse_args().run)
