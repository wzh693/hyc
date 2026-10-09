"""Read-only independent serialized-artifact verification; no prediction imports."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
def read(path): return json.loads(Path(path).read_text(encoding='utf-8-sig'))
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def norm(text): return re.sub(r'\s+','',text).rstrip(';')


def verify(run, archived=False):
    manifest,report=read(run/'manifest.json'),read(run/'report.json')
    rows=[json.loads(line) for line in (run/'rows.jsonl').read_text(encoding='utf8').splitlines()]
    assert len(rows)==508
    indexed={(r['idx'],r['profile']):r for r in rows}
    assert len(indexed)==508 and set(indexed)=={(i,p) for i in range(254) for p in ('control','display')}
    assert len(manifest['samples'])==254 and {s['idx'] for s in manifest['samples']}==set(range(254))
    assert sha(manifest['dataset'])==manifest['dataset_sha256']
    assert sha(run/'rows.jsonl')==report['rows_sha256']
    for p,hashes in manifest['source_hashes'].items():
        source = run/'code_snapshot' if archived and p=='display' else Path(manifest['source_roots'][p])
        for name,expected in hashes.items(): assert sha(source/name)==expected
    for name,expected in manifest['tooling_hashes'].items():
        tool = run/'tooling_snapshot'/name if archived else ROOT/name
        assert sha(tool)==expected
    saved={}
    for line in (ROOT/'output/sven_complete_src_eval_20261008/api_receipts.jsonl').read_text(encoding='utf8').splitlines():
        call=json.loads(line)
        if call['profile']=='control': saved.setdefault((call['idx'],call['repeat']),call['request'])
    changed,selection_changed=0,0
    lexical={p:{kind:0 for kind in ('reads','updates','guards')} for p in ('control','display')}
    for idx in range(254):
        a,b=indexed[idx,'control'],indexed[idx,'display']
        assert not a.get('error') and not b.get('error')
        assert all(a['request']==saved[idx,rep] for rep in (1,2))
        for name in ('graph_hash','compressed_hash','path_graph_hash','candidate_paths_sha256','src','display_chars','display_slots'):
            assert a[name]==b[name]
        changed+=a['request']!=b['request']; selection_changed+=a['topk']!=b['topk']
        normalized=[]
        for row in (a,b):
            request=json.loads(json.dumps(row['request']))
            assert request['max_tokens']==150 and request['temperature']==0
            assert row['display_paths']==row['topk'][:row['display_slots']]
            assert row['all_selected_from_candidates'] and len(row['topk'])==len(a['topk'])
            text=request['messages'][1]['content']
            prefix,rest=text.split('\n\nDEP PATHS:\n',1); dep,suffix=rest.split('\n\nSTATE:',1)
            assert dep==row['dep'] and prefix[5:]==row['src']
            for body in row['serialized']:
                assert len(body)<=row['display_chars']
                assert not body or body in dep
            for kind in lexical[row['profile']]:
                for fact in row[kind]:
                    expected=norm(fact['expression']) in norm(dep)
                    assert expected==fact['survival']['dep_exact']
                    lexical[row['profile']][kind]+=expected
            request['messages'][1]['content']=prefix+'\n\nDEP PATHS:\n<dep>\n\nSTATE:'+suffix
            normalized.append(request)
        assert normalized[0]==normalized[1]
        receipt=b['selection_receipt']
        assert receipt['legacy_paths']==a['topk'] and receipt['selected_paths']==b['topk']
        assert receipt['changed']==(a['topk']!=b['topk'])
    assert changed==report['actual_request_changes'] and selection_changed==report['selected_path_changes']
    assert report['engineering_errors']==[] and not any(report['shard_exit_codes'])
    assert report['new_api_calls']==0 and report['blocked_external_attempts']==0
    from evaluation.audit_graph_read_evidence import summarize
    for p in ('control','display'): assert summarize([r for r in rows if r['profile']==p])==report['summaries'][p]
    result=dict(passed=True,rows=254,actual_mock_requests=508,historical_control_requests_checked=508,
                actual_request_changes=changed,selected_path_changes=selection_changed,
                complete_DEP_expression_counts=lexical,api_calls=0,
                artifact_sha256={n:sha(run/n) for n in ('manifest.json','rows.jsonl','report.json')},
                verifier_sha256=sha(__file__),quality_test=False)
    dest=run/'verification.json'
    if archived:
        result['archived_source_and_tools_checked']=True
    elif dest.exists():
        if read(dest)!=result: raise ValueError('Do not overwrite verification')
    else: dest.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf8')
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--run',required=True,type=Path)
    parser.add_argument('--archived',action='store_true')
    args=parser.parse_args(); verify(args.run,args.archived)
