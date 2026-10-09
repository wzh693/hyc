"""Independent full-scope check, reconstruct graph provenance, not candidate policy."""
import argparse
import contextlib
import io
import json
import os
import re
from pathlib import Path
import sys
from evaluation.preflight_graph_display import read, sha, graph_hash

DEPENDENCE={'DFG','REACHING_DEF','CDG','CONTROL_DEPENDENCE'}


def verify(run):
    manifest,report=read(run/'manifest.json'),read(run/'report.json')
    rows=[json.loads(s) for s in (run/'rows.jsonl').read_text(encoding='utf8').splitlines()]
    indexed={(r['idx'],r['profile']):r for r in rows}
    assert len(rows)==508 and set(indexed)=={(i,p) for i in range(254) for p in ('control','display')}
    assert len(manifest['samples'])==254 and {s['idx'] for s in manifest['samples']}==set(range(254))
    assert sha(manifest['dataset'])==manifest['dataset_sha256'] and sha(run/'rows.jsonl')==report['rows_sha256']
    root=Path(__file__).resolve().parents[1]
    for p, hashes in manifest['source_hashes'].items():
        for name,expected in hashes.items():
            assert sha(Path(manifest['source_roots'][p])/name)==expected
            assert sha(run/(p+'_snapshot')/name)==expected
    for name,expected in manifest['tooling_hashes'].items():
        assert sha(root/name)==sha(run/'tooling_snapshot'/name)==expected
    os.environ.update(manifest['settings'])
    sys.path.insert(0,str(run/'control_snapshot'))
    from graph.load_graph import load_graph
    from graph.summarize_graph import summarize_graph
    data=read(manifest['dataset']); samples={s['idx']:s for s in manifest['samples']}
    saved={}
    for line in (root/'output/sven_complete_src_eval_20261008/api_receipts.jsonl').read_text(encoding='utf8').splitlines():
        call=json.loads(line)
        if call['profile']=='control': saved.setdefault((call['idx'],call['repeat']),call['request'])
    cache={}; changed=0; included=0; witnesses=0; omissions=0; long_nodes=0; upstream_updates=0; ast_updates=0
    for idx in range(254):
        a,b=indexed[idx,'control'],indexed[idx,'display']; sample=samples[idx]
        assert not a.get('error') and not b.get('error')
        assert all(a['request']==saved[idx,rep] for rep in (1,2))
        for name in ('topk','graph_hash','compressed_hash','path_graph_hash','candidate_paths_sha256','src','display_chars','display_slots'):
            assert a[name]==b[name],(idx,name)
        stripped=[]
        for row in (a,b):
            request=json.loads(json.dumps(row['request'])); text=request['messages'][1]['content']
            prefix,rest=text.split('\n\nDEP PATHS:\n',1); dep,suffix=rest.split('\n\nSTATE:',1)
            assert dep==row['dep'] and prefix[5:]==row['src'] and request['max_tokens']==150 and request['temperature']==0
            assert row['display_paths']==row['topk'][:row['display_slots']] and row['all_selected_from_candidates']
            assert all(len(s)<=row['display_chars'] and (not s or s in dep) for s in row['serialized'])
            request['messages'][1]['content']=prefix+'\n\nDEP PATHS:\n<dep>\n\nSTATE:'+suffix; stripped.append(request)
        assert stripped[0]==stripped[1]
        changed+=a['request']!=b['request']
        key=sample['source_sha256'],sample['cpg_sha256']
        if key not in cache:
            assert sha(Path(sample['cache_path'])/'export/export.dot')==sample['cpg_sha256']
            with contextlib.redirect_stdout(io.StringIO()):
                original=load_graph(str(Path(sample['cache_path'])/'export/export.dot'))
                compressed=summarize_graph(original,token_budget=4096,source_code=data[idx]['input'])
            assert graph_hash(original)==b['graph_hash'] and graph_hash(compressed)==b['compressed_hash']
            cache[key]=original if b['path_graph_hash']==b['graph_hash'] else compressed
        graph=cache[key]; assert graph_hash(graph)==b['path_graph_hash']
        receipts=b['selection_receipt'] or {}
        for path,body in zip(b['display_paths'],b['serialized']):
            receipt=receipts[str(tuple(path))+':'+str(b['display_chars'])]
            assert receipt['body']==body and receipt['path']==path and len(body)<=receipt['budget']
            omissions+=len(receipt['omitted'])
            for entry in receipt['included']:
                nid=entry['node']; assert entry['code']==(graph.nodes[nid].get('code') or '').strip()
                assert entry['code'] in body
                included+=1; long_nodes+=len(entry['code'])>35
                if entry['role'].startswith('UPSTREAM') or entry['role']=='AST_BOUND_UPDATE':
                    bound=entry['role']=='AST_BOUND_UPDATE'
                    chain=receipt['witnesses'][str(nid)]; assert 1<=len(chain)<=4+int(bound)
                    assert chain[0][0]==nid and chain[-1][1]==entry['read']
                    assert any(x['node']==entry['read'] and x['role']=='READ' for x in receipt['included'])
                    for j,(u,v,k,et) in enumerate(chain):
                        assert graph.get_edge_data(u,v,k)['edge_type']==et
                        if bound and j==0:
                            assert et=='AST' and graph.nodes[v].get('node_type')=='IDENTIFIER'
                            node=graph.nodes[u]; code=node['code'].strip(); name=node.get('name','')
                            if 'Increment' in name or 'Decrement' in name:
                                lhs=code.replace('++','').replace('--','').strip()
                            else:
                                assert name.startswith('<operator>.assignment')
                                lhs=re.split(r'[+*/%&|^<>-]*=(?!=)',code,maxsplit=1)[0].strip()
                            assert re.fullmatch(r'[A-Za-z_]\w*',lhs) and lhs==graph.nodes[v]['code'].strip()
                            # Independently require one syntactic assignment owner.
                            possible=[]
                            for parent,_,key,attrs in graph.in_edges(v,keys=True,data=True):
                                pnode=graph.nodes[parent]; pn=pnode.get('name',''); pc=pnode.get('code','').strip()
                                plhs=pc.replace('++','').replace('--','').strip() if ('Increment' in pn or 'Decrement' in pn) else re.split(r'[+*/%&|^<>-]*=(?!=)',pc,maxsplit=1)[0].strip() if pn.startswith('<operator>.assignment') else None
                                if attrs.get('edge_type')=='AST' and plhs==lhs: possible.append((parent,key))
                            assert list(dict.fromkeys(possible))==[(u,k)]
                        else: assert et in DEPENDENCE
                        assert graph.nodes[u].get('node_type') not in {'METHOD','BLOCK','METHOD_RETURN','FILE'}
                        if j: assert chain[j-1][1]==u
                    witnesses+=1; upstream_updates+=entry['role']=='UPSTREAM_UPDATE'; ast_updates+=bound
                else: assert nid in path
            for entry in receipt['omitted']: assert entry['node'] in graph
    assert changed==report['actual_request_changes'] and report['selected_path_changes']==0
    assert not report['engineering_errors'] and not any(report['shard_exit_codes'])
    assert report['new_api_calls']==report['blocked_external_attempts']==0
    from evaluation.audit_graph_read_evidence import summarize
    for p in ('control','display'): assert summarize([r for r in rows if r['profile']==p])==report['summaries'][p]
    result=dict(passed=True,rows=254,mock_requests=508,changed_requests=changed,api_calls=0,
        complete_node_cards=included,long_graph_expressions=long_nodes,dependence_witnesses=witnesses,
        upstream_update_cards=upstream_updates,ast_bound_update_cards=ast_updates,omitted_node_attempts=omissions,quality_test=False,
        hashes={n:sha(run/n) for n in ('manifest.json','rows.jsonl','report.json')})
    dest=run/'verification.json'; assert not dest.exists()
    dest.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf8'); print(json.dumps(result,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--run',required=True,type=Path)
    verify(parser.parse_args().run)
