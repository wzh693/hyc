"""Full254 output-contract-only paired preflight, no model service or training."""
import argparse
import contextlib
from dataclasses import asdict
import hashlib
import io
import json
import os
from pathlib import Path
import socket
from unittest.mock import patch
import torch
from development.converged_graph_v2_candidate_20261010 import architecture as base
from development.converged_display_first_candidate_20261011 import architecture as control
from development.converged_compact_output_candidate_20261011 import architecture as candidate
from development.converged_graph_v2_candidate_20261010.audit_offline import audit
from development.converged_graph_v2_candidate_20261010.run_offline import ROOT, read, sha
from evaluation.test_graph_guided_foundation import verify_foundation
from graph.load_graph import load_graph
from linearization.source_mapping import source_line_offset


def validate_pair(left, right):
    if len(left['trace']) != 1 or len(right['trace']) != 1:
        raise ValueError('Unexpected mock step count')
    ltrace, rtrace = left['trace'][0], right['trace'][0]
    if ltrace['request']['messages'][1:] != rtrace['request']['messages'][1:]:
        raise ValueError('User evidence changed')
    if ltrace['request']['max_tokens'] != 150 or rtrace['request']['max_tokens'] != 150:
        raise ValueError('Output budget changed')
    if ltrace['request']['messages'][0]['content'] != base.SYSTEM or rtrace['request']['messages'][0]['content'] != candidate.SYSTEM:
        raise ValueError('Unexpected system prompt')
    if ltrace['evidence'] != rtrace['evidence']:
        raise ValueError('Evidence receipt changed')
    for key in left:
        if key != 'trace' and left[key] != right[key]:
            raise ValueError('Non-prompt result drift: '+key)
    if ltrace['parsed'] != rtrace['parsed'] or ltrace['response'] != rtrace['response']:
        raise ValueError('Identical mock parsed differently')
    return True


def payload_bounds(target):
    """UTF8 bytes only: no DeepSeek tokenizer is installed or fetched."""
    fixtures = {}
    for verdict in ('Vulnerable','Benign','Uncertain'):
        fixtures[verdict+'_stop'] = dict(verdict=verdict,action='Stop',reason='\\'*32)
        query = dict(verdict=verdict,action='Query',reason='\\'*32,target=target,
                     edge_types=sorted(base.DEPENDENCIES))
        if verdict == 'Vulnerable':
            query['hypothesis'] = '\\'*8
        fixtures[verdict+'_query'] = query
    encoded = {name:json.dumps(v,separators=(',',':')) for name,v in fixtures.items()}
    if any(base.decode(text)['verdict'] != fixtures[name]['verdict'] for name,text in encoded.items()):
        raise ValueError('Bounded fixture failed frozen decoder')
    return dict(max_graph_id_chars=len(target), payload_utf8_bytes={k:len(v.encode()) for k,v in encoded.items()},
                exact_model_token_count=None, limitation='Byte lengths, not a certified DeepSeek150-token guarantee')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    output = parser.parse_args().output
    if output.exists():
        raise ValueError('Fresh output required')
    if os.environ.get('PYTHONHASHSEED') != '0':
        raise ValueError('Startup PYTHONHASHSEED=0 required')
    verify_foundation()
    torch.set_num_threads(2)
    previous = ROOT/'output/converged_display_first_preflight_seed0_20261011'
    freeze = read(previous/'manifest.json')
    if not read(previous/'report.json')['pass']:
        raise ValueError('Prior full evidence audit required')
    bindings = dict(freeze['source_tool_hashes'])
    for name, expected in bindings.items():
        if sha(ROOT/name) != expected:
            raise ValueError('Frozen dependency drift')
    for path in (Path(__file__), Path(candidate.__file__),
        ROOT/'evaluation/test_compact_output_20261011.py',
        ROOT/'development/converged_compact_output_candidate_20261011/README.md'):
        bindings[str(path.relative_to(ROOT))] = sha(path)
    ref = read(ROOT/'output/sven_complete_src_eval_20261008/manifest.json')
    data = read(ref['dataset'])
    samples = sorted(ref['samples'], key=lambda r:r['idx'])
    if len(data)!=254 or len(samples)!=254 or {s['idx'] for s in samples}!=set(range(254)):
        raise ValueError('Full254 required')
    if sha(ref['dataset']) != freeze['dataset_sha256']:
        raise ValueError('Dataset drift')
    model = ROOT/'output/converged_expanded_gat_training_20261010'
    scorer = base.SharedGATScorer(model/'gat_mil.pt',model/'split.json')
    if scorer.model_sha256 != freeze['model_sha256']:
        raise ValueError('Changed model')
    manifest = dict(settings=asdict(base.Settings()), rows=254, planned_mock_requests=508,
        python_hash_seed=0, source_tool_hashes=bindings, dataset_sha256=freeze['dataset_sha256'],
        model_sha256=scorer.model_sha256, paid_api_calls=0, quality_evaluation=False,
        control='frozen display-first',candidate='compact-output-contract only')
    output.mkdir(parents=True)
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf8')
    rows, blocked_count, longest_id = {'control':[],'candidate':[]}, [0], ''
    def blocked(*args, **kwargs):
        blocked_count[0] += 1
        raise RuntimeError('Offline connection forbidden')
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(socket.socket,'connect',blocked))
        stack.enter_context(patch.object(socket,'create_connection',blocked))
        handles = {k:stack.enter_context((output/(k+'_rows.jsonl')).open('x',encoding='utf8')) for k in rows}
        for index,sample in enumerate(samples):
            graph_error = None
            try:
                source = data[sample['idx']]['input']
                dot = Path(sample['cache_path'])/'export/export.dot'
                if (sha(dot)!=sample['cpg_sha256'] or sha(sample['source_path'])!=sample['wrapped_source_sha256'] or
                    hashlib.sha256(source.encode()).hexdigest()!=sample['source_sha256']):
                    raise ValueError('Source/graph drift')
                with contextlib.redirect_stdout(io.StringIO()):
                    graph = load_graph(str(dot))
                offset = source_line_offset(source,Path(sample['source_path']).read_text(encoding='utf8'))
                scores = scorer(graph,source)
                longest_id = max([longest_id]+[str(n) for n in graph], key=len)
            except Exception as exc:
                graph_error = repr(exc)
            for arm,run in (('control',control.run),('candidate',candidate.run)):
                row = dict(idx=sample['idx'],source_sha256=sample['source_sha256'],group_id=sample['group_id'])
                calls = []
                try:
                    if graph_error:
                        raise ValueError(graph_error)
                    def invoke(**request):
                        calls.append(request)
                        return dict(text='{"verdict":"Uncertain","action":"Stop","reason":"Offline fixture"}',
                                    finish_reason='stop',model='offline-mock')
                    result = run(graph,source,offset,lambda g,s:scores,invoke)
                    if len(calls)!=1 or result['security_net']['mode']!='shadow':
                        raise ValueError('Unexpected mock/net behavior')
                    row.update(result=result,error=None)
                except Exception as exc:
                    row['error'] = repr(exc)
                row['actual_mock_requests'] = len(calls)
                rows[arm].append(row)
                handles[arm].write(json.dumps(row,ensure_ascii=False)+'\n')
                handles[arm].flush()
            if (index+1)%25==0 or index==253:
                print(f'paired {index+1}/254',flush=True)
    errors = sum(bool(r['error']) for rr in rows.values() for r in rr)
    report = dict(rows_per_arm=254,actual_mock_requests=sum(r['actual_mock_requests'] for rr in rows.values() for r in rr),
        errors=errors,blocked_external_attempts=blocked_count[0],paid_api_calls=0,audits={},
        user_evidence_equal_rows=0,output_length_fixtures=payload_bounds(longest_id))
    for arm,rr in rows.items():
        folder = output/arm
        folder.mkdir()
        (folder/'control').mkdir()
        for path,value in [('manifest.json',manifest),('report.json',{'pass':not errors and not blocked_count[0]})]:
            (folder/path).write_text(json.dumps(value,indent=2),encoding='utf8')
        for path,values in [('candidate_rows.jsonl',rr),('control/rows.jsonl',rows['control'])]:
            (folder/path).write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in values),encoding='utf8')
        if not errors and not blocked_count[0]:
            report['audits'][arm] = audit(folder)
    if not errors:
        report['user_evidence_equal_rows'] = sum(validate_pair(l['result'],r['result']) for l,r in zip(rows['control'],rows['candidate']))
        report['system_contract_changed_rows'] = sum(l['result']['trace'][0]['request']['messages'][0]!=r['result']['trace'][0]['request']['messages'][0] for l,r in zip(rows['control'],rows['candidate']))
    if any(sha(ROOT/name)!=expected for name,expected in bindings.items()):
        raise ValueError('Source/model freeze drift')
    verify_foundation()
    report['pass'] = (not errors and not blocked_count[0] and report['actual_mock_requests']==508 and
        report['user_evidence_equal_rows']==254 and len(report['audits'])==2)
    (output/'report.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps(report,indent=2),flush=True)
    if not report['pass']:
        raise SystemExit('Failed engineering gate; retain all rows')


if __name__ == '__main__':
    main()
