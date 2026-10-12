"""Offline full-scope replay of the one approved batch; never calls a model."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import socket
from unittest.mock import patch
from evaluation.run_display_first_llm_20261011 import (
    prepare, load_inputs, summarize, ROOT, read, sha, base, candidate, IDENTITY, PROFILES)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True, type=Path)
    directory = parser.parse_args().run
    manifest, expected, data = prepare()
    if read(directory/'manifest.json') != manifest:
        raise ValueError('Manifest drift')
    for name, value in manifest['source_tool_hashes'].items():
        if sha(directory/'snapshot'/name) != value:
            raise ValueError('Snapshot drift')
    rows = [json.loads(line) for line in (directory/'results.jsonl').read_text(encoding='utf8').splitlines()]
    calls = [json.loads(line) for line in (directory/'api_receipts.jsonl').read_text(encoding='utf8').splitlines()]
    report = summarize(rows, calls, manifest)
    if report != read(directory/'report.json'):
        raise ValueError('Metrics/accounting mismatch')
    own, samples = defaultdict(list), {s['idx']:s for s in manifest['samples']}
    keys = {(i,p,r) for i in range(254) for p in PROFILES for r in (1,2)}
    for call in calls:
        key = call['idx'], call['profile'], call['repeat']
        if key not in keys:
            raise ValueError('Unscheduled invocation')
        own[key].append(call)
    def blocked(*a, **kw):
        raise RuntimeError('Audit external connection forbidden')
    replayed, failures = 0, 0
    with patch.object(socket.socket, 'connect', blocked), patch.object(socket, 'create_connection', blocked):
        inputs = load_inputs(manifest, data)
        for row in rows:
            key = row['idx'], row['profile'], row['repeat']
            sample = samples[row['idx']]
            if any(row[k] != sample[k] for k in IDENTITY):
                raise ValueError('Result identity mismatch')
            receipts = own[key]
            if len(receipts) > 9 or row['tokens_used'] != sum(c.get('total_tokens') or 0 for c in receipts):
                raise ValueError('Budget/accounting mismatch')
            steps = defaultdict(list)
            for call in receipts:
                if any(call[k] != row[k] for k in (*IDENTITY, 'profile', 'repeat')):
                    raise ValueError('Call identity mismatch')
                if call['step'] not in (1,2,3):
                    raise ValueError('Step outside authorization')
                steps[call['step']].append(call)
                req = call['request']
                if req.get('model') != 'deepseek-chat' or req.get('max_tokens') != 150 or req.get('temperature') != 0:
                    raise ValueError('Unauthorized request parameters')
            for step, records in steps.items():
                if [c['attempt'] for c in records] != list(range(1,len(records)+1)) or len(records) > 3:
                    raise ValueError('Attempt sequence mismatch')
                if any(c['request'] != records[0]['request'] for c in records):
                    raise ValueError('Retry input changed')
                if any(not c.get('error') for c in records[:-1]):
                    raise ValueError('Retried successful call')
            if receipts and receipts[0]['request'] != expected[row['idx'],row['profile']]:
                raise ValueError('First request freeze mismatch')
            if row['error']:
                failures += 1
                continue
            successful = [c for c in receipts if not c.get('error')]
            position = [0]
            def invoke(**raw):
                record = successful[position[0]]
                position[0] += 1
                if record['request'] != dict(raw, model='deepseek-chat', temperature=0):
                    raise ValueError('Replay request differs from actual request')
                return record['response']
            graph, code, offset, scores = inputs[row['idx']]
            run = base.run if row['profile'] == 'control' else candidate.run
            rebuilt = run(graph, code, offset, lambda g,s:scores, invoke)
            if position[0] != len(successful) or rebuilt != row['result'] or rebuilt['final_pred'] != row['prediction']:
                raise ValueError('Actual answer/trace/prediction replay differs')
            replayed += 1
            if replayed % 200 == 0:
                print(f'replayed {replayed}/1016', flush=True)
    result = dict(pass_audit=True, full_planned_results=1016, replayed_results=replayed,
        failed_results_retained=failures, actual_invocations=len(calls),
        results_sha256=sha(directory/'results.jsonl'), calls_sha256=sha(directory/'api_receipts.jsonl'),
        report_sha256=sha(directory/'report.json'), manifest_sha256=sha(directory/'manifest.json'),
        paid_api_calls_by_audit=0, graph_net='shadow', independent_publication_test=False)
    (directory/'audit.json').write_text(json.dumps(result, indent=2), encoding='utf8')
    print(json.dumps(result, indent=2), flush=True)


if __name__ == '__main__':
    main()
