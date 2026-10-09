"""New full254 offline experiment; reuse frozen mock pipeline, never old artifacts."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import shutil
import subprocess
import sys
from evaluation import preflight_graph_display as previous

ROOT = previous.ROOT
SOURCES = dict(previous.SOURCES, display=ROOT/'development/graph_evidence_cards_candidate_20261009/src')
OLD_SOURCES, OLD_PREPARE = previous.SOURCES, previous.prepare
TOOLS = ['evaluation/preflight_graph_evidence_cards.py', 'evaluation/verify_graph_evidence_cards.py',
         'evaluation/test_graph_evidence_cards.py', 'evaluation/GRAPH_EVIDENCE_CARDS_PROTOCOL_20261009.md']


def prepare():
    # Validate all preserved source, data and previous candidate identities too.
    previous.SOURCES = OLD_SOURCES
    try: manifest, data = OLD_PREPARE()
    finally: previous.SOURCES = SOURCES
    base = manifest['source_hashes']['control']
    hashes = {p.relative_to(SOURCES['display']).as_posix(): previous.sha(p)
              for p in SOURCES['display'].rglob('*.py')}
    normalized = {n.replace('\\','/'):h for n,h in base.items()}
    assert set(hashes) == set(normalized) | {'linearization/evidence_cards.py'}
    assert {n for n,h in normalized.items() if hashes[n]!=h} == {'linearization/typed_paths.py'}
    manifest['source_hashes']['display'] = hashes
    manifest['source_roots'] = {p:str(root) for p,root in SOURCES.items()}
    manifest['tooling_hashes'].update({n:previous.sha(ROOT/n) for n in TOOLS})
    manifest['policy'] = 'whole_graph_evidence_v1'
    return manifest, data


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--internal-profile',choices=list(SOURCES)); parser.add_argument('--internal-indices')
    args=parser.parse_args()
    if args.output.exists(): raise ValueError('Fresh output required')
    previous.SOURCES, previous.prepare = SOURCES, prepare
    if args.internal_profile:
        return previous.worker(args.output,args.internal_profile,[int(i) for i in args.internal_indices.split(',')])
    if args.internal_indices: raise ValueError('Full scope only')
    manifest,_=prepare(); args.output.mkdir(parents=True)
    (args.output/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf8')
    for profile, root in SOURCES.items():
        for name in manifest['source_hashes'][profile]:
            target=args.output/(profile+'_snapshot')/name
            target.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(root/name,target)
    for name in manifest['tooling_hashes']:
        target=args.output/'tooling_snapshot'/name
        target.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(ROOT/name,target)
    jobs=[(p,i,list(range(254))[i::6]) for p in SOURCES for i in range(6)]
    def launch(job):
        p,i,indices=job
        result=subprocess.run([sys.executable,'-B','-m','evaluation.preflight_graph_evidence_cards',
            '--output',str((args.output/f'{p}_{i:02d}').resolve()),'--internal-profile',p,
            '--internal-indices',','.join(map(str,indices))],cwd=ROOT,capture_output=True,text=True,encoding='utf8',errors='replace')
        (args.output/f'{p}_{i:02d}.log').write_text(result.stdout+'\n'+result.stderr,encoding='utf8')
        print(f'OFFLINE shard {p}/{i} exit={result.returncode}',flush=True)
        return result.returncode
    with ThreadPoolExecutor(max_workers=6) as pool: statuses=list(pool.map(launch,jobs))
    rows=[]
    for p,i,_ in jobs:
        path=args.output/f'{p}_{i:02d}'/'rows.jsonl'
        if path.exists(): rows.extend(json.loads(s) for s in path.read_text(encoding='utf8').splitlines())
    assert len(rows)==508 and len({(r['idx'],r['profile']) for r in rows})==508
    rows.sort(key=lambda r:(r['idx'],r['profile']))
    (args.output/'rows.jsonl').write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in rows),encoding='utf8')
    report=previous.aggregate(rows)
    report['limitations']=['Whole graph code fields are not necessarily complete source expressions.',
        'Graph and incoming dependence can omit updates; bounded budgets cannot show all facts.',
        'Lexical coverage is not model quality, readable capacity, execution order or dominance.',
        'No paid authorization, default activation, independent test or GitHub publication.']
    report.update(shard_exit_codes=statuses,rows_sha256=previous.sha(args.output/'rows.jsonl'),
        blocked_external_attempts=sum(previous.read(args.output/f'{p}_{i:02d}'/'status.json')['blocked_external_attempts'] for p,i,_ in jobs))
    # Ranking must remain exactly the foundation's, not the rejected display v2.
    assert report['selected_path_changes']==0
    (args.output/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf8')
    assert prepare()[0]==manifest
    print(json.dumps({k:report[k] for k in ('rows','mock_requests','actual_request_changes','engineering_errors','new_api_calls')}),flush=True)
    if any(statuses) or report['engineering_errors'] or report['blocked_external_attempts']: raise SystemExit('Failed; preserve artifacts')


if __name__=='__main__': main()
