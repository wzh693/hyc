"""New batch identity; reuse only previously verified accounting/config helpers."""
import json
from pathlib import Path
from evaluation import run_graph_window_llm_20261011 as reference

ROOT=Path(__file__).resolve().parents[1]
STAGE=ROOT/'output/graph_integrity_requests_20261011'


def expected_failure(row):
    return (row.get('profile')=='display' and row.get('idx')==146
            and 'unusable_source_mapped_function_body' in (row.get('error') or ''))


def normalized_hashes(groups):
    result={}
    for arm,entries in groups.items():
        normalized={name.replace('\\','/'):value for name,value in entries.items()}
        if len(normalized)!=len(entries):raise ValueError('Ambiguous source hash paths')
        result[arm]=normalized
    return result


def prepare():
    manifest,_,_,data=reference.prepare()
    stage_manifest=reference.read_json(STAGE/'manifest.json')
    report=reference.read_json(STAGE/'report.json')
    if not report['pass_engineering'] or reference.digest(STAGE/'rows.jsonl')!=report['rows_sha256']:
        raise ValueError('New full graph-integrity preflight required')
    stage_rows=[json.loads(s) for s in (STAGE/'rows.jsonl').read_text(encoding='utf8').splitlines()]
    stages={(r['idx'],r['profile']):dict(r,graph_sha256=r.get('path_graph_hash')) for r in stage_rows}
    if len(stage_rows)!=508 or len(stages)!=508:raise ValueError('Full scope missing')
    requests={k:r.get('request') for k,r in stages.items()}
    roots=stage_manifest['source_roots']
    hashes={p:{f.relative_to(Path(root)).as_posix():reference.digest(f) for f in Path(root).rglob('*.py')} for p,root in roots.items()}
    if hashes!=normalized_hashes(stage_manifest['source_hashes']):raise ValueError('Source freeze changed')
    tools=['evaluation/run_graph_integrity_llm_20261011.py','evaluation/audit_graph_integrity_llm_20261011.py',
        'evaluation/supervise_graph_integrity_llm_20261011.py','evaluation/graph_integrity_llm_manifest_20261011.py',
        'evaluation/preflight_graph_integrity_20261011.py','evaluation/audit_graph_integrity_20261011.py',
        'evaluation/test_graph_integrity_20261011.py','evaluation/test_graph_integrity_llm_20261011.py',
        'evaluation/GRAPH_INTEGRITY_LLM_PROTOCOL_20261011.md']
    manifest.update(source_roots=roots,source_hashes=hashes,
        tooling_hashes={**manifest['tooling_hashes'],**{n:reference.digest(ROOT/n) for n in tools}},
        stage_root=str(STAGE),stage_artifact_sha256={n:reference.digest(STAGE/n) for n in ('manifest.json','rows.jsonl','report.json')},
        first_request_sha256={f'{p}/{i}':reference.request_hash(r) for (i,p),r in requests.items()},
        candidate_input_changes=report['actual_request_changes'],
        precall_abstentions=[dict(idx=146,profile='display',repeat=r) for r in (1,2)],
        retained_empty_indices=[146],expected_runtime_mock_calls=1014,
        candidate='source-mapped graph quality gate + atomic dependency-group compression',
        authorization='Human approved THIS graph-construction/compression full254x2x2 batch and API fees2026-10-11',
        scope='All254 exposed SVEN rows retained including2 candidate pre-call bad-graph abstentions; not independent testing')
    return manifest,requests,stages,data
