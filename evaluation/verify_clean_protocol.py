"""Validate and fingerprint local disjoint manifests without exposing test code."""
import argparse
import hashlib
import json
from pathlib import Path


def validate(splits):
    names = sorted(splits)
    for name, rows in splits.items():
        if len({r['idx'] for r in rows}) != len(rows): raise ValueError('duplicate index')
        if any('target' in r or 'input' in r or 'func' in r for r in rows):
            raise ValueError('index manifests must not contain code or labels')
    for i, a in enumerate(names):
        for b in names[i+1:]:
            for key in ('idx','source_sha256','group_id'):
                if {r[key] for r in splits[a]} & {r[key] for r in splits[b]}:
                    raise ValueError(f'overlap {a}/{b}: {key}')
            commits = lambda rows:{(r['project'],r['commit_id']) for r in rows if r['commit_id']}
            if commits(splits[a]) & commits(splits[b]): raise ValueError('commit overlap')


def validate_dataset(splits, blob, expected_sha):
    if hashlib.sha256(blob).hexdigest() != expected_sha:
        raise ValueError('dataset version mismatch')
    from evaluation.build_clean_protocol import code_hash
    raw = json.loads(blob)
    for rows in splits.values():
        for row in rows:
            idx = row['idx']
            if not isinstance(idx,int) or not 0 <= idx < len(raw):
                raise ValueError('manifest index out of range')
            source = raw[idx]
            if (code_hash(source['func']) != row['source_sha256']
                    or source.get('project','') != row['project']
                    or source.get('commit_id','') != row['commit_id']):
                raise ValueError('manifest source or provenance mismatch')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('directory', type=Path)
    p.add_argument('--dataset',type=Path)
    a = p.parse_args()
    names = ('development','validation','locked_test')
    splits = {name:json.loads((a.directory/f'{name}.json').read_text(encoding='utf8')) for name in names}
    validate(splits)
    audit = json.loads((a.directory/'audit.json').read_text(encoding='utf8'))
    if a.dataset is None:
        from config import DEVIGN_JSON_PATH
        a.dataset = Path(DEVIGN_JSON_PATH)
    validate_dataset(splits,a.dataset.read_bytes(),audit['dataset_sha256'])
    for name in names:
        if len(splits[name]) != audit['split_counts'][name]['rows']: raise ValueError('audit count mismatch')
    root = Path(__file__).resolve().parents[1]
    historical = set()
    for entry in audit['artifacts']:
        payload = json.loads((root/entry['path']).read_text(encoding='utf8'))
        samples = payload.get('samples', list(payload.values())) if isinstance(payload,dict) else payload
        if not isinstance(samples,list):raise ValueError('unsupported exposure inventory schema')
        historical.update(s['idx'] for s in samples if isinstance(s,dict) and isinstance(s.get('idx'),int))
    all_indices = {r['idx'] for rows in splits.values() for r in rows}
    if historical & all_indices: raise ValueError('historical index exposure found')
    result = {'status':'pass', 'api_calls':0, 'historical_index_overlap':0,
        'dataset_source_and_provenance_verified':True,
        'cross_split_idx_code_commit_group_overlap':0,
        'manifest_sha256':{name:hashlib.sha256((a.directory/f'{name}.json').read_bytes()).hexdigest()
                           for name in names},
        'limitations':audit['limitations'],
        'release_gate':('Do not evaluate locked_test until code/configuration and primary analysis are frozen; '
                        'only the documented token-clone definition is checked; unrecorded historical exposure remains uncertain.'
                        if audit.get('clone_method') else
                        'Do not evaluate locked_test until code/configuration and primary analysis are frozen; near-clone checks remain outstanding.')}
    (a.directory/'verification.json').write_text(json.dumps(result,indent=2),encoding='utf8')
    print(json.dumps(result,indent=2))


if __name__ == '__main__': main()
