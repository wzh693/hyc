"""Reuse the fixed code-only clone/commit closure for internal model selection."""
import hashlib
import json
from pathlib import Path
from evaluation.build_clean_protocol import Groups,code_hash


def grouped_split(meta,fids,dataset_path,protocol_dir,seed):
    blob=Path(dataset_path).read_bytes()
    audit=json.loads((Path(protocol_dir)/'audit.json').read_text(encoding='utf8'))
    if hashlib.sha256(blob).hexdigest()!=audit['dataset_sha256']:
        raise ValueError('grouping protocol dataset mismatch')
    raw=json.loads(blob);groups=Groups(len(raw));sources={};commits={}
    for idx,row in enumerate(raw):
        h=code_hash(row['func'])
        if h in sources:groups.join(idx,sources[h])
        else:sources[h]=idx
        if row.get('commit_id'):
            key=(row.get('project',''),row['commit_id'])
            if key in commits:groups.join(idx,commits[key])
            else:commits[key]=idx
    clones=json.loads((Path(protocol_dir)/'clone_pairs.json').read_text(encoding='utf8'))
    for pairs in clones.values():
        for x,y in pairs:groups.join(x,y)
    membership={}
    for fid in sorted(fids):
        idx=meta[fid]['idx']
        if not 0<=idx<len(raw) or int(meta[fid]['target'])!=int(raw[idx]['target']):
            raise ValueError('training metadata mismatch')
        row=raw[idx];info=meta[fid]
        if ('source_sha256' in info and info['source_sha256']!=code_hash(row['func'])):
            raise ValueError('training normalized source mismatch')
        if ('source_raw_sha256' in info and info['source_raw_sha256']!=hashlib.sha256(row['func'].encode()).hexdigest()):
            raise ValueError('training raw source mismatch')
        for key in ('project','commit_id'):
            if key in info and info[key]!=row.get(key,''):
                raise ValueError('training provenance mismatch')
        membership[fid]=groups.find(idx)
    train,hold=partition_groups(membership,seed)
    return train,hold,membership


def partition_groups(membership,seed):
    train,hold=[],[]
    for fid,group in sorted(membership.items()):
        value=int(hashlib.sha256(f'{seed}:{group}'.encode()).hexdigest()[:16],16)/2**64
        (hold if value<.2 else train).append(fid)
    return train,hold


def split_holdout(membership, holdout, seed):
    """Separate epoch selection from threshold calibration without label tuning."""
    selection, calibration = [], []
    for fid in sorted(holdout):
        digest = hashlib.sha256(f'calibration:{seed}:{membership[fid]}'.encode()).digest()
        (selection if digest[0] < 128 else calibration).append(fid)
    return selection, calibration
