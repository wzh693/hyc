"""Reconstruct historical GAT split and audit clone/commit group crossing."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import random
from config import DEVIGN_JSON_PATH,SEED
from evaluation.build_clean_protocol import Groups,code_hash


def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    blob=Path(DEVIGN_JSON_PATH).read_bytes();raw=json.loads(blob)
    protocol=Path('evaluation/protocol_clone_v2_20261005')
    audit=json.loads((protocol/'audit.json').read_text(encoding='utf8'))
    if hashlib.sha256(blob).hexdigest()!=audit['dataset_sha256']: raise ValueError('dataset mismatch')
    model_report=json.loads(Path('learning/model/gat_report.json').read_text(encoding='utf8'))
    meta=json.loads(Path('output/train_cpg/meta.json').read_text(encoding='utf8'))
    fids=sorted(fid for fid,m in meta.items() if not m.get('error') and
                (Path('output/train_cpg')/fid/(model_report['graph_cache_ver']+'.npz')).exists())
    if len(fids)!=model_report['n_functions']: raise ValueError('cannot reconstruct original available graph set')
    classes=defaultdict(list)
    for fid in fids:classes[int(meta[fid]['target'])].append(fid)
    rng=random.Random(SEED);train=[];hold=[]
    for label in (0,1):
        values=classes[label];rng.shuffle(values);n=max(1,int(len(values)*.2))
        hold.extend(values[:n]);train.extend(values[n:])
    groups=Groups(len(raw));first_hash={};first_commit={}
    for idx,row in enumerate(raw):
        h=code_hash(row['func'])
        if h in first_hash:groups.join(idx,first_hash[h])
        else:first_hash[h]=idx
        if row.get('commit_id'):
            k=(row.get('project',''),row['commit_id'])
            if k in first_commit:groups.join(idx,first_commit[k])
            else:first_commit[k]=idx
    clones=json.loads((protocol/'clone_pairs.json').read_text(encoding='utf8'))
    for pairs in clones.values():
        for x,y in pairs:groups.join(x,y)
    train_groups={groups.find(meta[f]['idx']) for f in train}
    hold_groups={groups.find(meta[f]['idx']) for f in hold}
    overlap=train_groups & hold_groups
    leaked=[meta[f]['idx'] for f in hold if groups.find(meta[f]['idx']) in overlap]
    report={'n_train':len(train),'n_holdout':len(hold),'seed':SEED,
        'crossing_connected_groups':len(overlap),'holdout_rows_in_crossing_groups':len(leaked),
        'affected_holdout_indices':sorted(leaked),
        'graph_cache_ver':model_report['graph_cache_ver'],'api_calls':0,
        'status':'Reconstructed split from current metadata/cache and documented seed, not stored original manifest.',
        'limitations':'Conservative commit/token-clone grouping; not proof of every semantic clone. '
                       'Checkpoint holdout AUC is not an independently grouped system evaluation.'}
    a.output.write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps({k:v for k,v in report.items() if k!='affected_holdout_indices'},indent=2))


if __name__=='__main__':main()
