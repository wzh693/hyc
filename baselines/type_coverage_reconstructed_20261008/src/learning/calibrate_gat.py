"""Calibrate a candidate on reserved groups, not epoch-selection data."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import torch
from learning.features import NODE_FEATURE_NAMES
from learning.gat_model import GATMIL
from learning.train_gat import CACHE_DIR, DEVICE, GRAPH_CACHE_VER, load_cache_sources, _to_tensors


def validate_split(split):
    partitions = [split.get(key, []) for key in ('train','holdout','calibration')]
    if not all(partitions):
        raise ValueError('Explicit nonempty train, selection and calibration splits required')
    groups = split['group_membership']
    sets = [{groups[fid] for fid in part} for part in partitions]
    if any(sets[i] & sets[j] for i in range(3) for j in range(i)):
        raise ValueError('Cross-partition group leakage')


def choose_threshold(scored):
    positives = sum(target == 1 for _,target,_ in scored)
    if not positives or not any(target == 0 for _,target,_ in scored):
        raise ValueError('Calibration requires both classes')
    rows = []
    for integer in range(50,100,5):
        selected = [(p,y,f) for p,y,f in scored if p >= integer/100]
        tp = sum(y == 1 for _,y,_ in selected)
        fp = sum(y == 0 for _,y,_ in selected)
        rows.append(dict(threshold=integer/100,selected=len(selected),tp=tp,fp=fp,
                         precision=tp/len(selected) if selected else 0.,recall=tp/positives))
    eligible = [r for r in rows if r['selected'] >= 3 and r['precision'] >= 2/3]
    return (min(eligible,key=lambda r:r['threshold']) if eligible else None),rows


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--model-dir',required=True)
    args=parser.parse_args()
    directory=Path(args.model_dir)
    output=directory/'gat_calibration.json'
    if output.exists():
        raise FileExistsError('Refusing to overwrite calibration receipt')
    split_bytes=(directory/'split.json').read_bytes()
    split=json.loads(split_bytes); validate_split(split)
    checkpoint_path=directory/'gat_mil.pt'
    checkpoint=torch.load(checkpoint_path,map_location=DEVICE,weights_only=True)
    split_hash=hashlib.sha256(split_bytes).hexdigest()
    if checkpoint.get('split_manifest_sha256') != split_hash:
        raise ValueError('Checkpoint not bound to this split manifest')
    if checkpoint.get('feature_names') != NODE_FEATURE_NAMES:
        raise ValueError('Feature schema mismatch')
    if checkpoint.get('graph_cache_ver') != GRAPH_CACHE_VER:
        raise ValueError('Graph cache version mismatch')
    sources=split.get('graph_cache_sources')
    if sources:
        for source in sources:
            digest=hashlib.sha256((Path(source['directory'])/'meta.json').read_bytes()).hexdigest()
            if digest!=source['metadata_sha256']:raise ValueError('Graph cache metadata changed since training')
    _,graphs,_=load_cache_sources([s['directory'] for s in sources] if sources else [CACHE_DIR])
    model=GATMIL(**checkpoint['config']).to(DEVICE)
    model.load_state_dict(checkpoint['state_dict']);model.eval()
    scored=[]
    with torch.no_grad():
        for fid in split['calibration']:
            graph=graphs[fid]
            logit,_=model(*_to_tensors(graph,DEVICE))
            scored.append((torch.sigmoid(logit).item(),graph['target'],fid))
    chosen,rows=choose_threshold(scored)
    from evaluation.calibrate_security_net import metrics
    from sklearn.metrics import roc_auc_score
    labels=[{'target':y} for _,y,_ in scored]
    report={'n_calibration':len(scored),'chosen':chosen,'candidates':rows,
            'scores':scored,'model_sha256':hashlib.sha256(checkpoint_path.read_bytes()).hexdigest(),
            'split_manifest_sha256':split_hash,'graph_cache_ver':GRAPH_CACHE_VER,
            'policy':'Frozen grid .50:.05:.95; >=3 selected; precision >=2/3; development only',
            'calibration_auc':float(roc_auc_score([y for _,y,_ in scored],[p for p,_,_ in scored])),
            'standalone_fixed_05':metrics(labels,[int(p>=.5) for p,_,_ in scored]),
            'always_positive':metrics(labels,[1]*len(scored)),
            'always_negative':metrics(labels,[0]*len(scored)),
            'calibration_groups':len({split['group_membership'][fid] for _,_,fid in scored}),
            'selected_groups':len({split['group_membership'][fid] for p,_,fid in scored if chosen and p>=chosen['threshold']}),
            'limitations':'Threshold calibration is development, not independent system F1/Accuracy. '
                          'Few selected groups can yield unstable precision; no automatic activation.'}
    with output.open('x',encoding='utf8') as handle:
        json.dump(report,handle,ensure_ascii=False,indent=2)
    print(json.dumps({k:v for k,v in report.items() if k!='scores'},ensure_ascii=False,indent=2))


if __name__=='__main__':main()
