"""Audit existing frozen GAT on development pilot. No fitting or model calls."""
import argparse
import contextlib
import hashlib
import io
import json
from pathlib import Path
import torch
from graph.load_graph import load_graph_from_dot
from learning.gat_model import GATMIL,graph_to_arrays
from learning.features import NODE_FEATURE_NAMES
from evaluation.calibrate_security_net import metrics


def main():
    p=argparse.ArgumentParser();p.add_argument('pilot',type=Path)
    p.add_argument('--model-dir',type=Path,default=Path('learning/model'))
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    checkpoint_path=a.model_dir/'gat_mil.pt'
    calibration_path=a.model_dir/'gat_calibration.json'
    checkpoint=torch.load(checkpoint_path,map_location='cpu',weights_only=True)
    if list(checkpoint.get('feature_names',[]))!=list(NODE_FEATURE_NAMES):
        raise ValueError('checkpoint schema mismatch')
    config=dict(checkpoint['config'])
    if 'edge_types' in config:config['n_edge_types']=config.pop('edge_types')
    model=GATMIL(**config);model.load_state_dict(checkpoint['state_dict']);model.eval()
    calibration=json.loads(calibration_path.read_text(encoding='utf8'))
    model_sha=hashlib.sha256(checkpoint_path.read_bytes()).hexdigest()
    is_bound=calibration.get('model_sha256')==model_sha
    if a.model_dir != Path('learning/model'):
        if not is_bound:raise ValueError('candidate calibration checkpoint binding mismatch')
        split_sha=hashlib.sha256((a.model_dir/'split.json').read_bytes()).hexdigest()
        if calibration.get('split_manifest_sha256')!=split_sha or checkpoint.get('split_manifest_sha256')!=split_sha:
            raise ValueError('candidate split binding mismatch')
    chosen=calibration.get('chosen')
    threshold=float(chosen['threshold']) if chosen else None
    metadata=json.loads((a.pilot/'metadata.json').read_text(encoding='utf8'))['samples']
    sources=json.loads((a.pilot/'sources.json').read_text(encoding='utf8'))
    baseline={r['idx']:r for r in map(json.loads,(a.pilot/'window_pairs/results.jsonl').read_text(encoding='utf8').splitlines())
              if r['variant']=='control'}
    a.output.mkdir(parents=True,exist_ok=False)
    records=[]
    torch.set_num_threads(2)
    for meta in metadata:
        with contextlib.redirect_stdout(io.StringIO()):
            graph=load_graph_from_dot(str(a.pilot/'cpg'/meta['sample_id']/'export/export.dot'))
        arrays=graph_to_arrays(graph,sources[str(meta['idx'])]['input'])
        with torch.no_grad():
            logit,attention=model(*(torch.from_numpy(arrays[k]) for k in
                ('x','tok_flat','tok_offsets','edge_index','edge_type')))
        prob=torch.sigmoid(logit).item()
        entropy=-(attention*attention.clamp_min(1e-9).log()).sum().item()
        records.append({'idx':meta['idx'],'target':meta['target'],
            'probability':prob,'gat_prediction':int(prob>=.5),
            'baseline_prediction':baseline[meta['idx']]['prediction'],
            'backstop_prediction':max(baseline[meta['idx']]['prediction'],int(threshold is not None and prob>=threshold)),
            'normalized_attention_entropy':entropy/__import__('math').log(len(attention)) if len(attention)>1 else 0,
            'max_attention':attention.max().item()})
        print(f"GAT audited {len(records)}/{len(metadata)}",flush=True)
    report={'api_calls':0,'scope':'existing checkpoint on development pilot; no retraining or threshold sweep',
        'checkpoint_sha256':model_sha,'calibration_checkpoint_bound':is_bound,
        'calibration_sha256':hashlib.sha256(calibration_path.read_bytes()).hexdigest(),
        'frozen_backstop_threshold':threshold,'standalone_threshold':.5,
        'baseline':metrics(records,[r['baseline_prediction'] for r in records]),
        'gat_standalone':metrics(records,[r['gat_prediction'] for r in records]),
        'gat_backstop':metrics(records,[r['backstop_prediction'] for r in records]),
        'limitations':('Legacy calibration pairing unproven. ' if not is_bound else '')+
                       'Exploratory already-exposed development audit only, no automatic activation.',
        'records':records}
    (a.output/'report.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps({k:v for k,v in report.items() if k!='records'},indent=2))


if __name__=='__main__':main()
