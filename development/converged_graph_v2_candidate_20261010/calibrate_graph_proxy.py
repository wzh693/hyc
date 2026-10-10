"""Whole reserved development split risk-proxy diagnostic, NEVER a flip license."""
import argparse
import contextlib
from dataclasses import asdict
import io
import json
from pathlib import Path
import socket
from unittest.mock import patch
import torch
from graph.load_graph import load_graph
from . import architecture as a
from .train_minimal_gat import ROOT, read, sha

GRID = [1., 2., 3., 4., 6., 8., 12., 16., 24., 32.]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    if args.output.exists():
        raise ValueError('Fresh diagnostic output required')
    torch.set_num_threads(2)
    model_dir=ROOT/'output/converged_minimal_gat_training_20261010'
    split=read(model_dir/'split.json')
    metadata=read(ROOT/'output/devign_development300_20261005/meta.json')
    cfg=a.Settings()
    scorer=a.SharedGATScorer(model_dir/'gat_mil.pt',model_dir/'split.json')
    args.output.mkdir(parents=True)
    identity = dict(model_sha256=scorer.model_sha256, split_sha256=sha(model_dir/'split.json'),
        policy_sha256=a.digest(dict(settings=asdict(cfg),code_sha256=sha(Path(a.__file__)))),
        diagnostic_tool_sha256=sha(Path(__file__)), grid=GRID,
        planned_rows=len(split['calibration']), scope='development', status='proxy_only')
    (args.output/'manifest.json').write_text(json.dumps(identity,indent=2),encoding='utf8')
    rows=[]
    blocked_attempts=[0]
    def blocked(*args,**kwargs):
        blocked_attempts[0]+=1
        raise RuntimeError('Offline diagnostic cannot connect externally')
    with patch.object(socket.socket,'connect',blocked),patch.object(socket,'create_connection',blocked):
        for fid in split['calibration']:
            folder=ROOT/'output/devign_development300_20261005'/fid
            row=dict(fid=fid,target=int(metadata[fid]['target']),group=split['group_membership'][fid])
            try:
                expected=split['graph_identities'][fid]
                if sha(folder/'source.c')!=expected['source_sha256'] or sha(folder/'export/export.dot')!=expected['dot_sha256']:
                    raise ValueError('Calibration source/graph drift')
                with contextlib.redirect_stdout(io.StringIO()):
                    graph=load_graph(str(folder/'export/export.dot'))
                source=(folder/'source.c').read_text(encoding='utf8')
                result=a.run(graph,source,0,scorer,lambda **kw:dict(
                    text='{"verdict":"Uncertain","action":"Stop"}',finish_reason='stop',model='offline-mock'),cfg)
                row.update(signal=result['graph_signal'],request=result['trace'][0]['request'],error=None)
            except Exception as exc:
                row.update(error=f'{type(exc).__name__}: {exc}')
            rows.append(row)
    candidates=[]
    for threshold in GRID:
        selected=[r for r in rows if not r['error'] and r['signal']['sink_anchored'] and r['signal']['score']>=threshold]
        tp=sum(r['target']==1 for r in selected); fp=len(selected)-tp
        negatives=sum(r['target']==0 for r in rows)
        candidates.append(dict(threshold=threshold,selected=len(selected),tp=tp,fp=fp,
            precision=tp/len(selected) if selected else 0.,false_positive_rate=fp/negatives if negatives else None))
    errors=sum(bool(r['error']) for r in rows)
    eligible=[r for r in candidates if not errors and r['selected']>=3 and r['precision']>=2/3 and r['false_positive_rate']<=.1]
    report=dict(**identity,rows=rows,candidates=candidates,
        proxy_threshold=min((r['threshold'] for r in eligible),default=None), errors=errors,
        calibration_groups=len({r['group'] for r in rows}),blocked_external_attempts=blocked_attempts[0],
        graph_security_net_calibrated=False, actual_llm_predictions_available=False,
        limitations='Only standalone danger-signal selectivity on every reserved development row. '
                    'No real b_pred: cannot estimate recovered FN or collateral TN flips. '
                    'status is proxy_only, deliberately rejected by the verifier. No automatic activation.')
    if a.digest(dict(settings=asdict(cfg),code_sha256=sha(Path(a.__file__))))!=identity['policy_sha256']:
        raise ValueError('Calibration source drift')
    (args.output/'report.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf8')
    print(json.dumps({k:report[k] for k in ('planned_rows','errors','proxy_threshold','graph_security_net_calibrated','status')},indent=2))


if __name__=='__main__':
    main()
