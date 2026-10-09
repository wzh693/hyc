"""Corrected historical tables only. Raw files preserved; zero API calls."""
import argparse
import hashlib
import json
from pathlib import Path
from evaluation.metrics import compute_metrics


def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    root=Path(__file__).resolve().parents[1]
    result={'api_calls':0,'historical_not_repaired_version':True,
            'deduplication':'Last recorded row per mode/index; duplicates are not independent samples.',
            'folds':{}}
    for fold,name in ((0,'devign_comparison/results/evaluation_results_v20_full_fold0.json'),
                      (1,'devign_comparison_fold1/results/evaluation_results.json')):
        path=root/'output'/name;blob=path.read_bytes();raw=json.loads(blob)
        rows=list({(r['mode'],r['idx']):r for r in raw}.values())
        bymode={mode:[r for r in rows if r['mode']==mode] for mode in ('direct_llm','hgl_vul')}
        common=set.intersection(*(set(r['idx'] for r in batch if r.get('prediction') in (0,1))
                                  for batch in bymode.values()))
        table={'raw_rows':len(raw),'unique_mode_index_rows':len(rows),
               'source_sha256':hashlib.sha256(blob).hexdigest(),'full_denominator':{},'success_paired':{}}
        for mode,batch in bymode.items():
            table['full_denominator'][mode]=compute_metrics([r['target'] for r in batch],
                                                            [r.get('prediction') for r in batch])
            paired=[r for r in batch if r['idx'] in common]
            table['success_paired'][mode]=compute_metrics([r['target'] for r in paired],
                                                          [r['prediction'] for r in paired])
        result['folds'][f'fold{fold}']=table
    args.output.mkdir(parents=True,exist_ok=False)
    (args.output/'history.json').write_text(json.dumps(result,indent=2),encoding='utf8')
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
