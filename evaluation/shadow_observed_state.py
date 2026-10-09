"""Synthetic prompt-only STATE comparison; no labels or model calls."""
import argparse
import hashlib
import json
from pathlib import Path
from unittest.mock import patch
import networkx as nx
from evaluation.audit_state_semantics import CASES
from evaluation.evaluate_wiring_quality import prediction_code_hashes
from linearization.typed_paths import build_hierarchical_context
from planning.state_memory import create_program_state
from reasoning.prompts import build_user_prompt


def shadow():
    root = Path(__file__).resolve().parents[1]
    old_path = root/'output/state_semantics_audit_20261007/report_with_controls.json'
    old = json.loads(old_path.read_text(encoding='utf-8')) if old_path.exists() else None
    historical = {row['id']:row['first_prompt'] for row in old['cases']} if old else {}
    rows = []
    for name, code, _, _, _, _ in CASES:
        arms = {}
        for enabled in (False, True):
            with patch('config.OBSERVED_STATE_CANDIDATE', enabled), patch(
                    'reasoning.reasoning_loop.query_llm_with_retry', side_effect=AssertionError('No API')):
                state = create_program_state()
                state.track_vars(code)
                context = build_hierarchical_context(nx.MultiDiGraph(), code, '', {}, [], include_state=True)
                prompt = build_user_prompt('', context, state.dump(), 1)
                arms['candidate' if enabled else 'control'] = dict(
                    user_prompt=prompt, prompt_chars=len(prompt), prompt_bytes=len(prompt.encode()),
                    state_dump=state.dump(), events=getattr(state,'events',None))
        a,b = arms['control'],arms['candidate']
        if a['user_prompt'].split('STATE:')[0] != b['user_prompt'].split('STATE:')[0]:
            raise ValueError('Non-STATE context changed')
        if b['prompt_chars'] > a['prompt_chars'] or b['prompt_bytes'] > a['prompt_bytes']:
            raise ValueError('Synthetic character/byte budget increased')
        if name in historical and a['user_prompt'] != historical[name]:
            raise ValueError('Default prompt changed relative to saved pre-implementation audit')
        rows.append(dict(id=name, **arms, baseline_saved_match=name in historical))
    return {'api_calls':0, 'cases':rows, 'baseline_saved_matches':sum(r['baseline_saved_match'] for r in rows),
            'historical_report_sha256':hashlib.sha256(old_path.read_bytes()).hexdigest() if old else None,
            'code_hashes':prediction_code_hashes(), 'default_enabled':False,
            'limitations':['Synthetic sources, not independent dataset validation.',
                'Character/UTF-8 bounds do not prove provider-token cost bounds.',
                'May-events intentionally do not resolve paths, object lifetimes or aliases.',
                'No F1/Accuracy claim. Candidate not promoted.']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args=parser.parse_args()
    report=shadow()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8') as stream:
        json.dump(report,stream,ensure_ascii=False,indent=2)
    print(json.dumps({'cases':len(report['cases']), 'baseline_saved_matches':report['baseline_saved_matches'],
                      'api_calls':0,'output':str(args.output)},ensure_ascii=False))


if __name__=='__main__':main()
