"""Transform frozen SRC only; retain all other input and graph selection."""
import argparse
import contextlib
import io
import json
from pathlib import Path
from evaluation.build_external_prompt_snapshot import ROOT
from graph.load_graph import load_graph_from_dot
from linearization.evidence_windows import source_windows


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--pilot',type=Path)
    a = p.parse_args()
    folder = a.pilot or ROOT/'sven_eval/external_type_check'
    rows = [json.loads(s) for s in (folder/'prompts.jsonl').read_text(encoding='utf8').splitlines()]
    sources = json.loads((folder/'sources.json').read_text(encoding='utf8'))
    cache_root = folder if a.pilot else ROOT/'output/devign_calib_v21'
    meta = {m['idx']:m for m in json.loads((cache_root/'metadata.json').read_text(encoding='utf8'))['samples']}
    a.output.mkdir(parents=True,exist_ok=False)
    for row in rows:
        source = sources[str(row['idx'])]['input']
        path = cache_root/'cpg'/meta[row['idx']]['sample_id']/'export/export.dot'
        with contextlib.redirect_stdout(io.StringIO()): graph = load_graph_from_dot(str(path))
        prompt = row['arbitrate']['reasoning_trace'][0]['user_prompt']
        prefix, tail = prompt.split('\n\nDEP PATHS:',1)
        old_src = prefix.removeprefix('SRC:\n')
        # Isolate source representation: no changes to ranking, labels or STATE.
        # No retrieved-node bonus, because frozen traces lack node IDs.
        new_src = source_windows(source,graph,[],len(old_src)) or old_src
        row['experimental_user_prompt'] = 'SRC:\n'+new_src+'\n\nDEP PATHS:'+tail
    with (a.output/'prompts.jsonl').open('w',encoding='utf8') as out:
        for row in rows: out.write(json.dumps(row,ensure_ascii=False)+'\n')
    changed=sum(r['experimental_user_prompt']!=r['arbitrate']['reasoning_trace'][0]['user_prompt'] for r in rows)
    if not changed: raise ValueError('No changed evidence; stop before model calls')
    (a.output/'protocol.json').write_text(json.dumps({'samples':len(rows), 'api_calls':0,
        'changed_inputs':changed,'fallback_unchanged_inputs':len(rows)-changed,
        'change':'SRC only; same character budget; full cached graph operations; local contiguous windows',
        'limitations':'Not PDG slicing. Character budget does not guarantee equal token count. '
                       'Disjoint windows are excerpts, not executable code. No retrieved-node bonus.'},indent=2),encoding='utf8')
    print('Prepared 30 frozen source-window pairs; zero model calls')


if __name__ == '__main__': main()
