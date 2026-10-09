"""Build paired evidence snapshots with API calls explicitly blocked."""
import contextlib
import importlib
import io
import json
from pathlib import Path
from unittest.mock import patch

from modes.compare_devign import _run_hgl_pipeline


def main():
    root = Path(__file__).resolve().parents[1]
    original = root/'sven_eval/output_compact_verdict_control/sven_results.jsonl'
    rows = [json.loads(line) for line in original.read_text(encoding='utf8').splitlines() if line.strip()]
    data = json.loads((root/'sven_eval/data/sven_test.json').read_text(encoding='utf8'))
    loop = importlib.import_module('reasoning.reasoning_loop')
    api = importlib.import_module('reasoning.llm_api')
    def blocked(*args, **kwargs):
        raise RuntimeError('real model calls forbidden during evidence preparation')
    changes = []
    output = root/'sven_eval/focused_anchor_prompt_pairs.jsonl'
    with output.open('x', encoding='utf8') as out, \
            patch.object(api, 'create_client', blocked), patch.object(api, 'query_llm', blocked), \
            patch('config.FOCUSED_GRAPH_ANCHORS', True):
        for row in rows:
            idx = row['idx']
            prompts = []
            def capture(prompt, client=None):
                prompts.append(prompt)
                return 'HYPOTHESIS: no vulnerability detected\nACTION: {"action":"Stop"}', 0
            sample = data[idx]
            sid = f"{idx:04d}_{Path(sample['file_name']).stem}"
            with patch.object(loop, 'query_llm_with_retry', capture), contextlib.redirect_stdout(io.StringIO()):
                _run_hgl_pipeline(str(root/'sven_eval/src_c'/f"{idx:04d}_{sample['file_name']}"),
                    sample['input'], sid, str(root/'sven_eval/cpg_cache'/sid), None, 4096)
            if len(prompts) != 1:
                raise RuntimeError('first-pass interception failed')
            prior = row['arbitrate']['reasoning_trace'][0]['user_prompt']
            row['experimental_user_prompt'] = prompts[0]
            if prior != prompts[0]:
                changes.append(idx)
            out.write(json.dumps(row, ensure_ascii=False)+'\n')
            out.flush()
            print(f'{idx}: changed={prior != prompts[0]}', flush=True)
    print(json.dumps({'api_calls':0, 'changed_indices':changes}))


if __name__ == '__main__':
    main()
