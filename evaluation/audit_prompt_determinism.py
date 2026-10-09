"""Check real pipeline prompts under independent Python hash seeds, without API calls."""
import contextlib
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def worker():
    from modes.compare_devign import _run_hgl_pipeline
    loop = importlib.import_module('reasoning.reasoning_loop')
    api = importlib.import_module('reasoning.llm_api')
    def blocked(*args, **kwargs):
        raise RuntimeError('model API disabled during offline prompt audit')
    api.create_client = blocked
    api.query_llm = blocked
    from reasoning.prompts import get_system_prompt
    data = json.loads((ROOT / 'sven_eval/data/sven_test.json').read_text(encoding='utf8'))
    result = []
    indices = [int(x) for x in os.environ.get('AUDIT_PROMPT_INDICES', '0,9,46,100,144,151,237').split(',')]
    for idx in indices:
        prompts = []
        def capture(prompt, client=None):
            prompts.append(prompt)
            return 'HYPOTHESIS: no vulnerability detected\nACTION: {"action":"Stop"}', 0
        loop.query_llm_with_retry = capture
        row = data[idx]
        sample_id = f"{idx:04d}_{Path(row['file_name']).stem}"
        with contextlib.redirect_stdout(io.StringIO()):
            _run_hgl_pipeline(str(ROOT / 'sven_eval/src_c' / f"{idx:04d}_{row['file_name']}"),
                              row['input'], sample_id, str(ROOT / 'sven_eval/cpg_cache' / sample_id),
                              None, 4096)
        if not prompts:
            raise RuntimeError('prompt interception failed')
        result.append({'idx': idx, 'prompt_sha256': hashlib.sha256(
            json.dumps([[get_system_prompt(p), p] for p in prompts], ensure_ascii=False).encode('utf8')).hexdigest()})
    print(json.dumps(result))


def main():
    runs = []
    for seed in ('0', '1', '2'):
        env = dict(os.environ, PYTHONHASHSEED=seed, USE_LEARNED_NODE_IMPORTANCE='0',
                   USE_LEARNED_SUMMARIZE='0', USE_LEARNED_PATH_RANK='0',
                   SOURCE_SLICE_ASSIGNMENT_FIX='0', USE_LLM_ARBITRATION='0')
        child = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--worker'],
                               cwd=ROOT, env=env, capture_output=True, text=True, encoding='utf8',
                               errors='replace', check=True)
        runs.append({'seed': seed, 'prompts': json.loads(child.stdout)})
    changed = [r['idx'] for j, r in enumerate(runs[0]['prompts'])
               if len({run['prompts'][j]['prompt_sha256'] for run in runs}) != 1]
    report = {'protocol': 'mocked first-step verdict; real cached graph/retrieval/context',
              'api_calls': 0, 'changed_indices': changed, 'runs': runs}
    (ROOT / 'sven_eval/prompt_determinism_audit.json').write_text(
        json.dumps(report, indent=2), encoding='utf8')
    print(json.dumps({'api_calls': 0, 'n_samples': len(runs[0]['prompts']), 'seeds': 3, 'changed_indices': changed}))


if __name__ == '__main__':
    worker() if '--worker' in sys.argv else main()
