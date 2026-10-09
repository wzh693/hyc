"""Fresh paired API evaluation on unique sources changed by the slicer fix."""
import contextlib
import json
import os
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_one(task):
    import config
    config.SOURCE_SLICE_ASSIGNMENT_FIX = True
    idx, variant = task
    from linearization import typed_paths
    from evaluation.audit_sven_evidence import legacy_slicer
    from modes.compare_devign import _run_hgl_pipeline
    from reasoning.llm_api import create_client
    if variant == 'legacy':
        typed_paths._slice_source = legacy_slicer()
    data = json.loads((ROOT / 'sven_eval/data/sven_test.json').read_text(encoding='utf8'))
    row = data[idx]
    sample_id = f"{idx:04d}_{Path(row['file_name']).stem}"
    result = {'idx': idx, 'variant': variant, 'cwe': row['cwe'],
              'target': int(row['output'] == 'VULNERABLE')}
    try:
        with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink):
            pred, answer, tokens, audit = _run_hgl_pipeline(
                str(ROOT / 'sven_eval/src_c' / f"{idx:04d}_{row['file_name']}"),
                row['input'], sample_id, str(ROOT / 'sven_eval/cpg_cache' / sample_id),
                create_client(), 4096)
        result.update(prediction=pred, answer=answer, tokens=tokens, audit=audit)
    except Exception as exc:
        result.update(prediction=None, error=f'{type(exc).__name__}: {exc}')
    return result


def main():
    report = json.loads((ROOT / 'sven_eval/source_evidence_audit.json').read_text(encoding='utf8'))
    conflicts = {i for group in report['conflicts'] for i in group['indices']}
    indices = [row['idx'] for row in report['changes'] if row['idx'] not in conflicts]
    tasks = [(idx, v) for idx in indices for v in ('legacy', 'fixed')]
    output = ROOT / 'sven_eval/output_slice_pair'
    output.mkdir(exist_ok=True)
    results = []
    # Each task runs in a fresh process so the legacy monkey patch cannot leak.
    with ProcessPoolExecutor(max_workers=4, max_tasks_per_child=1) as pool:
        for row in pool.map(run_one, tasks):
            results.append(row)
            with (output / 'results.jsonl').open('a', encoding='utf8') as handle:
                handle.write(json.dumps(row, ensure_ascii=False) + '\n')
            print(f"{len(results)}/{len(tasks)} idx={row['idx']} {row['variant']} "
                  f"pred={row['prediction']} target={row['target']}", flush=True)
    from modes.compare_devign import _calc_metrics
    from scipy.stats import binomtest
    summary = {'n_unique_sources': len(indices), 'excluded_conflicting_sources': True}
    for variant in ('legacy', 'fixed'):
        rows = [r for r in results if r['variant'] == variant]
        summary[variant] = _calc_metrics(rows)
        summary[variant]['mean_tokens'] = sum(r.get('tokens', 0) for r in rows) / len(rows)
    by_key = {(r['idx'], r['variant']): r for r in results}
    improved = regressed = 0
    for idx in indices:
        left, right = by_key[idx, 'legacy'], by_key[idx, 'fixed']
        if left['prediction'] is None or right['prediction'] is None:
            continue
        a, b = left['prediction'] == left['target'], right['prediction'] == right['target']
        improved += not a and b
        regressed += a and not b
    summary.update(improved=improved, regressed=regressed,
                   mcnemar_p=binomtest(improved, improved + regressed).pvalue
                   if improved + regressed else 1.0)
    (output / 'report.json').write_text(json.dumps(summary, indent=2), encoding='utf8')
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == '__main__':
    main()
