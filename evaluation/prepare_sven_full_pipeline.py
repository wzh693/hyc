"""Generate new SVEN wrappers/validated graphs without replacing old artifacts."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--workers', type=int, default=3)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('New output directory required')
    from evaluation.build_clean_development_pilot import SETTINGS
    os.environ.update(SETTINGS)
    from graph.build_cpg import build_cpg, _dot_has_func_method, _source_fingerprint
    from sven_eval.data.wrap_slice import wrap_slice
    from linearization.source_mapping import source_line_offset
    root = Path(__file__).resolve().parents[1]
    data = json.loads((root/'sven_eval/data/sven_test.json').read_text(encoding='utf-8'))
    args.output.mkdir(parents=True)
    def worker(idx, item):
        sid = f"{idx:04d}_{Path(item['file_name']).stem}"
        directory = args.output/sid
        directory.mkdir()
        wrapped, ok, reason = wrap_slice(item['input'], item['file_name'])
        source = directory/'source.c'
        source.write_text(wrapped, encoding='utf-8')
        old = root/'sven_eval/cpg_cache'/sid
        receipt = {'idx': idx, 'sample_id': sid, 'wrapper_reason': reason, 'cache_reused': False}
        try:
            if not ok or source_line_offset(item['input'], wrapped) > len(wrapped.splitlines()):
                raise ValueError('Unverifiable source mapping')
            meta = json.loads((old/'.hgl_cpg_cache.json').read_text(encoding='utf-8'))
            dot = old/'export/export.dot'
            if meta.get('source_fingerprint') == _source_fingerprint(wrapped, str(source)) and _dot_has_func_method(str(dot)):
                shutil.copytree(old/'export', directory/'export')
                shutil.copy2(old/'.hgl_cpg_cache.json', directory/'.hgl_cpg_cache.json')
                receipt['cache_reused'] = True
            export = build_cpg(str(source), str(directory))
            if not _dot_has_func_method(str(Path(export)/'export.dot')):
                raise ValueError('No defined function body')
            receipt['wrapped_sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
        except Exception as exc:
            receipt['error'] = str(exc)
        return receipt
    rows = []
    with (args.output/'preparation.log').open('w', encoding='utf-8') as log, contextlib.redirect_stdout(log):
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            for future in as_completed([pool.submit(worker, idx, item) for idx, item in enumerate(data)]):
                row = future.result()
                rows.append(row)
                print(f"PREP {len(rows)}/{len(data)} idx={row['idx']} reused={row['cache_reused']} error={row.get('error', '')}", file=sys.__stdout__, flush=True)
    (args.output/'preparation.json').write_text(json.dumps(sorted(rows, key=lambda r:r['idx']), indent=2), encoding='utf-8')
    errors = [r for r in rows if r.get('error')]
    print(json.dumps({'samples': len(rows), 'errors': len(errors), 'reused': sum(r['cache_reused'] for r in rows), 'api_calls': 0}))
    if errors:
        raise ValueError('Preparation errors retained; repair before model evaluation')


if __name__ == '__main__':
    main()
