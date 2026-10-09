"""Label-independent evidence measurements on saved SVEN runs; no API calls."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import sys

CATEGORIES = {
    'guard_candidate': re.compile(r'\b(?:if|while|for|switch)\s*\('),
    'lifetime': re.compile(r'\b(?:malloc|calloc|realloc|alloca|free|kfree|kmalloc|kzalloc|kcalloc|av_malloc\w*|av_freep?)\s*\('),
    'exit': re.compile(r'\b(?:return|break|goto)\b'),
    'memory_access_candidate': re.compile(r'\[[^\]\n]+\]|->'),
}


def classify_lines(source):
    from graph.security_net import _mask_noncode
    lines = _mask_noncode(source).splitlines()
    return {name: {i+1 for i, line in enumerate(lines) if pattern.search(line)}
            for name, pattern in CATEGORIES.items()}


def src_segment(prompt):
    match = re.search(r'(?:^|\n)SRC:\n(.*?)(?:\n\n(?:DEP PATHS|SUMMARY|STATE|EXPLORATION STATE):|$)', prompt, re.S)
    if not match:
        raise ValueError('No SRC segment in saved first prompt')
    return match.group(1)


def visible_lines(source, segment):
    """Exact stripped whole-line matches; duplicated lines stay ambiguous."""
    original = source.splitlines()
    counts = Counter(line.strip() for line in original if line.strip())
    shown = {line.strip() for line in segment.splitlines() if line.strip()}
    visible = {i+1 for i, line in enumerate(original)
               if line.strip() in shown and counts[line.strip()] == 1}
    ambiguous = {i+1 for i, line in enumerate(original)
                 if line.strip() in shown and counts[line.strip()] > 1}
    return visible, ambiguous


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--code-root', type=Path, help='Verified frozen prediction-code snapshot; default current project')
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('New audit output directory required')
    root = Path(__file__).resolve().parents[1]
    code_root = args.code_root.resolve() if args.code_root else root
    manifest = json.loads((args.run/'manifest.json').read_text(encoding='utf-8'))
    for name, expected in manifest['code_hashes'].items():
        if hashlib.sha256((code_root/name).read_bytes()).hexdigest() != expected:
            raise ValueError('Prediction code differs from frozen run: '+name)
    dataset = Path(manifest['dataset'])
    if hashlib.sha256(dataset.read_bytes()).hexdigest() != manifest['dataset_sha256']:
        raise ValueError('Dataset changed')
    os.environ.update(manifest['settings'])
    sys.path.insert(0, str(code_root))
    import config
    from evaluation.evaluate_wiring_quality import effective_configuration
    effective_configuration(config, manifest['settings'])
    from graph.load_graph import load_graph
    from graph.summarize_graph import summarize_graph
    data = json.loads(dataset.read_text(encoding='utf-8'))
    saved_rows = list(map(json.loads, (args.run/'results.jsonl').read_text(encoding='utf-8').splitlines()))
    results = {(r['idx'], r['profile']): r for r in saved_rows}
    expected = {(s['idx'], p) for s in manifest['samples'] for p in ('control', 'slice_expansion')}
    if len(results) != len(saved_rows) or set(results) != expected:
        raise ValueError('Duplicate, incomplete or unexpected saved results')
    first = {}
    for call in map(json.loads, (args.run/'api_receipts.jsonl').read_text(encoding='utf-8').splitlines()):
        if not call.get('error'):
            first.setdefault((call['idx'], call['profile']), call['request']['messages'])
    args.output.mkdir(parents=True)
    def worker(sample):
        idx = sample['idx']
        code = data[idx]['input']
        dot = Path(sample['cache_path'])/'export/export.dot'
        if hashlib.sha256(dot.read_bytes()).hexdigest() != sample['cpg_sha256']:
            raise ValueError('Graph changed')
        graph = load_graph(str(dot))
        small = summarize_graph(graph, token_budget=manifest['token_budget'], source_code=code, verbose=False)
        control, candidate = results[idx, 'control'], results[idx, 'slice_expansion']
        if len(graph) != control['orig_nodes'] or len(small) != control['compressed_nodes']:
            raise ValueError('Replayed graph size differs from saved run')
        categories = classify_lines(code)
        control_src = src_segment(next(m['content'] for m in first[idx, 'control'] if m['role'] == 'user'))
        candidate_src = src_segment(next(m['content'] for m in first[idx, 'slice_expansion'] if m['role'] == 'user'))
        a, amb_a = visible_lines(code, control_src)
        b, amb_b = visible_lines(code, candidate_src)
        slice_audit = candidate['module_audit']['backward_slice']
        if not slice_audit['fallback']:
            recorded = set(slice_audit['source_lines'])
            rendered = '\n'.join(code.splitlines()[n-1] for n in sorted(recorded))
            if candidate_src.strip() != rendered.strip():
                raise ValueError('Recorded slice does not match actual model SRC')
            b, amb_b = recorded, set()
        offset = sample['source_line_offset']
        node_lines = {}
        for node, attrs in graph.nodes(data=True):
            try:
                line = int(attrs.get('line_number'))-offset
            except (TypeError, ValueError):
                continue
            if 1 <= line <= len(code.splitlines()):
                node_lines[node] = line
        mapped = set(node_lines.values())
        compressed = {line for node, line in node_lines.items() if node in small}
        facts = {name: {'source_lines': sorted(lines),
                       'absent_from_full_cpg': sorted(lines-mapped),
                       'absent_from_compressed_line_coverage': sorted((lines & mapped)-compressed),
                       'control_src_present': sorted(lines & a),
                       'candidate_src_present': sorted(lines & b),
                       'control_src_ambiguous': sorted(lines & amb_a),
                       'candidate_src_ambiguous': sorted(lines & amb_b),
                       'lost_from_candidate_src': sorted((lines & a)-b-amb_b),
                       'gained_in_candidate_src': sorted((lines & b)-a-amb_a)}
                 for name, lines in categories.items()}
        # Outcome annotation is added ONLY after evidence measurements; no rule
        # is selected/tuned by labels or by which examples flipped.
        return {'idx': idx, 'group_id': sample['group_id'], 'cwe': sample['cwe'],
                'facts': facts, 'slice_budget_omissions': slice_audit['omitted_lines'],
                'slice_fallback': slice_audit['fallback'],
                'first_messages_identical': first[idx, 'control'] == first[idx, 'slice_expansion'],
                'target': control['target'], 'control_prediction': control['prediction'],
                'candidate_prediction': candidate['prediction']}
    rows = []
    with (args.output/'execution.log').open('w', encoding='utf-8') as log, contextlib.redirect_stdout(log):
        with ThreadPoolExecutor(max_workers=4) as pool:
            for future in as_completed([pool.submit(worker, s) for s in manifest['samples']]):
                rows.append(future.result())
                if len(rows) % 25 == 0:
                    print(f'AUDIT {len(rows)}/{len(manifest["samples"])}', file=sys.__stdout__, flush=True)
    rows.sort(key=lambda r:r['idx'])
    totals = {name: {key: sum(len(r['facts'][name][key]) for r in rows)
                    for key in rows[0]['facts'][name]} for name in CATEGORIES}
    cohorts = {}
    for label, predicate in {
        'tp_to_fn': lambda r:r['target']==1 and r['control_prediction']==1 and r['candidate_prediction']==0,
        'fn_to_tp': lambda r:r['target']==1 and r['control_prediction']==0 and r['candidate_prediction']==1,
        'tn_to_fp': lambda r:r['target']==0 and r['control_prediction']==0 and r['candidate_prediction']==1,
        'fp_to_tn': lambda r:r['target']==0 and r['control_prediction']==1 and r['candidate_prediction']==0,
    }.items():
        cohort = [r for r in rows if predicate(r)]
        cohorts[label] = {'n': len(cohort), 'indices': [r['idx'] for r in cohort],
            'identical_first_messages': sum(r['first_messages_identical'] for r in cohort),
            'budget_omission_samples': sum(r['slice_budget_omissions']>0 for r in cohort),
            'lost_src_samples_by_category': {name: sum(bool(r['facts'][name]['lost_from_candidate_src']) for r in cohort)
                                            for name in CATEGORIES}}
    report = {'samples': len(rows), 'api_calls': 0, 'prediction_changes': 0,
              'verified_code_root': str(code_root),
              'category_totals': totals, 'cohorts': cohorts,
              'identical_first_messages': sum(r['first_messages_identical'] for r in rows),
              'scope': 'Post-hoc label-independent evidence audit; no causal or gain claim.',
              'limitations': ['Regex categories are candidates, not proven guards or vulnerabilities.',
                  'SRC loss does not prove loss from PATHS/STATE or prove causality.',
                  'Compressed line coverage is an optimistic proxy; it does not prove edge/semantic preservation.',
                  'Saved paths contain truncated text without node IDs; no exact TopK-node attribution is fabricated.',
                  'Rows/families correlated; same-input predictions can vary.']}
    (args.output/'rows.json').write_text(json.dumps(rows, indent=2), encoding='utf-8')
    (args.output/'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
