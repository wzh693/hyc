"""Zero-call, label-blind lexical evidence survival audit of the chosen foundation.

This is NOT a C parser, guard proof, detection score or causal experiment.
Prediction code is imported in a fresh process, verified and never modified.
"""
import argparse
from collections import Counter, defaultdict
import contextlib
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT/'baselines/type_coverage_reconstructed_20261008/baseline.json'
RUN = ROOT/'output/sven_complete_src_eval_20261008'
SOURCE = ROOT/'development/type_coverage_reconstructed_20261008/src'
READ_APIS = {'strchr': (0, None), 'strrchr': (0, None), 'strlen': (0, None),
             'strnlen': (0, 1), 'memcpy': (1, 2), 'memmove': (1, 2),
             'memcmp': (0, 2), 'strcpy': (1, None), 'strncpy': (1, 2),
             'strcat': (1, None), 'strncat': (1, 2), 'strcmp': (0, None),
             'strncmp': (0, 2), 'memchr': (0, 2)}
SECOND_READ = {'memcmp', 'strcmp', 'strncmp'}
KEYWORDS = set('if else for while switch return int char void const struct unsigned signed long short static sizeof NULL true false'.split())
STAGES = ('original', 'compressed', 'path_graph', 'candidate_paths', 'topk', 'displayed_path_nodes', 'src_exact', 'dep_exact')


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def norm(text):
    return re.sub(r'\s+', '', text).rstrip(';')


def identifiers(text):
    return set(re.findall(r'\b[A-Za-z_]\w*\b', text)) - KEYWORDS - set(READ_APIS)


def masked(code):
    # Preserve coordinates/newlines while ignoring comment and literal decoys.
    pattern = r'/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    return re.sub(pattern, lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), code)


def parenthesis_end(text, start):
    depth = 0
    for pos in range(start, len(text)):
        if text[pos] == '(':
            depth += 1
        elif text[pos] == ')':
            depth -= 1
            if depth == 0:
                return pos
    return None


def arguments(code, mask, start, end):
    cuts, depth = [start+1], 0
    for pos in range(start+1, end):
        if mask[pos] in '([{': depth += 1
        elif mask[pos] in ')]}': depth -= 1
        elif mask[pos] == ',' and depth == 0: cuts.append(pos+1)
    return [code[a:b].strip().rstrip(',').strip() for a, b in zip(cuts, [c-1 for c in cuts[1:]]+[end])]


def extract_facts(code):
    """Find conservative lexical candidates, without labels or CWE metadata."""
    clean = masked(code)
    reads, assignments, guards = [], [], []
    def fact(kind, start, end, **extra):
        return dict(kind=kind, line=code.count('\n', 0, start)+1, end_line=code.count('\n', 0, end)+1,
                    expression=code[start:end], **extra)
    for match in re.finditer(r'\b('+'|'.join(sorted(READ_APIS))+r')\s*\(', clean):
        opening = clean.find('(', match.start())
        end = parenthesis_end(clean, opening)
        if end is None: continue
        args = arguments(code, clean, opening, end)
        target_index, width_index = READ_APIS[match[1]]
        for index in ([target_index, 1] if match[1] in SECOND_READ else [target_index]):
            if len(args) <= index: continue
            width = args[width_index] if width_index is not None and len(args) > width_index else None
            reads.append(fact('api_read_candidate', match.start(), end+1, api=match[1], target=args[index],
                              operand=index, width=width, offset=None, capacity_contract='unknown'))
    for match in re.finditer(r'\b([A-Za-z_]\w*(?:\s*->\s*[A-Za-z_]\w*)*)\s*\[([^\]\n]+)\]', clean):
        prefix = clean[clean.rfind('\n', 0, match.start())+1:match.start()]
        statement_prefix = re.split(r'[;{}]', prefix)[-1]
        if re.fullmatch(r'\s*(?:(?:const|int|char|float|double|unsigned|long|short|uint\d+_t|size_t)\s+)+\**\s*', statement_prefix):
            # Avoid declarations, but allow an indexed RHS following '='.
            if '=' not in prefix: continue
        suffix = clean[match.end():].lstrip()
        if re.match(r'=(?!=)', suffix): continue  # Pure destination, not a read.
        reads.append(fact('index_read_candidate', match.start(), match.end(), target=match[1].strip(),
                          offset=match[2].strip(), width='one element; byte width unknown', capacity_contract='unknown'))
    for match in re.finditer(r'(?:\breturn\s+|=(?!=)\s*)\*\s*([A-Za-z_]\w*)', clean):
        start = clean.find('*', match.start())
        reads.append(fact('deref_read_candidate', start, match.end(), target=match[1], offset=None,
                          width='one element; byte width unknown', capacity_contract='unknown'))
    for match in re.finditer(r'\b[A-Za-z_]\w*\s*(?:=(?!=)|\+=|-=|\*=|/=)\s*[^;\n]+|\b[A-Za-z_]\w*\s*(?:\+\+|--)', clean):
        assignments.append(fact('assignment_update_candidate', match.start(), match.end()))
    for match in re.finditer(r'\b(if|for|while)\s*\(', clean):
        start = clean.find('(', match.start()); end = parenthesis_end(clean, start)
        if end is not None:
            guards.append(fact('guard_condition_candidate', start+1, end, control=match[1]))
    return reads, assignments, guards


def related_facts(read_fact, assignments, guards):
    # Element-width prose is metadata, not a source expression named "width".
    width_expression = read_fact.get('width') if read_fact['kind'] == 'api_read_candidate' else None
    names = identifiers(read_fact['target']+' '+str(read_fact.get('offset') or '')+' '+str(width_expression or ''))
    related = []
    # Two lexical alias/update rounds, including later statements. No ordering or
    # dominance guarantee is inferred from this loose relatedness relation.
    for _ in range(2):
        for value in assignments:
            found = identifiers(value['expression'])
            if found & names and value not in related:
                related.append(value); names |= found
    return related, [g for g in guards if identifiers(g['expression']) & names]


def matching_nodes(graph, value, offset):
    expression = norm(value['expression'])
    found = set()
    for nid, attrs in graph.nodes(data=True):
        line = attrs.get('line_number')
        if not isinstance(line, int) or not value['line']+offset <= line <= value['end_line']+offset:
            continue
        if attrs.get('node_type') in ('BLOCK', 'METHOD', 'METHOD_RETURN', 'FILE'):
            continue  # Whole-body text does not prove an operation was parsed.
        if expression and expression in norm(attrs.get('code') or ''):
            found.add(nid)
    return found


def sections(context):
    if not context.startswith('SRC:\n') or '\n\nDEP PATHS:\n' not in context:
        raise ValueError('Unexpected frozen context format')
    src, rest = context[5:].split('\n\nDEP PATHS:\n', 1)
    dep = rest.split('\n\nSTATE:', 1)[0]
    return src, dep


def survival(value, graph, compressed, path_graph, candidates, topk, displayed, offset, src, dep):
    nodes = matching_nodes(graph, value, offset)
    def contains(paths):
        return any(nodes.intersection(path) for path in paths)
    status = dict(original=bool(nodes), compressed=bool(nodes.intersection(compressed.nodes)),
                  path_graph=bool(nodes.intersection(path_graph.nodes)), candidate_paths=contains(candidates),
                  topk=contains(topk), displayed_path_nodes=contains(displayed),
                  src_exact=norm(value['expression']) in norm(src), dep_exact=norm(value['expression']) in norm(dep))
    api_line_name_nodes = []
    if value.get('api'):
        api_line_name_nodes = sorted(nid for nid, attrs in graph.nodes(data=True)
                                    if attrs.get('node_type') == 'CALL' and attrs.get('name') == value['api']
                                    and isinstance(attrs.get('line_number'), int)
                                    and value['line']+offset <= attrs['line_number'] <= value['end_line']+offset)
    return dict(value, original_node_ids=sorted(nodes), survival=status,
                api_line_name_node_ids=api_line_name_nodes,
                api_line_name_mapping_limit='Supplement only; same-line repeated calls/operands may be ambiguous. Does not replace exact-expression mapping.')


def summarize(rows):
    scope = {}
    for label, batch in [('all', rows)]+[(c, [r for r in rows if r['cwe'] == c]) for c in sorted({r['cwe'] for r in rows})]:
        facts = [v for row in batch for v in row.get('reads', [])]
        updates = [v for row in batch for v in row.get('updates', [])]
        guards = [v for row in batch for v in row.get('guards', [])]
        summary = dict(scheduled_rows=len(batch), successful_rows=sum(not r.get('error') for r in batch),
                       failed_rows=sum(bool(r.get('error')) for r in batch), rows_with_read_candidates=sum(bool(r.get('reads')) for r in batch),
                       lexical_read_candidates=len(facts), related_update_candidates=len(updates), related_guard_candidates=len(guards),
                       src_dep_reconstruction_matches=sum(bool(r.get('context_sections_match')) for r in batch),
                       topk_anchor_additions_redundant_rows=sum(r.get('anchors_equal_without_topk') is True for r in batch))
        for category, values in [('reads', facts), ('updates', updates), ('guards', guards)]:
            summary[category+'_stage_presence'] = {s: sum(v['survival'].get(s) is True for v in values) for s in STAGES}
        missing = Counter()
        for value in facts:
            s = value['survival']
            for name, condition in [('original_unmapped', not s['original']),
                                    ('compression_excludes_original', s['original'] and not s['compressed']),
                                    ('candidate_paths_exclude_pathgraph_read', s['path_graph'] and not s['candidate_paths']),
                                    ('topk_excludes_candidate_read', s['candidate_paths'] and not s['topk']),
                                    ('display_cap_excludes_topk_read', s['topk'] and not s['displayed_path_nodes']),
                                    ('src_missing_exact_read', not s['src_exact']), ('dep_missing_exact_read', not s['dep_exact'])]:
                missing[name] += bool(condition)
        summary['nonexclusive_loss_observations'] = dict(missing)
        summary['exact_unmapped_api_but_line_name_node_present'] = sum(not v['survival']['original'] and bool(v.get('api_line_name_node_ids')) for v in facts)
        # Macro averages give each source/family equal weight, then each member
        # row equal weight. Failures are explicit; not silently converted to zero.
        for unit in ('source_sha256', 'group_id'):
            groups = defaultdict(list)
            for row in batch: groups[row[unit]].append(row)
            rates = {}
            for stage in ('src_exact', 'dep_exact', 'topk'):
                group_rates = []
                for members in groups.values():
                    row_rates = [sum(v['survival'][stage] for v in r['reads'])/len(r['reads'])
                                 for r in members if not r.get('error') and r.get('reads')]
                    if row_rates: group_rates.append(sum(row_rates)/len(row_rates))
                rates[stage] = dict(eligible_units=len(group_rates), total_units=len(groups),
                                    mean_read_candidate_presence=sum(group_rates)/len(group_rates) if group_rates else None)
            summary[unit+'_macro'] = rates
        scope[label] = summary
    return scope


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--indices', help='Optional fixed diagnostic subset, never called full-SVEN audit')
    parser.add_argument('--workers', type=int, default=1, help='Independent offline processes, 1..8; not prediction threads')
    args = parser.parse_args()
    if args.output.exists(): raise ValueError('Do not overwrite an audit; choose a new directory')
    if not 1 <= args.workers <= 8: raise ValueError('workers must be 1..8')
    if args.workers > 1:
        requested = list(range(254)) if args.indices is None else [int(s) for s in args.indices.split(',')]
        if len(set(requested)) != len(requested) or any(i not in range(254) for i in requested):
            raise ValueError('Invalid diagnostic subset')
        args.output.mkdir(parents=True)
        partitions = [requested[i::args.workers] for i in range(args.workers) if requested[i::args.workers]]
        def worker(item):
            i, indices = item
            command = [sys.executable, '-B', '-m', 'evaluation.audit_graph_read_evidence',
                       '--output', str((args.output/f'shard_{i:02d}').resolve()), '--indices', ','.join(map(str, indices))]
            result = subprocess.run(command, cwd=ROOT, capture_output=True, encoding='utf8', errors='replace')
            (args.output/f'shard_{i:02d}.log').write_text(result.stdout+'\n'+result.stderr, encoding='utf8')
            print(f'OFFLINE shard {i+1}/{len(partitions)} completed exit={result.returncode}', flush=True)
            return result.returncode
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            statuses = list(pool.map(worker, enumerate(partitions)))
        rows = []
        for i in range(len(partitions)):
            path = args.output/f'shard_{i:02d}'/'rows.jsonl'
            if path.exists(): rows += [json.loads(s) for s in path.read_text(encoding='utf8').splitlines()]
        if len(rows) != len(requested) or {r['idx'] for r in rows} != set(requested):
            raise ValueError('Incomplete shards; logs and rows preserved, no silent row omission')
        rows.sort(key=lambda r: r['idx'])
        (args.output/'rows.jsonl').write_text(''.join(json.dumps(r, ensure_ascii=False)+'\n' for r in rows), encoding='utf8')
        reports = [read(args.output/f'shard_{i:02d}'/'report.json') for i in range(len(partitions))]
        report = dict(reports[0])
        report.update(scope='all exposed SVEN rows' if args.indices is None else 'fixed diagnostic subset', scheduled_indices=requested,
                      workers=len(partitions), shard_exit_codes=statuses, summaries=summarize(rows),
                      rows_sha256=sha(args.output/'rows.jsonl'), unique_stage_reconstructions=sum(r['unique_stage_reconstructions'] for r in reports),
                      blocked_external_attempts=sum(r['blocked_external_attempts'] for r in reports))
        (args.output/'report.json').write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf8')
        print(json.dumps(dict(output=str(args.output), rows=len(rows), errors=sum(bool(r.get('error')) for r in rows),
                              api_calls=0, all=report['summaries']['all']), indent=2))
        if any(statuses) or any(r.get('error') for r in rows): raise SystemExit('Offline audit failed; inspect preserved shards')
        return
    receipt, manifest = read(BASE), read(RUN/'manifest.json')
    prior = read(RUN/'audit.json')
    for name, expected in prior['artifact_sha256'].items():
        if sha(RUN/name) != expected: raise ValueError('Audited experiment changed: '+name)
    if sha(RUN/'api_receipts.jsonl') != read(RUN/'audit_addendum.json')['api_receipts_sha256']:
        raise ValueError('Saved request receipts changed')
    if sha(manifest['dataset']) != manifest['dataset_sha256']: raise ValueError('Dataset changed')
    data = read(manifest['dataset'])
    if len(data) != 254: raise ValueError('Dataset scope changed')
    def verify_sources():
        for root, hashes in [(SOURCE, receipt['code_hashes']), (Path(receipt['frozen_source']), receipt['code_hashes']),
                             (ROOT, receipt['preserved_repaired_code_hashes'])]:
            for name, expected in hashes.items():
                if sha(root/name) != expected: raise ValueError('Prediction source changed: '+str(root/name))
    verify_sources()
    requested = list(range(254)) if args.indices is None else [int(s) for s in args.indices.split(',')]
    if len(set(requested)) != len(requested) or any(i not in range(254) for i in requested):
        raise ValueError('Invalid diagnostic subset')
    samples = {s['idx']: s for s in manifest['samples']}
    first = {}
    for line in (RUN/'api_receipts.jsonl').read_text(encoding='utf8').splitlines():
        call = json.loads(line)
        if call['profile'] == 'control': first.setdefault((call['idx'], call['repeat']), call['request'])
    os.environ.update(receipt['settings']); os.environ.update(OPENAI_API_KEY='offline-not-a-key')
    sys.dont_write_bytecode = True; sys.path.insert(0, str(SOURCE))
    pipeline = importlib.import_module('graph.pipeline')
    typed = importlib.import_module('linearization.typed_paths')
    api = importlib.import_module('reasoning.llm_api')
    for module in (pipeline, typed, api):
        if not Path(module.__file__).resolve().is_relative_to(SOURCE): raise ValueError('Wrong prediction source imported')
    args.output.mkdir(parents=True)
    rows, cache = [], {}
    blocked_attempts = [0]
    def blocked(*unused, **kwargs):
        blocked_attempts[0] += 1
        raise RuntimeError('External access forbidden in evidence audit')
    class Captured(Exception): pass
    from evaluation.audit_type_coverage_baseline import memoized_search
    re._MAXCACHE = 32768
    if hasattr(re, '_MAXCACHE2'): re._MAXCACHE2 = 16384
    original_search = re.search
    with patch.object(re, 'search', memoized_search(original_search)), patch.object(api, 'create_client', blocked), \
            patch.object(socket.socket, 'connect', blocked), patch.object(socket, 'create_connection', blocked), patch('subprocess.Popen', blocked):
        for number, idx in enumerate(requested):
            sample, code = samples[idx], data[idx]['input']
            row = {k: sample[k] for k in ('idx', 'source_sha256', 'group_id', 'cwe')}
            try:
                source, graph_file = Path(sample['source_path']), Path(sample['cache_path'])/'export/export.dot'
                if sha(source) != sample['wrapped_source_sha256'] or sha(graph_file) != sample['cpg_sha256']:
                    raise ValueError('Saved source/graph changed')
                if hashlib.sha256(code.encode()).hexdigest() != sample['source_sha256']: raise ValueError('Supplied source changed')
                key = (sample['source_sha256'], sample['cpg_sha256'])
                if key not in cache:
                    captured = {}
                    original_summary, original_extract = pipeline.summarize_graph, pipeline.extract_all_candidate_paths
                    def capture_summary(*a, **k):
                        result = original_summary(*a, **k); captured['compressed'] = result; return result
                    def capture_extract(graph, *a, **k):
                        result = original_extract(graph, *a, **k)
                        captured.setdefault('extractions', []).append((graph, result)); return result
                    def capture_loop(graph, paths, function_code, func_summary, blocks, **kwargs):
                        captured.update(graph=kwargs['full_graph'], path_graph=graph, topk=paths, offset=kwargs['source_line_offset'],
                                        context=typed.build_hierarchical_context(graph, function_code, func_summary, blocks, paths, include_state=True))
                        raise Captured()
                    with patch.object(pipeline, 'build_cpg', return_value=str(graph_file.parent)), \
                            patch.object(pipeline, 'summarize_graph', capture_summary), \
                            patch.object(pipeline, 'extract_all_candidate_paths', capture_extract), \
                            patch.object(pipeline, 'reasoning_loop', capture_loop), contextlib.redirect_stdout(io.StringIO()):
                        try:
                            pipeline.run_hgl_pipeline(str(source), code, sample['sample_id'], str(source.parent), None, 4096, ablation='')
                        except Captured: pass
                    graph, compressed, path_graph, topk = [captured[k] for k in ('graph', 'compressed', 'path_graph', 'topk')]
                    candidates = next(paths for g, paths in reversed(captured['extractions']) if g is path_graph)
                    src, dep = sections(captured['context'])
                    displayed = topk[:4 if min(1100, max(600, len(code)//8)) > 600 else 2]
                    reads, updates, guards = extract_facts(code)
                    selected_updates, selected_guards = [], []
                    links = []
                    for value in reads:
                        us, gs = related_facts(value, updates, guards)
                        for v in us:
                            if v not in selected_updates: selected_updates.append(v)
                        for v in gs:
                            if v not in selected_guards: selected_guards.append(v)
                        links.append((us, gs))
                    def observed(value):
                        return survival(value, graph, compressed, path_graph, candidates, topk, displayed, captured['offset'], src, dep)
                    read_obs, update_obs, guard_obs = map(lambda facts: [observed(v) for v in facts], (reads, selected_updates, selected_guards))
                    for value, (us, gs) in zip(read_obs, links):
                        read_nodes = set(value['original_node_ids'])
                        guard_nodes = {n for g in gs for n in matching_nodes(graph, g, captured['offset'])}
                        value['related_updates'] = [selected_updates.index(u) for u in us]
                        value['related_guards'] = [selected_guards.index(g) for g in gs]
                        value['shared_topk_path_with_guard_candidate'] = any(read_nodes.intersection(p) and guard_nodes.intersection(p) for p in topk)
                        value['guard_dominance_and_capacity_proof'] = 'unknown; not certified by lexical match or shared path'
                    anchors = typed._collect_graph_anchors(path_graph, topk)
                    cache[key] = dict(reads=read_obs, updates=update_obs, guards=guard_obs,
                                      anchors_equal_without_topk=anchors == typed._collect_graph_anchors(path_graph, []),
                                      graph_nodes=graph.number_of_nodes(), compressed_nodes=compressed.number_of_nodes(),
                                      path_graph_origin='compressed' if path_graph is compressed else 'original_fallback',
                                      candidate_path_count=len(candidates), topk_path_count=len(topk), displayed_path_count=len(displayed),
                                      source_line_offset=captured['offset'], src=src, dep=dep)
                row.update(cache[key])
                saved_parts = [sections(first[idx, repeat]['messages'][1]['content']) for repeat in (1, 2)]
                row['context_sections_match'] = all(parts == (row['src'], row['dep']) for parts in saved_parts)
                if not row['context_sections_match']: row['error'] = 'Reconstructed SRC/DEP differs from saved control; keep diagnostic row'
            except Exception as exc:
                row['error'] = type(exc).__name__+': '+str(exc)
            rows.append(row)
            with (args.output/'rows.jsonl').open('a', encoding='utf8') as stream:
                stream.write(json.dumps(row, ensure_ascii=False)+'\n')
            if (number+1) % 10 == 0 or number+1 == len(requested):
                print(f'OFFLINE evidence {number+1}/{len(requested)} errors={sum(bool(r.get("error")) for r in rows)} api_calls=0', flush=True)
    verify_sources()
    report = dict(scope='all exposed SVEN rows' if args.indices is None else 'fixed diagnostic subset', scheduled_indices=requested,
                  new_api_calls=0, blocked_external_attempts=blocked_attempts[0], prediction_code_changed=False,
                  independent_quality_test=False, source_files_verified=47, source_manifest_sha256=sha(RUN/'manifest.json'),
                  audit_tool_sha256=sha(__file__), rows_sha256=sha(args.output/'rows.jsonl'), unique_stage_reconstructions=len(cache),
                  summaries=summarize(rows), reference_full_set_conflict_rows=read(RUN/'audit_addendum.json')['exact_source_conflict_rows'],
                  limitations=['Lexical read/update/guard candidates, not complete C semantics; macros/custom helper reads may be missed.',
                               'Array read/write heuristic and two-round lexical relations may over/under-match; statements after a read are not preconditions.',
                               'Node mapping requires source-line alignment plus exact normalized expression, excludes whole-body BLOCK/METHOD text.',
                               'Supplemental API-name/line nodes expose possible escape/format mismatches; unmapped is NOT proof the CPG has no read.',
                               'Text presence ignores whitespace/terminal semicolons and cannot distinguish repeated equal occurrences or prove guard scope.',
                               'Stage/text presence is not guard dominance, read capacity or correct reasoning; contracts remain unknown.',
                               'Stages are not a monotonic pipeline: original-graph fallback and independent SRC selection can recover absent path evidence.',
                               'Labels/CWE are used only after extraction for exposed-development summaries, not evidence selection or prediction.',
                               'Failures stay in row denominators; macro means explicitly report eligible vs total source/family units.',
                               'No new model calls, predictions, quality gains, locked Devign reads or causal claims.'])
    (args.output/'report.json').write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf8')
    print(json.dumps(dict(output=str(args.output), rows=len(rows), errors=sum(bool(r.get('error')) for r in rows),
                          api_calls=0, all=report['summaries']['all']), indent=2), flush=True)
    if any(r.get('error') for r in rows) or blocked_attempts[0]: raise SystemExit('Audit incomplete; retain all diagnostic records')


if __name__ == '__main__': main()
