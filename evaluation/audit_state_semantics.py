"""Label-free synthetic STATE audit. Observations are not desired regression behavior.

No client, dataset labels, or model calls. Never changes prediction modules.
"""
import argparse
import hashlib
import json
from pathlib import Path

import networkx as nx
from planning.state_memory import ProgramState
from reasoning.reasoning_loop import _update_program_state
from reasoning.prompts import build_user_prompt
from linearization.typed_paths import build_hierarchical_context


# Expectations concern the indicated operation only, not whole-function safety.
CASES = [
    ('control_straight_uaf', 'void f(struct S *p) {\nfree(p);\np->x=1;\n}',
     'is_freed_and_used', 'p', True, 'Straight-line release followed by use.'),
    ('control_guarded_deref', 'void f(struct S *p) {\nif(!p) return;\np->x=1;\n}',
     'is_null_pointer_deref', 'p', False, 'Null input exits before use.'),
    ('control_single_free', 'void f(void *p) {\nfree(p);\n}',
     'is_double_free', 'p', False, 'One release operation.'),
    ('control_scanf_destination', 'void f(char *buf) {\nscanf("%s",buf);\nbuf[0]=1;\n}',
     'is_taint_propagation', 'buf', True, 'Successful conversion writes into the second argument.'),
    ('exclusive_uaf', 'void f(int c, struct S *p) {\nif(c) free(p);\nelse p->x=1;\n}',
     'is_freed_and_used', 'p', False, 'Free and use are mutually exclusive in this invocation.'),
    ('exclusive_double_free', 'void f(int c, void *p) {\nif(c) free(p);\nelse free(p);\n}',
     'is_double_free', 'p', False, 'Each invocation executes one free.'),
    ('new_allocation_uaf', 'void f(void) {\nchar *p=malloc(4);\nfree(p);\np=malloc(4);\nif(!p) return;\np[0]=1;\n}',
     'is_freed_and_used', 'p', False, 'Use belongs to the second allocation, guarded for failure.'),
    ('new_allocation_double_free', 'void f(void) {\nchar *p=malloc(4);\nfree(p);\np=malloc(4);\nfree(p);\n}',
     'is_double_free', 'p', False, 'Two distinct allocation lifetimes, not repeated release of one lifetime.'),
    ('earlier_uaf_hidden', 'void f(struct S *p) {\nfree(p);\np->x=1;\nfree(p);\n}',
     'is_freed_and_used', 'p', True, 'A later free cannot erase the earlier use-after-free.'),
    ('late_null_check', 'void f(struct S *p) {\np->x=1;\nif(!p) return;\n}',
     'is_null_pointer_deref', 'p', True, 'The check does not guard the preceding use; null input is feasible.'),
    ('wrong_guard_polarity', 'void f(struct S *p) {\nif(p==NULL) p->x=1;\n}',
     'is_null_pointer_deref', 'p', True, 'The checked branch explicitly dereferences null.'),
    ('comment_events', 'void f(void *p) {\n/* free(p); p->x=1; */\n}',
     'is_freed_and_used', 'p', False, 'Comments do not execute.'),
    ('string_events', 'void f(void) {\nputs("free(p); p->x=1;");\n}',
     'is_freed_and_used', 'p', False, 'String contents do not execute.'),
    ('alias_uaf', 'void f(struct S *p) {\nstruct S *q=p;\nfree(p);\nq->x=1;\n}',
     'is_freed_and_used', 'q', True, 'q aliases the released object.'),
    ('scanf_destination', 'void f(char *src, char *fmt, char *buf) {\nsscanf(src,fmt,buf);\nbuf[0]=1;\n}',
     'is_taint_propagation', 'buf', True, 'Successful conversion writes into buf, not the format parameter.'),
]


def collect_audit():
    rows = []
    for name, code, probe, var, expected, reason in CASES:
        state = ProgramState()
        state.track_vars(code)
        observed = getattr(state, probe)(var)
        context = build_hierarchical_context(nx.MultiDiGraph(), code, '', {}, [], include_state=True)
        prompt = build_user_prompt('', context, state.dump(), 1)
        rows.append(dict(id=name, code=code, probe=probe, variable=var,
                         expected_pattern=expected, observed_pattern=observed,
                         mismatch=observed != expected, rationale=reason,
                         histories=state.states, dump=state.dump(), first_prompt=prompt))

    graph = nx.MultiDiGraph()
    graph.add_node('alloc', code='p = malloc(n);')
    empty = ProgramState()
    _update_program_state(empty, '', graph, [['alloc']], 1)
    # Source-free path extraction currently attributes malloc's size to allocation.
    path_probe = {'code': 'p = malloc(n);', 'histories': empty.states,
                  'expected_allocated_variable': 'p',
                  'observed_allocated_variables': [v for v in empty.states
                      if any(h['state'] == 'allocated' for h in empty.get_state(v))]}
    later = build_user_prompt('', 'PATHS: synthetic', empty.dump(), 2)
    root = Path(__file__).resolve().parents[1]
    files = ['planning/state_memory.py', 'reasoning/reasoning_loop.py',
             'reasoning/prompts.py', 'reasoning/explanation.py', 'linearization/typed_paths.py']
    return {'scope': 'synthetic diagnostic only; no benchmark labels or API calls',
            'semantic_expectations': 'hand-written local operation reasoning, not whole-function labels',
            'mismatch_count': sum(row['mismatch'] for row in rows), 'cases': rows,
            'path_probe': path_probe, 'second_prompt': later,
            'production_sha256': {f: hashlib.sha256((root/f).read_bytes()).hexdigest() for f in files},
            'limitations': ['Does not estimate F1/Accuracy impact or prevalence.',
                            'Predicate helpers generate explanations, not direct final predictions.',
                            'Stored full histories are not necessarily visible after prompt truncation.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = collect_audit()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
    print(json.dumps({'cases': len(report['cases']), 'mismatches': report['mismatch_count'],
                      'output': str(args.output)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
