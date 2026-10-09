"""Audit source filtering and contradictory SVEN labels without API calls."""
import collections
import inspect
import json
from pathlib import Path

from linearization import typed_paths


def legacy_slicer():
    source = inspect.getsource(typed_paths._slice_source)
    source = source.replace('        + (r"|(?<![=!<>])=(?!=)|\\+\\+|--" if SOURCE_SLICE_ASSIGNMENT_FIX else "")', '        + ""')
    start = source.index('    in_block_comment = False\n')
    end = source.index('        if not stripped:', start)
    source = source[:start] + '    for line in src.split("\\n"):\n        stripped = line.strip()\n' + source[end:]
    source = source.replace('if stripped.startswith("//") or (not SOURCE_SLICE_ASSIGNMENT_FIX and stripped.startswith("*")):',
                            'if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):')
    scope = dict(vars(typed_paths))
    exec(source, scope)
    return scope['_slice_source']


def main():
    import config
    config.SOURCE_SLICE_ASSIGNMENT_FIX = True
    root = Path(__file__).resolve().parents[1]
    data = json.loads((root / 'sven_eval/data/sven_test.json').read_text(encoding='utf8'))
    groups = collections.defaultdict(list)
    for i, row in enumerate(data):
        groups[row['input']].append((i, row['output']))
    old = legacy_slicer()
    changes = []
    conflicts = []
    upper_correct = 0
    for code, group in groups.items():
        counts = collections.Counter(label for _, label in group)
        upper_correct += max(counts.values())
        if len(counts) > 1:
            conflicts.append({'indices': [i for i, _ in group], 'labels': dict(counts)})
        budget = min(1100, max(600, len(code) // 8))
        before = old(code, max_chars=budget)
        after = typed_paths._slice_source(code, max_chars=budget)
        if before != after:
            changes.append({'idx': group[0][0], 'indices': [i for i, _ in group],
                            'before': before, 'after': after,
                            'budget': budget, 'before_chars': len(before), 'after_chars': len(after)})
    report = {'n': len(data), 'unique_source': len(groups),
              'conflicting_source': len(conflicts), 'conflicts': conflicts,
              'deterministic_accuracy_ceiling': upper_correct / len(data),
              'changed_unique_source': len(changes), 'changes': changes}
    output = root / 'sven_eval/source_evidence_audit.json'
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf8')
    print(json.dumps({k: v for k, v in report.items() if k not in ('changes', 'conflicts')}, indent=2))


if __name__ == '__main__':
    main()
