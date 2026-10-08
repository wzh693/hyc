"""Fail-closed line offsets for exact or line-preserving function wrappers."""
import re


def source_line_offset(code, wrapped):
    invalid = len(wrapped.splitlines()) + 1
    if not code:
        return invalid
    position = wrapped.find(code)
    if position >= 0:
        return (wrapped[:position].count('\n')
                if wrapped.find(code, position+1) < 0 else invalid)
    # SVEN signature wrapping adds ' {' on a signature line without adding or
    # deleting any original lines. Validate the ENTIRE original line sequence;
    # never infer an offset from one repeated body statement or a fuzzy match.
    original, lines = code.splitlines(), wrapped.splitlines()
    candidates = []
    for offset in range(len(lines)-len(original)+1):
        mismatches = [i for i, line in enumerate(original) if line != lines[offset+i]]
        # An explicitly incomplete signature is commented, not completed with
        # guessed parameters; body lines stay byte-for-byte identical. Synthetic
        # wrapper/stub lines remain outside the original evidence coordinates.
        if (mismatches and mismatches == list(range(len(mismatches))) and
                original[0].count('(') > original[0].count(')') and
                not re.match(r'^\s*(if|for|while|switch)\b', original[0]) and
                all(lines[offset+i] == '// '+original[i] for i in mismatches) and
                offset > 0 and lines[offset-1] == 'void sven_slice(void) {'):
            candidates.append(offset)
            continue
        if len(mismatches) != 1:
            continue
        i = mismatches[0]
        before = original[i]
        after = lines[offset+i]
        if after != before.rstrip().rstrip('{').rstrip() + ' {':
            continue
        signature = '\n'.join(original[:i+1]).strip().rstrip('{').rstrip()
        if (not signature.endswith(')') or '(' not in signature or
                signature.count('(') != signature.count(')') or
                re.search(r'\b(?:if|for|while|switch)\s*\(', signature) or
                ';' in signature or '=' in signature):
            continue
        candidates.append(offset)
    return candidates[0] if len(candidates) == 1 else invalid
