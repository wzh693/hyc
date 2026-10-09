"""Zero-token structural verifier for high-confidence missed vulnerabilities.

The verifier is deliberately one-way: it may recover a negative LLM
prediction under restricted adjacent lifecycle patterns, but never turns a
positive prediction into benign.  Rules are evidence patterns rather than API
presence: ``free(x)`` alone, for example, is not a UAF signal.
Unsupported control/alias/call contexts are abstained from, not certified safe.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass


_FREE_RE = re.compile(
    r"\b(?:free|kfree|av_free|av_freep|munmap)\s*\(\s*&?"
    r"(?P<expr>[A-Za-z_]\w*(?:\s*->\s*[A-Za-z_]\w*)?)\s*\)"
)
_UNBOUNDED_RE = re.compile(r"\b(?:gets|strcpy|strcat|sprintf|vsprintf)\s*\(")
_COMMAND_RE = re.compile(r"\b(?:system|popen|execv(?:e|p)?)\s*\(")
_TAINT_RE = re.compile(
    r"\b(?:recv|read|fread|scanf|fscanf|getenv|gets|getline|getchar)\s*\("
)


@dataclass(frozen=True)
class SecuritySignal:
    score: int
    uaf_chains: int
    double_free_chains: int
    unbounded_calls: int
    tainted_command: bool
    reasons: tuple[str, ...]

    def to_dict(self) -> dict:
        value = asdict(self)
        value["reasons"] = list(self.reasons)
        return value


def _canonical_expr(expr: str) -> str:
    return re.sub(r"\s+", "", expr or "")


def _mask_noncode(code: str) -> str:
    """Exclude C comments and literals from executable-operation matching."""
    code = re.sub(r'\\\r?\n', lambda m: ' ' * len(m.group()), code or '')
    pattern = r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/'
    return re.sub(pattern, lambda m: ''.join('\n' if c == '\n' else ' ' for c in m.group()), code)


def _strong_use_re(expr: str) -> re.Pattern:
    """Use after free requiring a dereference/index, not mere identifier reuse."""
    expr = _canonical_expr(expr)
    if "->" in expr:
        # A freed member may subsequently be dereferenced/indexed or passed to a
        # memory operation.  Matching the same member name alone is too weak.
        base = re.escape(expr).replace(r"\->", r"\s*->\s*")
        return re.compile(
            rf"(?:{base}\s*(?:->|\[)|\*\s*{base}\b|"
            rf"\b(?:memcpy|memmove|memset|strcpy|strlen)\s*\([^;]*\b{base}\b)"
        )
    ident = re.escape(expr)
    return re.compile(
        rf"(?:\b{ident}\s*(?:->|\[)|\*\s*{ident}\b|"
        rf"\b(?:memcpy|memmove|memset|strcpy|strlen)\s*\([^;]*\b{ident}\b)"
    )


def _reassignment_re(expr: str) -> re.Pattern:
    expr = _canonical_expr(expr)
    escaped = re.escape(expr).replace(r"\->", r"\s*->\s*")
    return re.compile(rf"\b{escaped}\s*=(?!=)")


def _lifecycle_signals(code: str) -> tuple[int, int]:
    matches = list(_FREE_RE.finditer(code or ""))
    uaf = double_free = 0
    for i, match in enumerate(matches):
        expr = _canonical_expr(match.group("expr"))
        # Releasing a different object does not end this object's lifetime.
        following = next((later for later in matches[i + 1:]
                          if _canonical_expr(later.group("expr")) == expr), None)
        tail_end = following.start() if following else len(code)
        tail = code[match.end():tail_end]
        # Reinitialisation/NULL assignment ends the old object's lifetime.
        reassigned = _reassignment_re(expr).search(tail)
        use = _strong_use_re(expr).search(tail)
        if use and (not reassigned or use.start() < reassigned.start()):
            uaf += 1

        for later in matches[i + 1:]:
            if _canonical_expr(later.group("expr")) != expr:
                continue
            between = code[match.end():later.start()]
            if not _reassignment_re(expr).search(between):
                double_free += 1
            break
    return uaf, double_free


def extract_security_signal(code: str) -> SecuritySignal:
    """Legacy lexical diagnostics ONLY; scores are not proof or flip criteria."""
    code = _mask_noncode(code)
    uaf, double_free = _lifecycle_signals(code)
    unbounded = len(_UNBOUNDED_RE.findall(code))
    tainted_command = bool(_COMMAND_RE.search(code) and _TAINT_RE.search(code))

    score = min(uaf, 2) * 4 + min(double_free, 2) * 5
    score += min(unbounded, 2) * 2
    score += 4 if tainted_command else 0
    reasons = []
    if uaf:
        reasons.append(f"free-to-deref:{uaf}")
    if double_free:
        reasons.append(f"double-free:{double_free}")
    if unbounded:
        reasons.append(f"unbounded-call:{unbounded}")
    if tainted_command:
        reasons.append("taint-to-command")
    return SecuritySignal(score, uaf, double_free, unbounded,
                          tainted_command, tuple(reasons))


def extract_confirmed_signal(code: str) -> SecuritySignal:
    """Conservative adjacent straight-line evidence, not a C semantic solver.

    Reject control flow, multiple bodies, preprocessing and indirect syntax.
    Do not infer taint from co-occurrence or overflow from API counts. Unknown
    intervening calls and assignments cannot certify a continuing lifetime.
    Assumes ordinary C/libc release contracts, not macro redefinitions.
    """
    code = _mask_noncode(code)
    if (re.search(r'\b(?:if|else|for|while|switch|goto|do)\b|[#?:]|&&|\|\|', code)
            or code.count('{') > 1 or code.count('}') > 1):
        return SecuritySignal(0, 0, 0, 0, False, ())
    uaf = double = 0
    for match in _FREE_RE.finditer(code):
        if not re.match(r'\s*(?:free|kfree|av_free)\b', match.group()):
            continue  # av_freep clears the pointer; munmap has a different contract.
        prefix = code[:match.start()].rstrip()
        if prefix and prefix[-1] not in ';{':
            continue  # Do not treat a release inside an expression as a statement.
        if re.search(r'\b(?:return|break|continue)\b', prefix):
            continue
        tail = code[match.end():]
        if not re.match(r'\s*;', tail):
            continue
        following = re.sub(r'^\s*;\s*', '', tail).split(';', 1)[0].strip()
        expr = _canonical_expr(match.group('expr'))
        release = _FREE_RE.fullmatch(following)
        if (release and _canonical_expr(release.group('expr')) == expr
                and re.match(r'(?:free|kfree|av_free)\b', following)):
            double += 1
        elif (_strong_use_re(expr).search(following)
              and not _reassignment_re(expr).search(following)
              and not re.search(r'\b[A-Za-z_]\w*\s*\(', following)
              and '{' not in following and '}' not in following):
            uaf += 1
    reasons = tuple([f'adjacent-free-to-deref:{uaf}'] if uaf else []) + tuple(
        [f'adjacent-double-free:{double}'] if double else [])
    return SecuritySignal(min(uaf, 2)*4 + min(double, 2)*5, uaf, double, 0, False, reasons)


def zero_token_verify(b_pred: int, code: str, threshold: int = 4) -> tuple[int, dict]:
    """Flip only restricted evidence; uncertain decisions remain uncertain."""
    signal = extract_confirmed_signal(code)
    flipped = b_pred == 0 and signal.score >= threshold
    return (1 if flipped else b_pred), {
        "triggered": signal.score >= threshold,
        "flipped": flipped,
        "threshold": threshold,
        "signal": signal.to_dict(),
        "audit_tokens": 0,
        "policy": "adjacent-straight-line-v1",
        "limitations": "No alias/path solver; unsupported evidence cannot trigger a flip.",
    }
