"""Offline candidate audit; does not change the production verifier."""
import argparse
import json
from pathlib import Path
import re

from graph.security_net import (_FREE_RE, _canonical_expr, _reassignment_re,
                                _strong_use_re, extract_security_signal, SecuritySignal)
from evaluation.calibrate_security_net import metrics


def mask_noncode(code):
    # Translation-phase line splices precede C comment parsing.
    code = re.sub(r'\\\r?\n', lambda m:' '*len(m.group()), code)
    pattern = r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/'
    return re.sub(pattern, lambda m:''.join('\n' if c=='\n' else ' ' for c in m.group()), code)


def candidate_signal(code):
    code = mask_noncode(code)
    baseline = extract_security_signal(code)
    frees = list(_FREE_RE.finditer(code))
    uaf = double = 0
    for i, match in enumerate(frees):
        expr = _canonical_expr(match.group('expr'))
        following = next((m for m in frees[i+1:] if _canonical_expr(m.group('expr'))==expr), None)
        tail = code[match.end():following.start() if following else len(code)]
        reset = _reassignment_re(expr).search(tail)
        use = _strong_use_re(expr).search(tail)
        uaf += bool(use and (not reset or use.start()<reset.start()))
        double += bool(following and not reset)
    score = min(uaf,2)*4 + min(double,2)*5 + min(baseline.unbounded_calls,2)*2 + 4*baseline.tainted_command
    reasons = []
    if uaf: reasons.append(f'free-to-deref:{uaf}')
    if double: reasons.append(f'double-free:{double}')
    if baseline.unbounded_calls: reasons.append(f'unbounded-call:{baseline.unbounded_calls}')
    if baseline.tainted_command: reasons.append('taint-to-command')
    return SecuritySignal(score,uaf,double,baseline.unbounded_calls,baseline.tainted_command,tuple(reasons))


def main():
    p = argparse.ArgumentParser()
    p.add_argument('report', type=Path)
    p.add_argument('samples', type=Path)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    payload = json.loads(a.report.read_text(encoding='utf8'))
    rows = [r for r in payload['results_b'] if r.get('prediction') in (0,1)]
    before, after, changes = [], [], []
    for r in rows:
        source = a.samples/f"sample_{r['idx']:06d}.c"
        code = source.read_text(encoding='utf8',errors='replace')
        old = extract_security_signal(code)
        new = candidate_signal(code)
        pred = r['prediction']
        x, y = int(pred==1 or old.score>=4), int(pred==1 or new.score>=4)
        before.append(x); after.append(y)
        if old != new:
            changes.append({'idx':r['idx'], 'target':r['target'], 'old_pred':x, 'new_pred':y,
                            'old_signal':old.to_dict(), 'new_signal':new.to_dict()})
    result = {'protocol':'offline non-SVEN saved-response audit; threshold fixed at 4; zero API calls',
              'rows':len(rows), 'before':metrics(rows,before), 'after':metrics(rows,after), 'changes':changes}
    a.output.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf8')
    print(json.dumps({**result,'changes':len(changes)},indent=2))


if __name__ == '__main__':
    main()
