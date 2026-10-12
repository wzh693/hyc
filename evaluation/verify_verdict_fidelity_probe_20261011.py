import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'development/verdict_fidelity_candidate_20261011/src'
sys.path.insert(0, str(SOURCE))
from reasoning.reasoning_loop import (
    parse_binary_verdict, _extract_vulnerability_type, _conclusion_is_benign)
from linearization.typed_paths import _slice_source, _strip_c_comments_line

ok = True
def check(name, actual, expected):
    global ok
    good = actual == expected
    ok = ok and good
    print(('PASS' if good else 'FAIL'), name, '->', repr(actual))

# BUG-A: no-HYPOTHESIS 分支补齐不确定性/良性短语
check('A1 no-hyp uncertain', _extract_vulnerability_type(
    'insufficient evidence to confirm vulnerability', is_final=True), 'Unknown')
check('A2 no-hyp unlikely', _extract_vulnerability_type(
    'exploit unlikely; input validated', is_final=True), 'Unknown')
check('A3 with-hyp uncertain', _extract_vulnerability_type(
    'HYPOTHESIS: insufficient evidence to confirm vulnerability', is_final=True), 'Unknown')
# foundation 设计: 无 HYPOTHESIS 行的回退分支不做具体类型提取,只判
# 良性/通用词;此处仅确认良性短语扩充未引入行为回退(具体类型仍 Unknown)
check('A4 no-hyp real vuln unchanged (foundation behavior)', _extract_vulnerability_type(
    'buffer overflow in the copy loop', is_final=True), 'Unknown')
check('A4b no-hyp generic vuln word', _extract_vulnerability_type(
    'this is a dangerous vulnerability', is_final=True), 'Generic Vulnerability')

# BUG-B: 最终良性豁免补齐 correctly/properly
check('B1 exempt correctly', _conclusion_is_benign(
    'HYPOTHESIS: the length check is correctly applied'), True)
check('B2 exempt definite', _conclusion_is_benign(
    'HYPOTHESIS: no vulnerability detected'), True)
check('B3 uncertain NOT exempt', _conclusion_is_benign(
    'HYPOTHESIS: insufficient evidence to confirm'), False)
check('B4 vuln NOT exempt', _conclusion_is_benign(
    'HYPOTHESIS: buffer overflow'), False)

# BUG-C: parse_binary_verdict 短语表对齐
check('C1 no exploit', parse_binary_verdict('no exploit path exists'), 0)
check('C2 no risk', parse_binary_verdict('the copy poses no risk'), 0)
check('C3 no security concern', parse_binary_verdict('no security concern found'), 0)
check('C4 vuln still 1', parse_binary_verdict('buffer overflow in the loop'), 1)
check('C5 benign+vuln keeps benign-wins', parse_binary_verdict(
    'the check is safe; loop copy could overflow but bounded'), 0)

# BUG-D: _slice_source 注释剥离
out = _slice_source('p = 1; // memcpy(buf, src, len) unbounded copy here', 1000)
check('D1 trailing // stripped', 'memcpy' in out, False)
out = _slice_source('x = a[i];\nfoo(a);\n/* memcpy(b, c, n); fake */\nreturn p->q;', 1000)
check('D2 full-line block comment gone', 'fake' in out or 'memcpy' in out, False)
out = _slice_source('x = 1; /* comment start\nstill comment text\n*/\nmemcpy(a, b, n);', 1000)
check('D3 multiline block comment masked', ('still comment' in out), False)
check('D3b real code kept', 'memcpy(a, b, n);' in out, True)
out = _slice_source('log_error("http://x // not comment");', 1000)
check('D4 // inside string kept', 'http://x // not comment' in out, True)
out = _slice_source('if (n > 0) {\n  memcpy(dst, src, n);\n}\nreturn 0;', 1000)
check('D5 regression control flow', 'if (n > 0) {' in out and 'memcpy(dst, src, n);' in out, True)
a, b = _strip_c_comments_line('a = "/x"; /* c */ b;', False)
check('D6 midline block', (a, b), ('a = "/x";  b;', False))

print('ALL PASS' if ok else 'SOME FAILED')
sys.exit(0 if ok else 1)
