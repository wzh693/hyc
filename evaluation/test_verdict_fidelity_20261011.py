"""verdict_fidelity_candidate_20261011 四项修复的单元回归;须在隔离进程中运行(见 run_tests_isolated.py)。"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'development/verdict_fidelity_candidate_20261011/src'
sys.path.insert(0, str(SOURCE))

from reasoning.reasoning_loop import (  # noqa: E402
    parse_binary_verdict, _extract_vulnerability_type, _conclusion_is_benign)
from linearization.typed_paths import _slice_source, _strip_c_comments_line  # noqa: E402


class VerdictParsingTests(unittest.TestCase):
    """BUG-A/B/C: 良性判定词表三处统一后的行为。"""

    def test_no_hypothesis_uncertain_phrases_are_not_vulnerable(self):
        # BUG-A: 无 HYPOTHESIS 行时 "insufficient evidence ... vulnerability"
        # 此前落入通用词匹配返回 Generic Vulnerability(误报)
        self.assertEqual(
            _extract_vulnerability_type('insufficient evidence to confirm vulnerability', is_final=True),
            'Unknown')
        self.assertEqual(
            _extract_vulnerability_type('exploit unlikely; input validated', is_final=True),
            'Unknown')
        self.assertEqual(
            _extract_vulnerability_type('cannot confirm the free is matched', is_final=True),
            'Unknown')

    def test_hypothesis_uncertain_phrases_unchanged(self):
        self.assertEqual(
            _extract_vulnerability_type('HYPOTHESIS: insufficient evidence to confirm vulnerability', is_final=True),
            'Unknown')

    def test_no_hypothesis_generic_vulnerability_word_still_detected(self):
        self.assertEqual(
            _extract_vulnerability_type('this is a dangerous vulnerability', is_final=True),
            'Generic Vulnerability')

    def test_final_benign_exemption_accepts_benign_words(self):
        # BUG-B: "correctly/properly" 类明确良性表述此前无法触发 v16.1 豁免,
        # 导致 Step1 漏洞类型粘住最终结论
        self.assertTrue(_conclusion_is_benign('HYPOTHESIS: the length check is correctly applied'))
        self.assertTrue(_conclusion_is_benign('HYPOTHESIS: inputs are properly validated'))
        self.assertTrue(_conclusion_is_benign('HYPOTHESIS: no vulnerability detected'))
        self.assertTrue(_conclusion_is_benign('HYPOTHESIS: the copy is safe'))

    def test_final_benign_exemption_still_rejects_uncertain_and_vuln(self):
        self.assertFalse(_conclusion_is_benign('HYPOTHESIS: insufficient evidence to confirm'))
        self.assertFalse(_conclusion_is_benign('HYPOTHESIS: buffer overflow'))
        self.assertFalse(_conclusion_is_benign('no hypothesis line at all'))

    def test_parse_binary_verdict_aligned_benign_phrases(self):
        # BUG-C: 短语表与 _BENIGN_DEFINITE 对齐
        self.assertEqual(parse_binary_verdict('no exploit path exists'), 0)
        self.assertEqual(parse_binary_verdict('the copy poses no risk'), 0)
        self.assertEqual(parse_binary_verdict('no security concern found'), 0)

    def test_parse_binary_verdict_vulnerable_unchanged(self):
        self.assertEqual(parse_binary_verdict('buffer overflow in the loop'), 1)
        self.assertEqual(parse_binary_verdict('use-after-free on p'), 1)
        self.assertIsNone(parse_binary_verdict('the pointer is checked afterwards'))

    def test_parse_binary_verdict_negation_guards_preserved(self):
        # 既有 v7 教训回归: "not safe"/"incorrectly" 不得判良性
        # (无漏洞关键词时保守 abstain 为 None,而非 0)
        self.assertIsNone(parse_binary_verdict('the deallocation is not safe'))
        self.assertIsNone(parse_binary_verdict('incorrectly validated input'))
        # 否定词 + 具体漏洞关键词同时出现时仍判 1
        self.assertEqual(parse_binary_verdict('the deallocation is not safe; use-after-free'), 1)
        self.assertEqual(parse_binary_verdict('incorrectly validated input, buffer overflow'), 1)


class SliceCommentMaskingTests(unittest.TestCase):
    """BUG-D: SRC 切片先剥注释再匹配 keep_pat。"""

    def test_trailing_line_comment_not_injected(self):
        out = _slice_source('p = 1; // memcpy(buf, src, len) unbounded copy here', 1000)
        self.assertNotIn('memcpy', out)
        self.assertNotIn('unbounded', out)

    def test_full_line_block_comment_dropped(self):
        out = _slice_source('x = a[i];\nfoo(a);\n/* memcpy(b, c, n); fake */\nreturn p->q;', 1000)
        self.assertNotIn('fake', out)
        self.assertNotIn('memcpy', out)
        self.assertIn('foo(a);', out)

    def test_multiline_block_comment_masked(self):
        out = _slice_source('x = 1; /* comment start\nstill comment text\n*/\nmemcpy(a, b, n);', 1000)
        self.assertNotIn('still comment', out)
        self.assertNotIn('comment start', out)
        self.assertIn('memcpy(a, b, n);', out)

    def test_string_literal_slashes_preserved(self):
        out = _slice_source('log_error("http://x // not comment");', 1000)
        self.assertIn('http://x // not comment', out)

    def test_control_flow_and_calls_regression(self):
        out = _slice_source('if (n > 0) {\n  memcpy(dst, src, n);\n}\nreturn 0;', 1000)
        self.assertIn('if (n > 0) {', out)
        self.assertIn('memcpy(dst, src, n);', out)
        self.assertIn('return 0;', out)

    def test_strip_helper_midline_block_comment(self):
        self.assertEqual(_strip_c_comments_line('a = "/x"; /* c */ b;', False),
                         ('a = "/x";  b;', False))
        visible, state = _strip_c_comments_line('a; /* open', False)
        self.assertEqual((visible, state), ('a; ', True))
        self.assertEqual(_strip_c_comments_line('still comment', True), ('', True))
        self.assertEqual(_strip_c_comments_line('end */ b;', True), (' b;', False))

    def test_star_prefix_line_still_skipped_without_assignment_fix(self):
        # foundation 行为保持: 未启用赋值修复时 '*' 前缀行按注释续行跳过
        out = _slice_source('foo(a);\n* deref continuation line\nreturn 0;', 1000)
        self.assertNotIn('deref continuation', out)


if __name__ == '__main__':
    unittest.main()
