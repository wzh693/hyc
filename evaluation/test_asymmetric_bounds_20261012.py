"""asymmetric_bounds_candidate_20261012 非对称证据负担契约的单元回归;
须在隔离进程中运行(单模块运行,勿与其他候选测试混跑)。"""
import contextlib
import io
import re
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'development/asymmetric_bounds_candidate_20261012/src'
CONTROL = ROOT/'development/type_coverage_reconstructed_20261008/src'
sys.path.insert(0, str(SOURCE))

from reasoning.prompts import SYSTEM_PROMPT, build_bounds_challenge_prompt  # noqa: E402
from reasoning.reasoning_loop import (  # noqa: E402
    _benign_bounds_valid, _extract_vulnerability_type, reasoning_loop)

import networkx as nx  # noqa: E402

CODE = """int copy(char *dst, char *src, int n) {
    if (n < 16) { return -1; }
    if (dst == NULL || src == NULL) { return -1; }
    memcpy(dst, src, n);
    return 0;
}"""

BENIGN = 'VERDICT: no vulnerability detected\nACTION: {"action":"Stop","reason":"bounded"}'
VALID_BOUNDS = BENIGN + '\nBOUNDS: if (n < 16) { return -1; }'


def make_graph():
    g = nx.MultiDiGraph()
    g.add_node('m', node_type='CALL', code='memcpy(dst, src, n)', line_number=4)
    g.add_node('g', node_type='CALL', code='if (n < 16)', line_number=2)
    g.add_edge('m', 'g', edge_type='CFG')
    return g


def client_with(answers):
    calls = []

    def create(**request):
        calls.append(request)
        return SimpleNamespace(model='offline-mock',
            usage=SimpleNamespace(total_tokens=0, prompt_tokens=0, completion_tokens=0),
            choices=[SimpleNamespace(finish_reason='stop',
                message=SimpleNamespace(content=answers[len(calls) - 1]))])

    return SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create))), calls


def run_loop(answers, code=CODE, **kw):
    client, calls = client_with(answers)
    with contextlib.redirect_stdout(io.StringIO()):
        result = reasoning_loop(make_graph(), [['m', 'g']], code, 'copy', {},
                                client=client, max_steps=kw.pop('max_steps', 2),
                                use_output_contract=False, use_expansion=False,
                                use_slice=False, use_prog_state=False, **kw)
    return result, calls


class ContractFormatTests(unittest.TestCase):
    """SYSTEM 契约:判定先行,BOUNDS 行仅约束非类型判定。"""

    def test_verdict_action_bounds_order(self):
        lines = SYSTEM_PROMPT.splitlines()
        fmt = next(i for i, l in enumerate(lines) if l.startswith('Format:'))
        self.assertTrue(lines[fmt + 1].startswith('VERDICT:'))
        self.assertTrue(lines[fmt + 2].startswith('ACTION:'))
        self.assertTrue(lines[fmt + 3].startswith('BOUNDS:'))

    def test_no_observation_or_reasoning_in_contract(self):
        fmt = SYSTEM_PROMPT.split('\nFormat:', 1)[1]
        self.assertNotIn('OBSERVATION:', fmt)
        self.assertNotIn('\nREASONING:', fmt)

    def test_bounds_line_requires_verbatim_quote_for_non_type(self):
        fmt = SYSTEM_PROMPT.split('\nFormat:', 1)[1]
        bounds = next(l for l in fmt.splitlines() if l.startswith('BOUNDS:'))
        self.assertIn('required when VERDICT is not a type', bounds)
        self.assertIn('verbatim', bounds)

    def test_first_part_identical_to_control(self):
        control = (CONTROL/'reasoning/prompts.py').read_text(encoding='utf8')
        m = re.search(r'SYSTEM_PROMPT = """(.+?)\nFormat', control, re.S)
        self.assertIsNotNone(m)
        self.assertEqual(SYSTEM_PROMPT.split('\nFormat:', 1)[0], m.group(1))


class BoundsValidatorTests(unittest.TestCase):
    """BOUNDS 引用验证:逐字片段 + 守卫 token,防转述/防sink行混充。"""

    def test_valid_verbatim_guard_quote(self):
        self.assertTrue(_benign_bounds_valid(VALID_BOUNDS, CODE))

    def test_verbatim_null_check_quote_valid(self):
        quote = BENIGN + '\nBOUNDS: if (dst == NULL || src == NULL) { return -1; }'
        self.assertTrue(_benign_bounds_valid(quote, CODE))

    def test_case_and_whitespace_insensitive(self):
        quote = BENIGN + '\nBOUNDS: IF ( N<16 ) { Return -1; }'
        self.assertTrue(_benign_bounds_valid(quote, CODE))

    def test_paraphrase_invalid(self):
        quote = BENIGN + '\nBOUNDS: the code checks n against 16 before copying'
        self.assertFalse(_benign_bounds_valid(quote, CODE))

    def test_missing_bounds_line_invalid(self):
        self.assertFalse(_benign_bounds_valid(BENIGN, CODE))

    def test_sink_line_quote_invalid(self):
        # 逐字引用了源码,但引用的是危险操作行而非守卫行
        quote = BENIGN + '\nBOUNDS: memcpy(dst, src, n);'
        self.assertFalse(_benign_bounds_valid(quote, CODE))

    def test_short_quote_invalid(self):
        self.assertFalse(_benign_bounds_valid(BENIGN + '\nBOUNDS: if (n)', CODE))

    def test_empty_code_invalid(self):
        self.assertFalse(_benign_bounds_valid(VALID_BOUNDS, ''))

    def test_comment_only_word_not_guard(self):
        quote = BENIGN + '\nBOUNDS: bounds are verified carefully here'
        self.assertFalse(_benign_bounds_valid(quote, CODE))


class VerdictExtractionTests(unittest.TestCase):
    """继承 verdict-first 的双标签解析(VERDICT|HYPOTHESIS)。"""

    def test_verdict_type_extracted(self):
        self.assertEqual(_extract_vulnerability_type(
            'VERDICT: buffer overflow\nACTION: {"action":"Stop","reason":"x"}'),
            'Buffer Overflow')

    def test_verdict_benign_is_unknown(self):
        self.assertEqual(_extract_vulnerability_type(BENIGN), 'Unknown')

    def test_verdict_uncertain_is_unknown(self):
        self.assertEqual(_extract_vulnerability_type(
            'VERDICT: uncertain\nACTION: {"action":"Stop","reason":"x"}'), 'Unknown')


class ChallengePromptTests(unittest.TestCase):
    """挑战步 prompt:完整源码 + Prior + DEP 路径 + 显式守卫要求。"""

    def test_contains_full_src_prior_and_challenge(self):
        prompt = build_bounds_challenge_prompt(CODE, make_graph(), [['m', 'g']],
                                               prev_conclusion=BENIGN)
        self.assertIn('FULL SRC:', prompt)
        self.assertIn('memcpy(dst, src, n);', prompt)
        self.assertIn('Prior: VERDICT: no vulnerability detected', prompt)
        self.assertIn('DEP PATHS:', prompt)
        self.assertIn('P1', prompt)
        self.assertIn('not verifiable', prompt)

    def test_no_graph_renders_none(self):
        prompt = build_bounds_challenge_prompt(CODE, None, [], prev_conclusion=BENIGN)
        self.assertIn('(none)', prompt)


class LoopIntegrationTests(unittest.TestCase):
    """循环集成:四条终态路径 + 请求计数 + 挑战步内容。"""

    def test_benign_valid_bounds_single_request(self):
        result, calls = run_loop([VALID_BOUNDS])
        self.assertEqual(len(calls), 1)
        self.assertEqual(result['module_audit']['stop_reason'], 'benign_bounds_proven')
        self.assertEqual(result['decision_status'], 'Benign')
        self.assertTrue(result['module_audit']['asymmetric']['step1']['bounds_valid'])
        self.assertNotIn('challenge_step', result['module_audit']['asymmetric'])

    def test_benign_no_bounds_challenge_then_benign(self):
        result, calls = run_loop([BENIGN, BENIGN])
        self.assertEqual(len(calls), 2)
        audit = result['module_audit']
        self.assertEqual(audit['stop_reason'], 'asymmetric_challenge_final')
        self.assertFalse(audit['asymmetric']['step1']['bounds_valid'])
        self.assertEqual(audit['asymmetric']['challenge_step'], 2)
        self.assertEqual(audit['asymmetric']['challenge_verdict'], 'Unknown')
        self.assertEqual(result['decision_status'], 'Benign')
        self.assertEqual(result['vulnerability_type'], 'Unknown')
        self.assertEqual(result['steps'], 2)
        # step1 走常规 user prompt,step2 才是挑战 prompt(含完整源码)
        self.assertIn('SRC:', calls[0]['messages'][1]['content'])
        self.assertNotIn('FULL SRC:', calls[0]['messages'][1]['content'])
        self.assertIn('FULL SRC:', calls[1]['messages'][1]['content'])
        self.assertIn('memcpy(dst, src, n);', calls[1]['messages'][1]['content'])

    def test_benign_no_bounds_challenge_then_type(self):
        result, calls = run_loop(
            [BENIGN, 'VERDICT: integer overflow\nACTION: {"action":"Stop","reason":"wrap"}'])
        self.assertEqual(len(calls), 2)
        self.assertEqual(result['module_audit']['stop_reason'], 'asymmetric_challenge_final')
        self.assertEqual(result['vulnerability_type'], 'Integer Overflow')
        self.assertEqual(result['decision_status'], 'Vulnerable')

    def test_uncertain_no_bounds_also_challenged(self):
        result, calls = run_loop(
            ['VERDICT: uncertain\nACTION: {"action":"Stop","reason":"x"}', BENIGN])
        self.assertEqual(len(calls), 2)
        self.assertEqual(result['module_audit']['stop_reason'], 'asymmetric_challenge_final')
        self.assertEqual(result['decision_status'], 'Benign')

    def test_type_verdict_step1_confirm_unchanged(self):
        result, calls = run_loop(
            ['VERDICT: buffer overflow\nACTION: {"action":"Stop","reason":"copy"}'])
        self.assertEqual(len(calls), 1)
        self.assertEqual(result['module_audit']['stop_reason'], 'confirmed_first_step')
        self.assertEqual(result['vulnerability_type'], 'Buffer Overflow')
        self.assertEqual(result['decision_status'], 'Vulnerable')

    def test_step2_benign_accepted_even_without_bounds(self):
        # 次步良性即便引用仍无效也采信:不做机械翻转,完整证据下复查即终局
        result, calls = run_loop(
            [BENIGN, BENIGN + '\nBOUNDS: cannot find a guard actually'])
        self.assertEqual(len(calls), 2)
        self.assertFalse(result['module_audit']['asymmetric']['challenge_bounds_valid'])
        self.assertEqual(result['decision_status'], 'Benign')

    def test_single_step_limit_no_challenge(self):
        # max_steps=1 时良性无引用直接生效(无次步可走,不产生额外请求)
        result, calls = run_loop([BENIGN], max_steps=1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(result['module_audit']['stop_reason'], 'expansion_ablation')
        self.assertEqual(result['decision_status'], 'Benign')


if __name__ == '__main__':
    unittest.main(verbosity=2)
