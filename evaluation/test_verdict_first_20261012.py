"""verdict_first_candidate_20261012 输出契约(判定先行)的单元回归;须在隔离进程中运行(见 run_tests_isolated.py)。"""
import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'development/verdict_first_candidate_20261012/src'
CONTROL = ROOT/'development/type_coverage_reconstructed_20261008/src'
sys.path.insert(0, str(SOURCE))

from reasoning.prompts import SYSTEM_PROMPT, _summarize_prior, get_system_prompt  # noqa: E402
from reasoning.reasoning_loop import _extract_vulnerability_type, _conclusion_is_benign  # noqa: E402


class ContractFormatTests(unittest.TestCase):
    """SYSTEM 契约:判定先行两行格式,首行与对照逐字节一致。"""

    def test_verdict_line_is_first_line_of_format(self):
        lines = SYSTEM_PROMPT.splitlines()
        fmt = next(i for i, l in enumerate(lines) if l.startswith('Format:'))
        self.assertTrue(lines[fmt + 1].startswith('VERDICT:'))
        self.assertTrue(lines[fmt + 2].startswith('ACTION:'))

    def test_no_observation_or_reasoning_line_in_contract(self):
        fmt = SYSTEM_PROMPT.split('\nFormat:', 1)[1]
        self.assertNotIn('OBSERVATION:', fmt)
        self.assertNotIn('\nREASONING:', fmt)

    def test_first_line_identical_to_control(self):
        control = (CONTROL/'reasoning/prompts.py').read_text(encoding='utf8')
        import re
        m = re.search(r'SYSTEM_PROMPT = """(.+?)\nFormat', control, re.S)
        self.assertIsNotNone(m)
        self.assertEqual(SYSTEM_PROMPT.split('\nFormat:', 1)[0], m.group(1))

    def test_reason_cap_in_contract(self):
        self.assertIn('"reason":"at most 32 ASCII chars"', SYSTEM_PROMPT)

    def test_format_marker_preserved_for_derived_prompts(self):
        # "Format:" 行首保留:COMPACT/BOUNDED 派生常量的 split 不受影响
        self.assertIn('\nFormat:', SYSTEM_PROMPT)
        from reasoning.prompts import COMPACT_SYSTEM_PROMPT, BOUNDED_OBSERVATION_PROMPT
        for derived in (COMPACT_SYSTEM_PROMPT, BOUNDED_OBSERVATION_PROMPT):
            self.assertIn('HYPOTHESIS:', derived)  # 派生(off路径)格式不变


class VerdictLineParsingTests(unittest.TestCase):
    """判定行解析:VERDICT 与 HYPOTHESIS 双标签等价。"""

    def test_verdict_line_extracts_specific_types(self):
        for t in ('Buffer Overflow', 'Use-After-Free', 'Integer Overflow',
                  'Null Deref', 'Memory Leak', 'Double Free'):
            self.assertEqual(
                _extract_vulnerability_type(f'VERDICT: {t}\nACTION: {{"action":"Stop","reason":"ok"}}', is_final=True),
                t if t != 'Null Deref' else 'Null Pointer Dereference',
                t)

    def test_verdict_line_benign(self):
        self.assertEqual(_extract_vulnerability_type('VERDICT: no vulnerability detected\nACTION: {"action":"Stop","reason":"guarded"}', is_final=True), 'Unknown')

    def test_verdict_line_uncertain_is_unknown(self):
        # 三态:uncertain 不构成具体类型 -> 不触发 Step1ConfirmStop,
        # 由 step-2/图信号兜底机器处理
        self.assertEqual(_extract_vulnerability_type('VERDICT: uncertain\nACTION: {"action":"ExpandDFG","reason":"need dep"}', is_final=False), 'Unknown')
        self.assertEqual(_extract_vulnerability_type('VERDICT: uncertain\nACTION: {"action":"Stop","reason":"none"}', is_final=True), 'Unknown')

    def test_legacy_hypothesis_line_still_parses(self):
        # 模型不遵守契约时的防御回退
        self.assertEqual(_extract_vulnerability_type('HYPOTHESIS: Buffer Overflow\nACTION: {"action":"Stop","reason":"x"}', is_final=True), 'Buffer Overflow')
        self.assertEqual(_extract_vulnerability_type('OBSERVATION: stuff\nHYPOTHESIS: no vulnerability detected\nREASONING: r\nACTION: {"action":"Stop","reason":"x"}', is_final=True), 'Unknown')

    def test_conclusion_is_benign_on_verdict_line(self):
        self.assertTrue(_conclusion_is_benign('VERDICT: no vulnerability detected\nACTION: {"action":"Stop","reason":"safe"}'))
        self.assertFalse(_conclusion_is_benign('VERDICT: Buffer Overflow'))
        self.assertFalse(_conclusion_is_benign('VERDICT: uncertain'))
        # 注:"correctly/properly"良性词扩充是 verdict_fidelity 候选(BUG-B)的
        # 变量,不属于本候选——这里词表行为须与对照一致
        self.assertFalse(_conclusion_is_benign('VERDICT: the length check is correctly applied'))
        self.assertEqual(_conclusion_is_benign('HYPOTHESIS: the length check is correctly applied'),
                         _conclusion_is_benign('VERDICT: the length check is correctly applied'))


class TruncationSurvivalTests(unittest.TestCase):
    """核心价值:截断只损失无关文本,判定行与 ACTION 行存活。"""

    def test_verdict_and_action_survive_mid_narrative_cut(self):
        # 模型违规在两行后追加叙述,150-token 截断切在叙述中间
        answer = ('VERDICT: Buffer Overflow\n'
                  'ACTION: {"action":"Stop","reason":"memcpy without bounds check"}\n'
                  'Additionally the loop iterates over naddrs while writing to addrs without verifying the buffer capacit')
        self.assertEqual(_extract_vulnerability_type(answer, is_final=True), 'Buffer Overflow')
        import re
        self.assertIsNotNone(re.search(r'ACTION:\s*\{[^}]*"action"\s*:\s*"[^"]+"[^}]*\}', answer, re.I))

    def test_verdict_survives_when_action_line_cut(self):
        # 极端情形:ACTION 行自身被切,判定行仍完整可解析
        answer = 'VERDICT: no vulnerability detected\nACTION: {"action":"Expan'
        self.assertEqual(_extract_vulnerability_type(answer, is_final=True), 'Unknown')
        self.assertTrue(_conclusion_is_benign(answer))


class PriorSummaryTests(unittest.TestCase):
    """_summarize_prior:新格式提取 VERDICT+ACTION,旧格式回退 HYPOTHESIS。"""

    def test_new_format_summary(self):
        out = ('VERDICT: Integer Overflow\n'
               'ACTION: {"action":"ExpandDFG","reason":"need mult provenance"}')
        s = _summarize_prior(out)
        self.assertIn('VERDICT: Integer Overflow', s)
        self.assertIn('ACTION:', s)
        self.assertNotIn('REASONING', s)

    def test_legacy_format_summary_keeps_verdict_semantics(self):
        out = ('HYPOTHESIS: no vulnerability detected\n'
               'REASONING: the copy is guarded\n'
               'ACTION: {"action":"Stop","reason":"done"}')
        s = _summarize_prior(out)
        self.assertIn('VERDICT: no vulnerability detected', s)
        self.assertIn('ACTION:', s)

    def test_budget_respected(self):
        out = ('VERDICT: ' + 'x'*200 + '\n' + 'ACTION: ' + 'y'*200)
        s = _summarize_prior(out, limit=150)
        self.assertLessEqual(len(s), 150)


class IsolationTests(unittest.TestCase):
    """单变量纪律:除 prompts.py/reasoning_loop.py 外,其余文件与对照逐字节一致。"""

    def test_only_two_files_differ_from_control(self):
        changed = []
        for p in sorted(CONTROL.rglob('*')):
            if not p.is_file() or '__pycache__' in str(p):
                continue
            q = SOURCE/p.relative_to(CONTROL)
            self.assertTrue(q.exists(), f'missing {p.relative_to(CONTROL)}')
            h1 = hashlib.sha256(p.read_bytes()).hexdigest()
            h2 = hashlib.sha256(q.read_bytes()).hexdigest()
            if h1 != h2:
                changed.append(str(p.relative_to(CONTROL)).replace('\\', '/'))
        self.assertEqual(sorted(changed), ['reasoning/prompts.py', 'reasoning/reasoning_loop.py'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
