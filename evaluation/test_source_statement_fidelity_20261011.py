"""Isolated SRC-filter repair tests; no live calls or graph rebuild."""
import importlib.util
import os
from pathlib import Path
import sys
import unittest

from evaluation.test_graph_guided_foundation import verify_foundation

ROOT = Path(__file__).resolve().parents[1]
BASE = verify_foundation()
os.environ.update(BASE['settings'])
SOURCE = ROOT/'development/source_statement_fidelity_candidate_20261011/src'
sys.path.insert(0, str(SOURCE))
from linearization.typed_paths import _slice_source


class FidelityTests(unittest.TestCase):
    def test_only_one_source_file_differs(self):
        import hashlib
        actual = {p.relative_to(SOURCE).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in SOURCE.rglob('*.py')}
        expected = {n.replace('\\','/'):h for n,h in BASE['code_hashes'].items()}
        self.assertEqual(set(actual),set(expected))
        self.assertEqual({n for n in actual if actual[n]!=expected[n]}, {'linearization/typed_paths.py'})

    def test_assignment_and_inc_dec(self):
        for statement in ('n = 7;', 'n++;', '++n;', 'n--;', '--n;', 'n += 2;', 'n -= 2;'):
            with self.subTest(statement=statement):
                self.assertIn(statement,_slice_source('void f(void) {\n'+statement+'\nreturn;\n}',1000))

    def test_leading_deref(self):
        for statement in ('*p = 1;', '*p++;', '**out = *in;', '*p += n;'):
            with self.subTest(statement=statement):
                self.assertIn(statement,_slice_source(statement,1000))

    def test_actual_block_comment_stays_excluded(self):
        source = '/*\n *not_code = 123;\n */\n*p = 1;\n// fake = 7;'
        actual = _slice_source(source,1000)
        self.assertNotIn('not_code',actual)
        self.assertNotIn('fake',actual)
        self.assertIn('*p = 1;',actual)

    def test_comment_end_followed_by_deref(self):
        self.assertEqual(_slice_source('/* comment */ *p = 1;',1000),'*p = 1;')
        self.assertEqual(_slice_source('/* start\n*/ *p = 1;',1000),'*p = 1;')

    def test_budget_unchanged_and_lines_not_invented(self):
        source = '\n'.join(['void f(void) {','return;']+['n = '+str(i)+';' for i in range(100)]+['}'])
        actual = _slice_source(source,100)
        self.assertLessEqual(len(actual),100)
        for line in actual.splitlines():
            self.assertTrue(line == '...' or line in source.splitlines())


if __name__ == '__main__':
    unittest.main()
