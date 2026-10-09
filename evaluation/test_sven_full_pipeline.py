import unittest
from evaluation.evaluate_sven_full_pipeline import PROFILES, source_groups, summarize
from linearization.source_mapping import source_line_offset
from sven_eval.data.wrap_slice import wrap_slice


class FullSvenTests(unittest.TestCase):
    def test_macro_multiline_and_incomplete_signature(self):
        macro = 'API(const char *) f(int x,\n int y)\n return x;\n'
        wrapped, ok, _ = wrap_slice(macro, 'f.c')
        self.assertTrue(ok)
        self.assertIn(' int y) {', wrapped)
        self.assertNotIn('f(int x, {', wrapped)
        self.assertLess(source_line_offset(macro, wrapped), len(wrapped.splitlines()))
        incomplete = 'int f(int x,\n if (x) {\n }\n return x;\n'
        wrapped, ok, reason = wrap_slice(incomplete, 'f.c')
        self.assertIn('incomplete signature', reason)
        self.assertIn('// int f(int x,', wrapped)
        self.assertIn(' if (x) {\n }', wrapped)
        self.assertLess(source_line_offset(incomplete, wrapped), len(wrapped.splitlines()))
        self.assertGreater(source_line_offset(incomplete, wrapped.replace('return x;', 'return 0;')), len(wrapped.splitlines()))

    def test_signature_brace_mapping(self):
        code = 'int f(int n)\n  return n;\n'
        wrapped = 'typedef int T;\nint f(int n) {\n  return n;\n}\n'
        self.assertEqual(source_line_offset(code, wrapped), 1)
        code_multi = 'int f(\n  int n)\n  return n;\n'
        wrapped_multi = 'typedef int T;\nint f(\n  int n) {\n  return n;\n}\n'
        self.assertEqual(source_line_offset(code_multi, wrapped_multi), 1)
        self.assertGreater(source_line_offset(code, wrapped.replace('return n;', 'return 0;')), len(wrapped.splitlines()))

    def test_ambiguous_and_control_wrapper_rejected(self):
        code = 'int f(int n)\n  return n;\n'
        wrapped = 'int f(int n) {\n  return n;\n}\n'
        self.assertGreater(source_line_offset(code, wrapped+wrapped), len((wrapped+wrapped).splitlines()))
        control = 'if (n)\n  return n;\n'
        wrapped_control = 'if (n) {\n  return n;\n}\n'
        self.assertGreater(source_line_offset(control, wrapped_control), len(wrapped_control.splitlines()))

    def test_source_and_family_union(self):
        rows = [{'input': 'a', 'file_name': 'f'}, {'input': 'b', 'file_name': 'f'},
                {'input': 'b', 'file_name': 'g'}, {'input': 'c', 'file_name': 'h'}]
        groups = source_groups(rows)
        self.assertEqual(groups[0], groups[2])
        self.assertNotEqual(groups[0], groups[3])

    def test_full_denominator_conflicts_and_failed_usage(self):
        samples = [{'idx': i, 'target': i, 'group_id': 'g', 'source_sha256': 'same', 'cwe': 'CWE-X'} for i in range(2)]
        rows = [dict(s, profile=p, prediction=None if s['idx'] else 0, error='test' if s['idx'] else '')
                for p in PROFILES for s in samples]
        calls = [{'profile': 'control', 'error': 'retry', 'usage_available': False},
                 {'profile': 'control', 'total_tokens': 20, 'usage_available': True}]
        report = summarize(rows, calls, samples, bootstrap=20)
        self.assertEqual(report['metrics']['control']['accuracy'], .5)
        self.assertEqual(report['metrics']['control']['fn_including_abstentions'], 1)
        self.assertEqual(report['api_accounting']['control']['mean_actual_tokens'], 10)
        self.assertEqual(report['api_accounting']['control']['calls_without_usage'], 1)
        self.assertEqual(report['source_groups']['conflicting_exact_sources'], 1)
        self.assertEqual(report['source_groups']['consistent_exact_lowest_index_supplement']['control']['n'], 0)

    def test_missing_and_duplicate_receipts_rejected(self):
        samples = [{'idx': 0, 'target': 1, 'group_id': 'g', 'source_sha256': 's', 'cwe': 'CWE-X'}]
        row = dict(samples[0], profile='control', prediction=1)
        with self.assertRaises(ValueError):
            summarize([row], [], samples)
        with self.assertRaises(ValueError):
            summarize([row, row], [], samples)


if __name__ == '__main__':
    unittest.main()
