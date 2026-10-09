"""Local reconstruction harness checks; no models or dataset preparation."""
import hashlib
import json
import re
from pathlib import Path
import tempfile
import unittest

from evaluation.audit_type_coverage_baseline import memoized_search, metrics, saved_rows, summarize_replays, validate_trace, verify


class BaselineAuditTests(unittest.TestCase):
    def test_regex_memoization_preserves_match_span_and_none(self):
        cached = memoized_search(re.search)
        for pattern, value, flags in [(r'\bfree\b', 'freeall free(p)', 0),
                                       ('UAF', 'uaf', re.I), ('missing', 'safe', 0),
                                       (re.compile('x'), 'xx', 0), (b'a', bytearray(b'ab'), 0)]:
            for _ in range(2):
                actual, expected = cached(pattern, value, flags), re.search(pattern, value, flags)
                self.assertEqual(actual is None, expected is None)
                if expected is not None:
                    self.assertEqual((actual.group(), actual.span()), (expected.group(), expected.span()))
        self.assertGreater(cached.cache_info().hits, 0)

    def test_uncertain_rows_remain_in_denominator(self):
        value = metrics([dict(target=1, prediction=1), dict(target=0, prediction=0),
                         dict(target=1, prediction=None), dict(target=0, prediction=None)])
        self.assertEqual(value['n'], 4)
        self.assertEqual(value['accuracy'], .5)
        self.assertEqual(value['f1'], .5)
        self.assertEqual(value['uncertain'], 2)

    def test_tampered_and_escaping_files_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/'config.py'
            source.write_text('BASE = 1\n', encoding='utf8')
            good = hashlib.sha256(source.read_bytes()).hexdigest()
            verify(root, {'config.py': good})
            with self.assertRaises(ValueError): verify(root, {'config.py': 'bad'})
            with self.assertRaises(ValueError): verify(root, {'../config.py': good})

    def test_duplicate_saved_rows_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'results.jsonl'
            path.write_text(json.dumps({'idx': 0})+'\n'+json.dumps({'idx': 0})+'\n', encoding='utf8')
            with self.assertRaises(ValueError): saved_rows(path, 2)

    def test_missing_trace_is_not_silently_replayed(self):
        with self.assertRaises(ValueError): validate_trace({'prediction': 1})
        with self.assertRaises(ValueError): validate_trace({'arbitrate': {'reasoning_trace': [{'answer': 'yes'}]}})

    def test_aggregate_keeps_prompt_mismatch_and_failed_row(self):
        summaries = summarize_replays([
            dict(history='type_coverage_history', target=1, prediction=1, historical_prediction=1,
                 user_prompt_equal=False, system_prompt_equal=True, same_step_count=True, output_cap_valid=True),
            dict(history='type_coverage_history', target=0, prediction=None, historical_prediction=0, error='failed'),
        ])
        value = summaries['type_coverage_history']
        self.assertEqual(value['n'], 2)
        self.assertEqual(value['errors'], 1)
        self.assertEqual(value['same_first_user_prompt'], 0)
        self.assertEqual(value['saved_answer_replay_metrics_NOT_new_llm_score']['accuracy'], .5)


if __name__ == '__main__':
    unittest.main()
