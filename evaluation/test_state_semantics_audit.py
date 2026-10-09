"""Test audit integrity, not an endorsement of known incorrect legacy semantics."""
import unittest
from unittest.mock import patch
from evaluation.audit_state_semantics import collect_audit


class StateAuditTests(unittest.TestCase):
    def test_synthetic_audit_has_unique_cases_and_provenance(self):
        report = collect_audit()
        rows = report['cases']
        self.assertEqual(len(rows), len({row['id'] for row in rows}))
        self.assertEqual(report['mismatch_count'], sum(row['mismatch'] for row in rows))
        self.assertTrue(all(row['code'] and row['rationale'] and row['probe'] for row in rows))
        self.assertTrue(all(len(value) == 64 for value in report['production_sha256'].values()))

    def test_audit_never_queries_model(self):
        with patch('reasoning.reasoning_loop.query_llm_with_retry', side_effect=AssertionError('No API')):
            report = collect_audit()
        self.assertIn('STATE:', report['cases'][0]['first_prompt'])
        self.assertIn('PROGRAM STATE UPDATE:', report['second_prompt'])


if __name__ == '__main__':
    unittest.main()
