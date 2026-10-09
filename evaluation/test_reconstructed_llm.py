import unittest
from evaluation.evaluate_reconstructed_llm import score, select_indices, summarize


class ReconstructedRealTests(unittest.TestCase):
    def test_selection_fixed_balanced_no_replacement(self):
        data = [dict(cwe=c, output=y) for c in ('CWE-125', 'CWE-190', 'CWE-416')
                for y in ('BENIGN', 'VULNERABLE') for _ in range(12)]
        indices = select_indices(data)
        self.assertEqual(indices, select_indices(data))
        self.assertEqual(len(indices), 30)
        for c in ('CWE-125', 'CWE-190', 'CWE-416'):
            for y in ('BENIGN', 'VULNERABLE'):
                self.assertEqual(sum(data[i] == dict(cwe=c, output=y) for i in indices), 5)

    def test_abstentions_remain(self):
        result = score([dict(target=1, prediction=1), dict(target=1, prediction=None),
                        dict(target=0, prediction=None), dict(target=0, prediction=0)])
        self.assertEqual(result['n'], 4)
        self.assertEqual(result['accuracy'], .5)
        self.assertEqual(result['f1'], .5)

    def test_missing_rows_cannot_pass(self):
        manifest = dict(samples=[dict(idx=0, target=1, cwe='X')])
        with self.assertRaises(ValueError): summarize([], [], manifest)

    def test_declared_request_and_trace_accounting(self):
        sample = dict(idx=0, target=1, cwe='X')
        manifest = dict(samples=[sample])
        rows = [dict(sample, repeat=r, prediction=1, tokens_used=10,
                     arbitrate={'reasoning_trace': [{'answer': 'yes'}]}) for r in (1, 2)]
        calls = [dict(idx=0, repeat=r, request=dict(model='deepseek-chat', max_tokens=150),
                      answer='yes', total_tokens=10, usage_known=True) for r in (1, 2)]
        report = summarize(rows, calls, manifest)
        self.assertTrue(report['functional_gate'])
        self.assertFalse(report['quality_sanity_gate'])  # Constant-positive cannot demonstrate discrimination.
        calls[0]['request']['max_tokens'] = 512
        with self.assertRaises(ValueError): summarize(rows, calls, manifest)


if __name__ == '__main__': unittest.main()
