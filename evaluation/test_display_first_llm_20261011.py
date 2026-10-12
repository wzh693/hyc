import unittest
from evaluation.run_display_first_llm_20261011 import bounded_call, response_usage


class CallTests(unittest.TestCase):
    def test_retry_bound_and_all_failures_retained(self):
        receipts = []
        def fail(request):
            raise TimeoutError('fixture timeout')
        with self.assertRaises(RuntimeError):
            bounded_call({'max_tokens':150}, fail, receipts.append, sleep=lambda x:None)
        self.assertEqual([r['attempt'] for r in receipts], [1,2,3])
        self.assertTrue(all(not r['usage_known'] for r in receipts))

    def test_success_not_retried(self):
        receipts = []
        raw = dict(model='fixture', choices=[dict(message={'content':'{}'},finish_reason='length')],
            usage=dict(prompt_tokens=2, completion_tokens=3,total_tokens=5))
        value = bounded_call({}, lambda req:raw, receipts.append)
        self.assertEqual(len(receipts), 1)
        self.assertEqual(value['finish_reason'], 'length')
        self.assertTrue(receipts[0]['usage_known'])

    def test_invalid_usage_unknown(self):
        self.assertFalse(response_usage({})['usage_known'])
        self.assertFalse(response_usage(dict(prompt_tokens=2,completion_tokens=3,total_tokens=6))['usage_known'])


if __name__ == '__main__':
    unittest.main()
