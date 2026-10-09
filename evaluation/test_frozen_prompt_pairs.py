"""Frozen experiments must not leak labels or change source evidence."""
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from evaluation.evaluate_frozen_prompts import run_pair


class FrozenPairTests(unittest.TestCase):
    def row(self):
        prompt = ('SRC:\nsize = n * width;\n\nDEP PATHS:\nsize -> memcpy\n\n'
                  'EXPLORATION STATE:\nStep: 0\n  Data Flow expanded: False\n\n'
                  'Analyze SRC slice, verify with paths. Answer now.')
        return {'idx':0, 'target':0, 'arbitrate': {'reasoning_trace':[{
            'user_prompt':prompt, 'answer':'HYPOTHESIS: integer overflow',
            'tokens_used':100, 'completion_tokens':10, 'finish_reason':'stop', 'model':'mock'}]}}

    def test_compact_initial_state_keeps_source_and_output_budget(self):
        row = self.row()
        response = SimpleNamespace(model='mock',
            usage=SimpleNamespace(total_tokens=100, completion_tokens=10),
            choices=[SimpleNamespace(finish_reason='stop',
                                     message=SimpleNamespace(content='HYPOTHESIS: integer overflow'))])
        create = Mock(return_value=response)
        client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
        with patch('evaluation.evaluate_frozen_prompts.create_client', return_value=client):
            records = run_pair(row, 'size = n * width;', 0, 'covered_compact_state')
        self.assertEqual(create.call_count, 2)
        a, b = [call.kwargs for call in create.call_args_list]
        self.assertEqual(a['messages'][0], b['messages'][0])
        self.assertEqual(a['max_tokens'], b['max_tokens'])
        prefix = lambda x:x['messages'][1]['content'].split('EXPLORATION STATE:')[0]
        self.assertEqual(prefix(a), prefix(b))
        self.assertTrue(all(r['prediction']==1 for r in records))  # target is not a prediction input
        self.assertEqual(records[0]['source_prompt_sha256'], records[1]['source_prompt_sha256'])

    def test_unchanged_evidence_reuses_one_saved_answer_for_both_sides(self):
        row = self.row()
        row['experimental_user_prompt'] = row['arbitrate']['reasoning_trace'][0]['user_prompt']
        with patch('evaluation.evaluate_frozen_prompts.create_client') as client:
            records = run_pair(row, 'size = n * width;', 0, 'focused_anchors')
        client.assert_not_called()
        self.assertTrue(all(r['reused_unchanged_evidence'] for r in records))
        self.assertEqual(records[0]['prediction'], records[1]['prediction'])


if __name__ == '__main__':
    unittest.main()
