import unittest
from unittest.mock import patch
from development.converged_display_first_candidate_20261011 import architecture as candidate
from development.converged_graph_v2_candidate_20261010 import architecture as base


class DisplayFirstTests(unittest.TestCase):
    def test_first_round_uses_only_displayed_paths(self):
        with patch.object(base, 'serialize_paths', return_value=('encoded', [('a',)])), \
             patch.object(base, 'context', return_value=('prompt', {})) as original:
            candidate.context('g', [('a',), ('b',)], 'src', 0, base.Settings(), 'state', 1)
            self.assertEqual(original.call_args.args[1], [('a',)])

    def test_incremental_context_unchanged(self):
        with patch.object(base, 'serialize_paths') as packing, \
             patch.object(base, 'context', return_value=('prompt', {})) as original:
            candidate.context('g', [('b',)], 'src', 0, base.Settings(), 'state', 2, 'prior')
            packing.assert_not_called()
            self.assertEqual(original.call_args.args[1], [('b',)])

    def test_no_shared_monkey_patch(self):
        self.assertIsNot(base.context, candidate.context)
        self.assertIs(candidate._run.__globals__['context'], candidate.context)
        self.assertIs(base.run.__globals__['context'], base.context)

    def test_calibrated_net_rejected(self):
        with self.assertRaises(ValueError):
            candidate.run(None, '', 0, None, None, calibration={'status': 'passed'})


if __name__ == '__main__':
    unittest.main()
