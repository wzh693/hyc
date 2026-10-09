from collections import Counter
import unittest
from unittest.mock import patch
from reasoning.prompts import get_system_prompt, SYSTEM_PROMPT
from evaluation.audit_action_order import verify_pair


class ActionOrderTests(unittest.TestCase):
    def test_flag_off_exact_standard(self):
        with patch.multiple('config',ACTION_BEFORE_REASONING=False,COMPACT_VERDICT_PROMPT=False,
                            TYPE_COVERAGE_PROMPT=False):
            self.assertEqual(get_system_prompt(),SYSTEM_PROMPT)

    def test_only_field_order_changes(self):
        for compact in (False,True):
            with patch.multiple('config',ACTION_BEFORE_REASONING=False,COMPACT_VERDICT_PROMPT=compact,
                                TYPE_COVERAGE_PROMPT=True,TYPE_COVERAGE_ROUTING=False):
                before=get_system_prompt('SRC:\nint x = a[i];')
            with patch.multiple('config',ACTION_BEFORE_REASONING=True,COMPACT_VERDICT_PROMPT=compact,
                                TYPE_COVERAGE_PROMPT=True,TYPE_COVERAGE_ROUTING=False):
                after=get_system_prompt('SRC:\nint x = a[i];')
            self.assertEqual(Counter(before.splitlines()),Counter(after.splitlines()))
            self.assertEqual(len(before.encode()),len(after.encode()))
            self.assertLess(after.index('\nHYPOTHESIS:'),after.index('\nACTION:'))
            self.assertLess(after.index('\nACTION:'),after.index('\nREASONING:'))
            self.assertIn('"no vulnerability detected"',after)
            self.assertIn('Out-of-Bounds Read, Integer Overflow',after)

    def test_rejected_contract_cannot_be_combined(self):
        with patch('config.ACTION_BEFORE_REASONING',True):
            with self.assertRaises(ValueError):get_system_prompt(bounded_output=True)

    def test_offline_pair_verification_rejects_other_changes(self):
        base={'model':'same','max_tokens':150,'messages':[
            {'role':'system','content':'HEAD\nHYPOTHESIS: x\nREASONING: y\nACTION: z'},
            {'role':'user','content':'same source'}]}
        candidate={**base,'messages':[
            {'role':'system','content':'HEAD\nHYPOTHESIS: x\nACTION: z\nREASONING: y'},base['messages'][1]]}
        self.assertTrue(verify_pair(base,candidate))
        with self.assertRaises(ValueError):verify_pair(base,dict(candidate,max_tokens=200))


if __name__=='__main__':unittest.main()
