import unittest
from evaluation.audit_grouped_completeness import response_facts, source_visibility


class CompletenessAuditTests(unittest.TestCase):
    def test_empty_hypothesis_cannot_absorb_reasoning(self):
        facts=response_facts('HYPOTHESIS:\nREASONING: buffer overflow\nACTION: {"action":"Stop"}')
        self.assertFalse(facts['hypothesis_present'])
        self.assertTrue(facts['action_json_complete'])

    def test_truncated_action_does_not_mean_missing_hypothesis(self):
        facts=response_facts('HYPOTHESIS: buffer overflow\nREASONING: x\nACTION: {"action":"Sto')
        self.assertTrue(facts['hypothesis_present'])
        self.assertTrue(facts['unqualified_positive'])
        self.assertTrue(facts['action_marker_present'])
        self.assertFalse(facts['action_json_complete'])

    def test_valid_json_with_trailing_text(self):
        self.assertTrue(response_facts('HYPOTHESIS: benign\nACTION: {"action":"Stop"}\nextra')['action_json_complete'])

    def test_recorded_slice_checked_against_actual_text(self):
        row={'arbitrate':{'module_audit':{'backward_slice':{
            'enabled':True,'fallback':False,'source_lines':[2]}}}}
        ids,ambiguous,kind=source_visibility('free(p);\nfree(p);','free(p);',row)
        self.assertEqual(ids,{2})
        self.assertFalse(ambiguous)
        self.assertEqual(kind,'recorded_exact_ids')
        with self.assertRaises(ValueError):source_visibility('free(p);\nfree(p);','free(q);',row)

    def test_fallback_duplicate_lines_not_claimed_exact(self):
        row={'arbitrate':{'module_audit':{'backward_slice':{'enabled':True,'fallback':True}}}}
        ids,ambiguous,kind=source_visibility('free(p);\nfree(p);','free(p);',row)
        self.assertFalse(ids)
        self.assertEqual(ambiguous,{1,2})


if __name__=='__main__':unittest.main()
