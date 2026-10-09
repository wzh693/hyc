import unittest
from evaluation.evaluate_sven_budget import budget_request,compare_requests,summarize
from evaluation.audit_sven_budget import dataset_facts


class SvenBudgetTests(unittest.TestCase):
    def test_only_output_ceiling_changes(self):
        original={'max_tokens':150,'model':'test','messages':[{'role':'user','content':'fixed'}]}
        candidate=budget_request(original,512)
        compare_requests(original,candidate)
        self.assertEqual(original['max_tokens'],150)
        with self.assertRaises(ValueError):compare_requests(original,dict(candidate,model='other'))
        with self.assertRaises(ValueError):budget_request(dict(original,max_tokens=999),512)

    def test_failed_rows_full_denominator_and_spent_tokens(self):
        samples=[{'idx':i,'target':i,'group_id':'g','cwe':'X'} for i in range(2)]
        manifest={'samples':samples,'profiles':{'control':150,'output512':512},'repeats':[1,2]}
        rows=[dict(s,profile=p,repeat=r,prediction=None,error='mock',tokens_used=0)
              for s in samples for p in manifest['profiles'] for r in manifest['repeats']]
        rows[0]['tokens_used']=8
        calls=[dict(samples[0],profile='control',repeat=1,total_tokens=8,
                    error='post-response exception',usage_known=True)]
        # Error receipt with known spent usage is still counted in the row/cost.
        report=summarize(rows,calls,manifest,bootstrap=20)
        self.assertEqual(report['scheduled_results'],8)
        self.assertEqual(report['metrics']['control/r1']['accuracy'],0)
        self.assertEqual(report['metrics']['control/r1']['n'],2)
        self.assertEqual(report['api_accounting']['control/r1']['total_tokens'],8)
        self.assertFalse(report['quality_support'])
        with self.assertRaises(ValueError):summarize(rows[:-1],calls,manifest,bootstrap=20)
        with self.assertRaises(ValueError):summarize(rows,[],manifest,bootstrap=20)

    def test_correlated_conflicting_rows_not_deleted(self):
        data=[{'input':'same','file_name':'f','output':'VULNERABLE','cwe':'X'},
              {'input':'same','file_name':'g','output':'BENIGN','cwe':'X'},
              {'input':'other','file_name':'g','output':'BENIGN','cwe':'X'}]
        facts=dataset_facts(data)
        self.assertEqual(facts['rows'],3)
        self.assertEqual(facts['exact_sources'],2)
        self.assertEqual(facts['family_union_groups'],1)
        self.assertEqual(facts['conflicting_rows'],2)
        self.assertAlmostEqual(facts['source_only_deterministic_accuracy_ceiling'],2/3)


if __name__=='__main__':unittest.main()
