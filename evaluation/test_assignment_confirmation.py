import unittest
from unittest.mock import patch
from evaluation.check_assignment_evidence import compare_prompts
from evaluation.evaluate_wiring_quality import score,summarize
import evaluation.evaluate_wiring_quality as runner


class AssignmentConfirmationTests(unittest.TestCase):
    def test_only_src_is_allowed_to_change(self):
        a='SRC:\na=1;\n\nDEP PATHS:\nx\nSTATE:\np=alive'
        b=a.replace('a=1;','a=1;\nb++;')
        self.assertTrue(compare_prompts(a,b)['changed'])
        self.assertFalse(compare_prompts(a,a)['changed'])
        with self.assertRaises(ValueError):compare_prompts(a,b.replace('p=alive','p=freed'))

    def test_exact_two_arm_two_repeat_schedule(self):
        profiles={'control':(0,0,0),'assignment_evidence':(0,0,0)}
        samples=[dict(sample_id='a',group_id='g',target=1)]
        rows=[dict(samples[0],profile=p,repeat=r,prediction=1) for p in profiles for r in (1,2)]
        with patch.object(runner,'PROFILES',profiles),patch.object(runner,'REPEAT_PROFILES',tuple(profiles)):
            result=summarize(rows,dict(samples=samples),[],bootstrap=100)
            self.assertEqual(len(result['metrics']),4)
            self.assertFalse(result['auto_promoted'])
            with self.assertRaises(ValueError):summarize(rows[:-1],dict(samples=samples),[],bootstrap=100)


if __name__=='__main__':unittest.main()
