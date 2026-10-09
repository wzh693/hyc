import unittest
from evaluation.evaluate_graph_read_slice import source_only_pair, summary


def request(src):
    return dict(model='deepseek-chat', temperature=0, max_tokens=150,
                messages=[dict(role='system',content='same'),dict(role='user',content='SRC:\n'+src+'\n\nDEP PATHS:\np\n\nSTATE:\ns')])


class ReadSliceRunnerTests(unittest.TestCase):
    def test_only_source_allowed_and_budget_bounded(self):
        self.assertTrue(source_only_pair(request('old'),request('new'),'source'))
        with self.assertRaises(ValueError): source_only_pair(request('old'),request('x'*601),'source')
        b=request('new'); b['messages'][0]['content']='changed'
        with self.assertRaises(ValueError): source_only_pair(request('old'),b,'source')

    def test_failed_rows_kept_and_no_gain_claim(self):
        s=dict(idx=0,sample_id='s',group_id='g',cwe='CWE-125',target=1,source_sha256='h')
        manifest=dict(samples=[s],profiles=['control','read_slice'],repeats=[1,2],first_request_sha256={},
                      bootstrap_seed=20261009,bootstrap_draws=2000,scope='unit-only')
        rows=[dict(s,profile=p,repeat=r,prediction=None,error='failure',tokens_used=0) for p in manifest['profiles'] for r in (1,2)]
        result=summary(rows,[],manifest)
        self.assertEqual(result['scheduled_results'],4)
        self.assertEqual(result['metrics']['read_slice/r1']['fn'],1)
        self.assertFalse(result['functional_gate']); self.assertFalse(result['exploratory_support'])
        with self.assertRaises(ValueError): summary(rows[:-1],[],manifest)


if __name__ == '__main__': unittest.main()
