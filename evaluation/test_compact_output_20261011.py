import json
import unittest
from development.converged_compact_output_candidate_20261011 import architecture as compact
from development.converged_graph_v2_candidate_20261010 import architecture as base
from development.converged_graph_v2_candidate_20261010.test_architecture import graph, SOURCE
from development.converged_display_first_candidate_20261011 import architecture as evidence


class CompactContractTests(unittest.TestCase):
    def execute(self, replies, cfg=base.Settings()):
        iterator = iter(replies)
        return compact.run(graph(), SOURCE, 0, lambda g,s:{n:.25 for n in g},
            lambda **req:dict(text=json.dumps(next(iterator), separators=(',',':')), finish_reason='stop'), cfg)

    def test_only_contract_replaced(self):
        self.assertEqual(compact.SYSTEM.replace(compact._NEW_CONTRACT, compact._OLD_CONTRACT), base.SYSTEM)
        self.assertIs(compact._run.__globals__['decode'], base.decode)
        self.assertIs(compact._run.__globals__['context'], evidence.context)
        self.assertEqual(base.run.__globals__['SYSTEM'], base.SYSTEM)

    def test_short_stop_all_verdicts(self):
        for verdict, prediction in [('Vulnerable',1),('Benign',0),('Uncertain',None)]:
            response = dict(verdict=verdict,action='Stop',reason='Evidence missing' if prediction is None else 'Graph evidence')
            self.assertLess(len(json.dumps(response,separators=(',',':')).encode()), 110)
            self.assertEqual(self.execute([response])['final_pred'], prediction)

    def test_three_step_query_still_works(self):
        result = self.execute([
            dict(verdict='Uncertain',action='Query',reason='Length origin missing',target='3',edge_types=['REACHING_DEF']),
            dict(verdict='Uncertain',action='Query',reason='Guard missing',target='3',edge_types=['CDG']),
            dict(verdict='Vulnerable',action='Stop',reason='Unchecked size')],
            base.Settings(graph_budget=12,minimum_nodes=0,path_chars=2000))
        self.assertEqual(len(result['trace']),3)
        self.assertEqual(result['final_pred'],1)

    def test_short_hypothesis_preserves_existing_early_stop(self):
        response = dict(verdict='Vulnerable',action='Query',reason='Guard missing',hypothesis='bounds',
                        target='3',edge_types=['REACHING_DEF'])
        result = self.execute([response, response], base.Settings(graph_budget=12,minimum_nodes=0,path_chars=2000))
        self.assertEqual(len(result['trace']),2)
        self.assertEqual(result['final_pred'],1)

    def test_illegal_query_target_and_edge_rejected(self):
        for target, edges in [('unknown',['CDG']),('3',['AST'])]:
            result = self.execute([dict(verdict='Uncertain',action='Query',reason='Missing',target=target,edge_types=edges)])
            self.assertEqual(len(result['trace']),1)
            self.assertIn('query_rejected',result['trace'][0])

    def test_no_partial_json_salvage(self):
        for text in ('{"verdict":"Vulnerable"', '```json\n{"verdict":"Benign"}\n```'):
            result = compact.run(graph(), SOURCE, 0,lambda g,s:{n:.25 for n in g},
                lambda **req:dict(text=text,finish_reason='stop'))
            self.assertIsNone(result['final_pred'])

    def test_length_even_with_complete_json_abstains(self):
        result = compact.run(graph(), SOURCE, 0,lambda g,s:{n:.25 for n in g},
            lambda **req:dict(text='{"verdict":"Vulnerable","action":"Stop"}',finish_reason='length'))
        self.assertIsNone(result['final_pred'])

    def test_calibrated_net_forbidden(self):
        with self.assertRaises(ValueError):
            compact.run(None,'',0,None,None,calibration={'status':'passed'})


if __name__ == '__main__':
    unittest.main()
