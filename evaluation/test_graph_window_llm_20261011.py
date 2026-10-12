import unittest
from types import SimpleNamespace
import networkx as nx
from evaluation import run_graph_window_llm_20261011 as runner


class RunnerTests(unittest.TestCase):
    def test_receipt_usage(self):
        self.assertTrue(runner.usage_record(SimpleNamespace(prompt_tokens=3,completion_tokens=2,total_tokens=5))['usage_known'])
        self.assertFalse(runner.usage_record(None)['usage_known'])

    def test_selection_bound_to_graph_and_candidates(self):
        graph=nx.MultiDiGraph();graph.add_node('1',code='x');graph.add_node('2',code='y');graph.add_edge('1','2',edge_type='DFG')
        stage=dict(graph_sha256=runner.graph_hash(graph),topk=[['1','2']])
        self.assertEqual(runner.checked_selection(graph,[['1','2']],stage),[['1','2']])
        with self.assertRaises(ValueError):runner.checked_selection(graph,[],stage)
        graph.nodes['1']['code']='changed'
        with self.assertRaises(ValueError):runner.checked_selection(graph,[['1','2']],stage)

    def test_response_adapter_no_extra_calls(self):
        client=runner.DirectClient.__new__(runner.DirectClient);client.key='test';client.endpoint='https://api.deepseek.com/v1'
        captured=[]
        def post(*a,**k):
            captured.append((a,k))
            return SimpleNamespace(raise_for_status=lambda:None,json=lambda:dict(model='actual',usage=dict(total_tokens=5,prompt_tokens=3,completion_tokens=2),choices=[dict(finish_reason='stop',message=dict(content='answer'))]))
        client.http=SimpleNamespace(post=post)
        result=client.create(model='deepseek-chat',max_tokens=150)
        self.assertEqual(len(captured),1);self.assertEqual(result.model,'actual');self.assertEqual(result.usage.total_tokens,5)


if __name__=='__main__':unittest.main()
