"""Offline accounting and frozen-selection unit tests; not model quality."""
import unittest
from types import SimpleNamespace
import networkx as nx
from evaluation import run_graph_integrity_llm_20261011 as runner


class RunnerTests(unittest.TestCase):
    def test_windows_manifest_paths_normalize_without_weakening_hashes(self):
        from evaluation.graph_integrity_llm_manifest_20261011 import normalized_hashes
        self.assertEqual(normalized_hashes({'control':{'graph\\pipeline.py':'abc'}}),{'control':{'graph/pipeline.py':'abc'}})
        self.assertNotEqual(normalized_hashes({'control':{'graph\\pipeline.py':'abc'}}),{'control':{'graph/pipeline.py':'changed'}})
        with self.assertRaises(ValueError):normalized_hashes({'control':{'graph\\pipeline.py':'abc','graph/pipeline.py':'abc'}})

    def test_only_declared_bad_graph_is_expected(self):
        row=dict(idx=146,profile='display',error='unusable_source_mapped_function_body')
        self.assertTrue(runner.expected_failure(row))
        for change in (dict(idx=145),dict(profile='control'),dict(error='timeout'),dict(error=None)):
            self.assertFalse(runner.expected_failure(dict(row,**change)))

    def test_null_request_can_be_bound_without_inventing_prompt(self):
        self.assertEqual(runner.request_hash(None),runner.value_hash(None))
        self.assertNotEqual(runner.request_hash(None),runner.request_hash({}))

    def test_selection_bound_to_actual_graph_and_candidates(self):
        graph=nx.MultiDiGraph()
        graph.add_node('a',code='read(buf)');graph.add_node('b',code='n--')
        graph.add_edge('b','a',edge_type='REACHING_DEF')
        stage=dict(graph_sha256=runner.graph_hash(graph),topk=[['b','a']])
        self.assertEqual(runner.checked_selection(graph,[['b','a']],stage),[['b','a']])
        with self.assertRaises(ValueError):runner.checked_selection(graph,[],stage)
        graph.nodes['a']['code']='different'
        with self.assertRaises(ValueError):runner.checked_selection(graph,[['b','a']],stage)

    def test_usage_unknown_not_zero(self):
        self.assertTrue(runner.usage_record(SimpleNamespace(prompt_tokens=3,completion_tokens=2,total_tokens=5))['usage_known'])
        self.assertFalse(runner.usage_record(None)['usage_known'])
        self.assertFalse(runner.usage_record(SimpleNamespace(prompt_tokens=3,completion_tokens=2,total_tokens=6))['usage_known'])

    def test_adapter_one_http_attempt_no_hidden_retry(self):
        client=runner.DirectClient.__new__(runner.DirectClient)
        client.key='test';client.endpoint='https://api.deepseek.com/v1'
        calls=[]
        def post(*args,**kwargs):
            calls.append((args,kwargs))
            return SimpleNamespace(raise_for_status=lambda:None,json=lambda:dict(model='actual',usage=dict(total_tokens=5,prompt_tokens=3,completion_tokens=2),choices=[dict(finish_reason='stop',message=dict(content='answer'))]))
        client.http=SimpleNamespace(post=post)
        result=client.create(model='deepseek-chat',max_tokens=150)
        self.assertEqual(len(calls),1);self.assertEqual(result.model,'actual')
        self.assertEqual(result.usage.total_tokens,5)


if __name__=='__main__':unittest.main()
