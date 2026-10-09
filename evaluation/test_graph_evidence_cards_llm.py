"""Engineering checks for full-scope cached runtime and paired order."""
import copy
import unittest
import networkx as nx
from evaluation.evaluate_graph_evidence_cards_llm import checked_selection,pair_order,prepare,usage_record,Runtime
import threading
from types import SimpleNamespace
from evaluation.preflight_graph_display import graph_hash,digest


class DisplayLLMRunnerTests(unittest.TestCase):
    def test_unknown_and_partial_usage_not_known_zero(self):
        self.assertFalse(usage_record(None)['usage_known'])
        self.assertIsNone(usage_record(None)['total_tokens'])
        self.assertFalse(usage_record(SimpleNamespace(total_tokens=100))['usage_known'])
        self.assertFalse(usage_record(SimpleNamespace(prompt_tokens=10,completion_tokens=5,total_tokens=99))['usage_known'])
        self.assertTrue(usage_record(SimpleNamespace(prompt_tokens=10,completion_tokens=5,total_tokens=15))['usage_known'])

    def test_balanced_counterbalanced_pair_order(self):
        for rep in (1,2):
            self.assertEqual(sum(pair_order(i,rep)[0]=='control' for i in range(254)),127)
        for idx in range(254):
            self.assertEqual(pair_order(idx,1),list(reversed(pair_order(idx,2))))

    def test_cache_requires_exact_graph_and_candidate_identity(self):
        graph=nx.MultiDiGraph();graph.add_node('a',code='x');graph.add_node('b',code='y');graph.add_edge('a','b',edge_type='DFG')
        paths=[['a','b']];stage=dict(path_graph_hash=graph_hash(graph),candidate_paths_sha256=digest(paths),all_selected_from_candidates=True,topk=paths)
        selected=checked_selection(graph,paths,stage);selected[0].append('other')
        self.assertEqual(stage['topk'],paths)
        with self.assertRaises(ValueError):checked_selection(graph,list(reversed(paths))+[['b','a']],stage)
        graph.nodes['a']['code']='changed'
        with self.assertRaises(ValueError):checked_selection(graph,paths,stage)

    def test_fake_cached_path_rejected(self):
        graph=nx.MultiDiGraph();paths=[['a','b']]
        stage=dict(path_graph_hash=graph_hash(graph),candidate_paths_sha256=digest(paths),all_selected_from_candidates=True,topk=[['missing']])
        with self.assertRaises(ValueError):checked_selection(graph,paths,stage)

    def test_preparation_is_entire_frozen_dataset(self):
        manifest,requests,stages,data=prepare()
        self.assertEqual(len(data),254);self.assertEqual(manifest['planned_results'],1016)
        self.assertEqual(len(requests),508);self.assertEqual(len(stages),508)
        self.assertEqual(set(manifest['sample_order']),set(range(254)))
        self.assertEqual(manifest['candidate_input_changes'],253)
        self.assertEqual(manifest['max_steps'],2);self.assertEqual(manifest['output_cap'],150)

    def test_serialization_profiles_are_thread_local(self):
        runtime=Runtime.__new__(Runtime);runtime.local=threading.local()
        runtime.control_serializer=lambda *a,**k:'legacy'
        runtime.candidate_serializer=lambda *a,**k:'whole'
        observed={}
        def work(profile):
            runtime.local.profile=profile;observed[profile]=runtime.serialize()
        threads=[threading.Thread(target=work,args=(p,)) for p in ('control','display')]
        for thread in threads:thread.start()
        for thread in threads:thread.join()
        self.assertEqual(observed,{'control':'legacy','display':'whole'})
        runtime.local.profile='unknown'
        with self.assertRaises(ValueError):runtime.serialize()


if __name__=='__main__':unittest.main()
