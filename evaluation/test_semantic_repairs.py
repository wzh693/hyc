"""Independent boundary cases for 2026-10-08 repairs; zero external calls."""
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import networkx as nx
from graph.security_net import zero_token_verify
from graph.graph_engine import GraphEngine
from graph.summarize_graph import _adjust_threshold_for_budget, NODE_TOKEN_ESTIMATE
from retrieval.candidate_paths import extract_candidate_paths_from_node
from evaluation.metrics import compute_metrics, compute_long_range_metrics, compute_token_efficiency
from reasoning.reasoning_loop import parse_binary_verdict


class SemanticRepairs(unittest.TestCase):
    def test_unsafe_lexical_inferences_cannot_flip(self):
        cases = ['if(c) free(p); else free(p);',
                 'if(c){free(p);return;} p->x=1;',
                 'read(fd,b,8); system("echo ok");',
                 'char a[100], b[100]; strcpy(a,"a"); strcpy(b,"b");',
                 'av_freep(&p); av_freep(&p);',
                 'free(p); cleanup(); free(p);',
                 'free(p); unknown_call(); return p[0];',
                 'free(p); return 0; p->x=1;',
                 'void a(){free(p);} void b(){p->x=1;}']
        for code in cases:
            with self.subTest(code=code):
                self.assertEqual(zero_token_verify(0, code)[0], 0)

    def test_confirmed_adjacent_evidence_and_abstention(self):
        for code in ('free(p); p->x=1;', 'free(p); return p[0];', 'free(p); free(p);'):
            self.assertEqual(zero_token_verify(0, code)[0], 1)
            self.assertIsNone(zero_token_verify(None, code)[0])
        self.assertEqual(zero_token_verify(0, 'free(p); p=alloc(); return p[0];')[0], 0)

    def test_each_direction_has_capacity_and_prefix_fairness(self):
        g = nx.MultiDiGraph()
        for a,b in (('s','a'),('s','b'),('before','s')):
            g.add_edge(a,b,edge_type='DFG')
        paths = GraphEngine(g).expand_dataflow('s',1,2)
        self.assertIn(['before','s'], paths[:2])
        self.assertLessEqual(len(paths),4)

    def test_cycles_are_not_serialized(self):
        g = nx.MultiDiGraph()
        g.add_edge('a','b',edge_type='DFG'); g.add_edge('b','a',edge_type='DFG')
        paths = GraphEngine(g).expand_dataflow('a',4,20)
        self.assertTrue(all(len(p)==len(set(p)) for p in paths))
        self.assertEqual(len(paths),len({tuple(p) for p in paths}))

    def test_hop_boundary(self):
        g = nx.MultiDiGraph()
        g.add_edge('a','b',edge_type='DFG'); g.add_edge('b','c',edge_type='DFG')
        self.assertEqual(extract_candidate_paths_from_node(g,'a',0),[])
        self.assertEqual(extract_candidate_paths_from_node(g,'a',1),[['a','b']])

    def test_monotone_budget_search(self):
        g = nx.MultiDiGraph(); g.add_nodes_from(map(str,range(100)))
        scores={str(i):1.5+i*.035 for i in range(100)}
        budget=10*NODE_TOKEN_ESTIMATE
        threshold,force=_adjust_threshold_for_budget(g,scores,set(),budget,verbose=False)
        cost=sum(s>=threshold or n in force for n,s in scores.items())*NODE_TOKEN_ESTIMATE
        self.assertLessEqual(cost,budget)
        self.assertGreater(cost,0)

    def test_all_failures_still_have_full_denominator(self):
        m=compute_metrics([0,1],[None,None])
        self.assertEqual((m['n'],m['n_valid'],m['fp'],m['fn']),(2,0,1,1))
        m=compute_metrics([1,0,1],[1,None,None])
        self.assertEqual(m['accuracy'],1/3); self.assertEqual(m['f1'],.5)

    def test_strata_and_cost_retain_failures(self):
        rows=[dict(label=1,prediction=1,hop_count=5,tokens_used=10),
              dict(label=0,prediction=None,hop_count=5,tokens_used=20,error='postprocess')]
        self.assertEqual(compute_long_range_metrics(rows)['long']['accuracy'],.5)
        self.assertEqual(compute_token_efficiency(rows)['total_tokens'],30)

    def test_mixed_verdict_is_not_local_safe(self):
        self.assertIsNone(parse_binary_verdict('The code is vulnerable, but the buffer copy is safe.'))
        self.assertEqual(parse_binary_verdict('no vulnerability detected'),0)

    def test_parser_failure_never_loads_legacy_json(self):
        from graph.pipeline import run_hgl_pipeline
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp)/'nodes.json').write_text('[]')
            with patch('graph.pipeline.build_cpg',side_effect=RuntimeError('parse failed')), \
                    patch('graph.pipeline.load_graph') as load:
                with self.assertRaisesRegex(RuntimeError,'parse failed'):
                    run_hgl_pipeline('source.c','x','sample',tmp,None)
                load.assert_not_called()

    def test_final_fields_do_not_retain_benign_main_verdict(self):
        from graph.pipeline import run_hgl_pipeline
        g=nx.MultiDiGraph();g.add_node('p',code='free(p)',node_type='CALL')
        source='free(p); p->x=1;'
        with tempfile.TemporaryDirectory() as tmp,contextlib.ExitStack() as stack:
            path=Path(tmp)/'source.c';path.write_text(source)
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            for target,value in [('graph.pipeline.build_cpg',tmp),
                                 ('graph.pipeline.find_export_files',('n','e')),
                                 ('graph.pipeline.load_graph',g),('graph.pipeline.summarize_graph',g),
                                 ('graph.pipeline.extract_all_candidate_paths',[['p']]),
                                 ('graph.pipeline.retrieve_topk',[['p']]),
                                 ('learning.scorer.summarize_enabled',False),
                                 ('learning.scorer.path_rank_enabled',False),
                                 ('graph.pipeline.reasoning_loop',dict(vulnerability_type='Unknown',
                                     conclusion='no vulnerability detected',decision_status='Benign',module_audit={}))]:
                stack.enter_context(patch(target,return_value=value))
            for target,value in [('config.GRAPH_SECURITY_NET',False),('config.USE_LLM_ARBITRATION',False),
                                 ('config.USE_ZERO_TOKEN_SECURITY_NET',True),('config.SECURITY_NET_THRESHOLD',4)]:
                stack.enter_context(patch(target,value))
            result=run_hgl_pipeline(str(path),source,'fixture',tmp,None,return_details=True)
        self.assertEqual(result['prediction'],1)
        self.assertEqual(result['decision_status'],'Vulnerable')
        self.assertEqual(result['vulnerability_type'],'Generic Vulnerability')
        self.assertEqual(result['arbitrate']['main_decision_status'],'Benign')
        self.assertEqual(result['arbitrate']['decision_status'],'Vulnerable')

    def test_dotenv_is_loaded_before_prediction_flags(self):
        import builtins
        import os
        import runpy
        original_open=builtins.open
        def opened(path,*a,**kw):
            if str(path).endswith('.env'):
                return io.StringIO('COMPACT_THREE_PART_CONTEXT=0\nUSE_BACKWARD_SLICE=1\n')
            return original_open(path,*a,**kw)
        with patch.dict(os.environ):
            os.environ.pop('COMPACT_THREE_PART_CONTEXT',None)
            os.environ.pop('USE_BACKWARD_SLICE',None)
            with patch('builtins.open',side_effect=opened):
                values=runpy.run_path(str(Path(__file__).resolve().parents[1]/'config.py'))
        self.assertFalse(values['COMPACT_THREE_PART_CONTEXT'])
        self.assertTrue(values['USE_BACKWARD_SLICE'])


if __name__=='__main__': unittest.main()
