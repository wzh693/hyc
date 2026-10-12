"""Graph construction/compression invariants; no network or Joern."""
import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from evaluation.test_graph_guided_foundation import verify_foundation

ROOT=Path(__file__).resolve().parents[1]
os.environ.update(verify_foundation()['settings'])
sys.path.insert(0,str(ROOT/'development/graph_integrity_candidate_20261011/src'))
import networkx as nx
from graph.build_cpg import _sanitize_for_joern, _has_defined_function
from graph.load_graph import load_graph_from_dot
from graph.quality import annotate_quality
from graph.dependency_compression import compress_dependencies,dependency_group
from graph.summarize_graph import estimate_token_usage


class IntegrityTests(unittest.TestCase):
    def test_annotations_preserve_coordinates_and_literals(self):
        source='av_cold int f(void) __attribute__((format(printf, 1, 2))) {\nchar *s="av_cold"; // noinline\nint __init = 1;\n}'
        actual=_sanitize_for_joern(source)
        self.assertEqual(len(source),len(actual))
        self.assertEqual([i for i,c in enumerate(source) if c=='\n'],[i for i,c in enumerate(actual) if c=='\n'])
        self.assertIn('"av_cold"',actual)
        self.assertIn('// noinline',actual)
        self.assertIn('int __init = 1;',actual)
        self.assertNotIn('__attribute__',actual)
        self.assertNotIn('format(printf',actual)

    def test_empty_body_rejected(self):
        dot='"1" [label="METHOD" NAME="f" IS_EXTERNAL="false"]\n"2" [label="BLOCK" CODE="{ }"]\n"1" -> "2" [label="AST"]'
        self.assertFalse(_has_defined_function(dot))
        self.assertFalse(_has_defined_function(dot+'\n"3" [label="CALL" CODE="x()"]'))
        self.assertTrue(_has_defined_function(dot+'\n"3" [label="RETURN" CODE="return 1;"]\n"2" -> "3" [label="AST"]'))

    def test_dot_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'input.dot'
            path.write_text('"1" [label="METHOD" NAME="f" FILENAME="stub.h" IS_EXTERNAL="true" TYPE_FULL_NAME="int"]',encoding='utf8')
            with contextlib.redirect_stdout(io.StringIO()): graph=load_graph_from_dot(str(path))
        self.assertEqual(graph.nodes['1']['file'],'stub.h')
        self.assertTrue(graph.nodes['1']['is_external'])

    def test_body_and_line_ownership(self):
        graph=nx.MultiDiGraph()
        graph.add_node('m',node_type='METHOD',name='f',is_external=False)
        graph.add_node('b',node_type='BLOCK')
        graph.add_node('op',node_type='CALL',line_number=2)
        graph.add_edge('m','b',edge_type='AST')
        graph.add_edge('b','op',edge_type='AST')
        code='int f(void) {\nreturn 0;\n}'
        self.assertTrue(annotate_quality(graph,code,code)['usable'])
        self.assertFalse(annotate_quality(graph,code,'// wrapper1\n// wrapper2\n'+code)['usable'])

    def fixture(self):
        graph=nx.MultiDiGraph()
        for n in ('1','2','3','4'):
            graph.add_node(n,node_type='CALL',code='x()',source_origin='original_line_range')
        graph.add_edge('2','3',edge_type='REACHING_DEF')
        graph.add_edge('3','1',edge_type='REACHING_DEF')
        graph.add_edge('2','1',edge_type='AST')
        return graph

    def test_reverse_id_and_ast_shortcut_do_not_lose_dependency(self):
        graph=self.fixture()
        group,_,_=dependency_group(graph,'1')
        self.assertEqual(group,{'1','2','3'})
        compressed=compress_dependencies(graph,None,{'1':100}, {'1'})
        self.assertTrue({'1','2','3'}<=set(compressed))
        self.assertTrue(any(e.get('edge_type')=='REACHING_DEF' for e in compressed['3']['1'].values()))

    def test_budget_omits_whole_group_not_partial(self):
        graph=self.fixture()
        compressed=compress_dependencies(graph,10,{'1':100},{'1'})
        self.assertLessEqual(estimate_token_usage(compressed),12)
        receipt=compressed.graph['dependency_compression']
        self.assertTrue(any(g['seed']=='1' for g in receipt['omitted_groups']))
        for g in receipt['accepted_groups']: self.assertTrue(set(g['nodes'])<=set(compressed))

    def test_unmapped_dependencies_are_unknown_not_guessed(self):
        graph=self.fixture()
        graph.nodes['3']['source_origin']='wrapper_or_unmapped'
        nodes,_,excluded=dependency_group(graph,'1')
        self.assertEqual(nodes,{'1'})
        self.assertEqual(excluded,['3'])

    def test_cfg_is_not_control_dependence(self):
        graph=nx.MultiDiGraph()
        graph.add_edge('guard','read',edge_type='CFG')
        self.assertEqual(dependency_group(graph,'read')[0],{'read'})
        graph.add_edge('guard','read',edge_type='CDG')
        self.assertEqual(dependency_group(graph,'read')[0],{'read','guard'})

    def test_no_fake_edges(self):
        graph=self.fixture()
        compressed=compress_dependencies(graph,None,{},set())
        for a,b,k,attrs in compressed.edges(keys=True,data=True):
            self.assertEqual(attrs,graph[a][b][k])


if __name__=='__main__': unittest.main()
