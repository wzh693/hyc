"""Independent semantic counterexamples; zero API and no source modification."""
import contextlib
import importlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from evaluation.test_graph_guided_foundation import verify_foundation

BASE = verify_foundation()
os.environ.update(BASE['settings'])
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'development/type_coverage_reconstructed_20261008/src'))
import networkx as nx
from graph.build_cpg import _has_defined_function
from graph.load_graph import load_graph_from_dot
summary = importlib.import_module('graph.summarize_graph')
from retrieval.candidate_paths import extract_candidate_paths_from_node
from retrieval.path_ranker import _compute_variable_lifecycle_completeness
from linearization.typed_paths import _slice_source, _collect_graph_anchors, _labeled_compact_path


class Recheck(unittest.TestCase):
    def test_function_gate_does_not_require_operations(self):
        dot = ('"1" [label="METHOD" NAME="f" IS_EXTERNAL="false"]\n'
               '"2" [label="BLOCK" CODE="{ }"]\n'
               '"1" -> "2" [label="AST"]')
        self.assertTrue(_has_defined_function(dot))

    def test_file_provenance_not_loaded(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'probe.dot'
            target.write_text('"1" [label="CALL" CODE="free(p)" FILENAME="stub.h" IS_EXTERNAL="true"]', encoding='utf8')
            with contextlib.redirect_stdout(io.StringIO()):
                graph = load_graph_from_dot(str(target))
            self.assertNotIn('file', graph.nodes['1'])
            self.assertNotIn('is_external', graph.nodes['1'])

    def fixture(self):
        graph = nx.MultiDiGraph()
        for nid, code in [('1','free(a)'),('2','free(b)'),('4','free(c)'),('3','length = n')]:
            graph.add_node(nid, code=code, node_type='CALL')
        return graph

    def compress(self, graph):
        # Isolate the connectivity-restoration logic from heuristic score noise.
        with patch.object(summary, 'score_node', side_effect=lambda g,n,*a,**k: 0 if n=='3' else 100):
            return summary.summarize_graph(graph, token_budget=None, verbose=False)

    def test_reverse_id_dependence_not_restored(self):
        graph = self.fixture()
        graph.add_edge('2','3',edge_type='DFG')
        graph.add_edge('3','1',edge_type='DFG')
        self.assertTrue(nx.has_path(graph,'2','1'))
        compressed = self.compress(graph)
        self.assertNotIn('3', compressed)
        self.assertFalse(nx.has_path(compressed,'2','1'))

    def test_ast_connectivity_masks_missing_data_chain(self):
        graph = self.fixture()
        graph.add_edge('1','2',edge_type='AST')
        graph.add_edge('1','3',edge_type='DFG')
        graph.add_edge('3','2',edge_type='DFG')
        compressed = self.compress(graph)
        self.assertTrue(nx.has_path(compressed,'1','2'))
        self.assertNotIn('3', compressed)

    def test_lifecycle_does_not_bind_objects(self):
        graph = nx.MultiDiGraph()
        graph.add_node('a',code='free(first)')
        graph.add_node('b',code='printf("%s", unrelated)')
        graph.add_edge('a','b',edge_type='CFG')
        self.assertEqual(_compute_variable_lifecycle_completeness(graph,['a','b']),7)

    def test_hop_off_by_one(self):
        graph = nx.MultiDiGraph()
        graph.add_edge('a','b',edge_type='DFG')
        graph.add_edge('b','c',edge_type='DFG')
        self.assertIn(['a','b','c'],extract_candidate_paths_from_node(graph,'a',max_hop=1))

    def test_src_omits_valid_updates_without_budget_pressure(self):
        source = 'void f(void) {\nlength = 8;\nlength++;\n*p = 1;\nreturn;\n}'
        actual = _slice_source(source, max_chars=10000)
        for statement in ('length = 8;', 'length++;', '*p = 1;'):
            self.assertNotIn(statement,actual)

    def test_src_anchors_ignore_topk_selection(self):
        graph = nx.MultiDiGraph()
        graph.add_node('a',code='buffer[index]')
        graph.add_node('b',code='length = n')
        self.assertEqual(_collect_graph_anchors(graph,[['a']]),_collect_graph_anchors(graph,[['b']]))

    def test_path_truncation_is_not_complete_node_packing(self):
        graph = nx.MultiDiGraph()
        graph.add_node('a',node_type='CALL',code='memcpy(destination, source, source_length)')
        graph.add_node('b',node_type='CALL',code='free(destination)')
        graph.add_edge('a','b',edge_type='CFG')
        actual = _labeled_compact_path(graph,['a','b'],max_len=25)
        self.assertEqual(len(actual),25)
        self.assertFalse(actual.endswith(']'))


if __name__ == '__main__':
    unittest.main()
