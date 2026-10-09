"""Single isolated source policy tests; no external calls or label-based routing."""
import importlib.util
from pathlib import Path
import unittest
import networkx as nx

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT/'development/graph_read_slice_candidate_20261009/src/linearization/backward_slice.py'
spec = importlib.util.spec_from_file_location('isolated_read_slice_policy', FILE)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class ReadSliceCandidateTests(unittest.TestCase):
    def test_bound_updates_scope_and_no_cfg_proof(self):
        source = 'int f(char *p,int n,int off) {\n p += off;\n n -= off;\n if(n > 0){\n  out = p[n];\n }\n unrelated = 999;\n}'
        g = nx.MultiDiGraph()
        for node, line, code, name in [('r', 5, 'p[n]', '<operator>.indirectIndexAccess'),
                                     ('p', 2, 'p += off', '<operator>.assignmentPlus'),
                                     ('n', 3, 'n -= off', '<operator>.assignmentMinus'),
                                     ('guard', 4, 'n > 0', '<operator>.greaterThan'),
                                     ('other', 7, 'unrelated = 999', '<operator>.assignment')]:
            g.add_node(node, line_number=line+10, code=code, name=name, node_type='CALL')
        for node, edge in [('p', 'REACHING_DEF'), ('n', 'DFG'), ('guard', 'CDG'), ('other', 'CFG')]:
            g.add_edge(node, 'r', edge_type=edge)
        text, receipt = policy.backward_evidence_slice(g, [['r']], source, line_offset=10)
        self.assertIn('p += off;', text); self.assertIn('n -= off;', text)
        self.assertIn('if(n > 0){', text); self.assertNotIn('unrelated = 999;', text)
        self.assertEqual(text.count('{'), text.count('}'))
        self.assertNotIn('CFG', receipt['dependence_edges'])
        self.assertIsNone(receipt['scope_is_complete'])
        self.assertLessEqual(len(text), 600)

    def test_copy_source_bound_not_destination_allocation(self):
        source = 'void f(){\n dest = malloc(4096);\n n -= off;\n memcpy(dest, source + off, n);\n}'
        g = nx.MultiDiGraph()
        for node, line, code, name in [('r', 4, 'memcpy(dest, source + off, n)', 'memcpy'),
                                     ('dst', 2, 'dest = malloc(4096)', '<operator>.assignment'),
                                     ('size', 3, 'n -= off', '<operator>.assignmentMinus')]:
            g.add_node(node, line_number=line, code=code, name=name, node_type='CALL')
        g.add_edge('dst', 'r', edge_type='REACHING_DEF'); g.add_edge('size', 'r', edge_type='REACHING_DEF')
        text, receipt = policy.backward_evidence_slice(g, [['r']], source)
        self.assertNotIn('dest = malloc', text); self.assertIn('n -= off;', text)
        self.assertEqual(receipt['read_bindings']['r']['targets'], ['source + off'])
        self.assertEqual(receipt['read_bindings']['r']['capacity_contract'], 'unknown')

    def test_write_only_array_not_seed(self):
        source = 'void f(){\n a[i] = 0;\n}'
        g = nx.MultiDiGraph()
        g.add_node('r', line_number=2, code='a[i]', name='<operator>.indexAccess', node_type='CALL')
        g.add_node('assignment', line_number=2, code='a[i] = 0', name='<operator>.assignment', node_type='CALL')
        g.add_edge('assignment', 'r', edge_type='AST')
        text, receipt = policy.backward_evidence_slice(g, [['r']], source)
        self.assertEqual(text, ''); self.assertTrue(receipt['fallback'])

    def test_missing_positions_and_tiny_budget_fallback(self):
        g = nx.MultiDiGraph(); g.add_node('r', code='p[i]', name='<operator>.indexAccess', node_type='CALL')
        text, receipt = policy.backward_evidence_slice(g, [['r']], 'void f(){ return p[i]; }')
        self.assertEqual(text, ''); self.assertTrue(receipt['fallback'])
        g.nodes['r']['line_number'] = 1
        text, receipt = policy.backward_evidence_slice(g, [['r']], 'void f(){ return p[i]; }', max_chars=20)
        self.assertEqual(text, ''); self.assertTrue(receipt['fallback'])

    def test_literal_delimiters_and_unknown_helpers_not_guessed(self):
        self.assertEqual(policy._args('memcpy(d, helper(a,b), n)', 'memcpy'), ['d', 'helper(a,b)', 'n'])
        pairs, unbalanced = policy._scope_pairs('void f(){ const char *s="}"; /* { */ return; }')
        self.assertEqual(pairs, [(1, 1)]); self.assertFalse(unbalanced)
        g = nx.MultiDiGraph(); g.add_node('r', code='custom_read(p)', name='custom_read', node_type='CALL', line_number=1)
        text, receipt = policy.backward_evidence_slice(g, [['r']], 'custom_read(p);')
        self.assertEqual(text, ''); self.assertEqual(receipt['criteria'], 0)

    def test_partial_source_does_not_gain_invented_brace(self):
        source = 'f(char *p, int n)\nreturn p[n];'
        g = nx.MultiDiGraph(); g.add_node('r', code='p[n]', name='<operator>.indexAccess', node_type='CALL', line_number=2)
        text, receipt = policy.backward_evidence_slice(g, [['r']], source)
        self.assertNotIn('{', text); self.assertNotIn('}', text)
        self.assertIn('contracts unknown', text)


if __name__ == '__main__': unittest.main()
