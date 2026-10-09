"""Fresh-process engineering regression, not a sampled dataset quality test."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'development/graph_display_candidate_20261009/src'


class IsolatedSuite(unittest.TestCase):
    def test_candidate_in_fresh_process(self):
        result = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), '--isolated'],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('Ran 10 tests', result.stderr)


def isolated():
    sys.path.insert(0, str(SOURCE))
    import networkx as nx
    import importlib
    policy = importlib.import_module('retrieval.retrieve_topk')
    from unittest.mock import patch

    class PolicyTests(unittest.TestCase):
        def graph(self):
            g = nx.MultiDiGraph()
            for nid, code, name in [('u', 'n -= off', '<operator>.assignmentMinus'),
                                    ('r', 'memcpy(d, p + off, n)', 'memcpy'),
                                    ('s', 'strchr(p, 0)', 'strchr'),
                                    ('c', 'n > 0', '<operator>.greaterThan'),
                                    ('dst', 'd = malloc(99)', '<operator>.assignment')]:
                g.add_node(nid, code=code, name=name, node_type='CALL')
            g.add_edge('u', 'r', edge_type='REACHING_DEF')
            g.add_edge('c', 'r', edge_type='CDG')
            g.add_edge('dst', 'r', edge_type='REACHING_DEF')
            g.add_edge('s', 'r', edge_type='CFG')
            return g

        def test_complete_visible_read_and_update(self):
            f = policy._visible_features(self.graph(), ['u', 'r'])
            self.assertEqual(f['reads'], {'r'})
            self.assertEqual(f['relations'], {('r', 'u', 'update')})

        def test_destination_not_source_capacity(self):
            g = self.graph()
            self.assertEqual(policy._read_names(g, 'r'), {'p', 'off', 'n'})
            self.assertEqual(policy._visible_features(g, ['dst', 'r'])['relations'], set())

        def test_cfg_not_dependency(self):
            g = self.graph(); g.remove_edges_from(list(g.edges(keys=True)))
            g.add_edge('u', 'r', edge_type='CFG')
            self.assertEqual(policy._visible_features(g, ['u', 'r'])['relations'], set())

        def test_truncated_read_not_counted(self):
            g = self.graph()
            self.assertEqual(policy._visible_features(g, ['u', 'r'], max_len=20)['reads'], set())
            g.nodes['r']['code'] = 'memcpy(destination, source_pointer + offset, length)'
            self.assertEqual(policy._visible_features(g, ['u', 'r'])['reads'], set())

        def test_container_and_custom_not_read(self):
            g = self.graph(); g.nodes['r']['node_type'] = 'METHOD'
            self.assertIsNone(policy._read_names(g, 'r'))
            g.nodes['r'].update(node_type='CALL', name='custom', code='custom(p)')
            self.assertIsNone(policy._read_names(g, 'r'))

        def test_write_only_index_skipped(self):
            g = self.graph()
            g.add_node('i', code='p[n]', name='<operator>.indexAccess', node_type='CALL', argument_index=1)
            g.add_node('a', code='p[n] = 0', name='<operator>.assignment', node_type='CALL')
            g.add_edge('a', 'i', edge_type='AST')
            self.assertIsNone(policy._read_names(g, 'i'))
            g.nodes['a'].update(code='x = p[n]'); g.nodes['i']['argument_index'] = 2
            self.assertEqual(policy._read_names(g, 'i'), {'p', 'n'})

        def test_equal_expression_after_cut_not_visible(self):
            g = self.graph()
            g.add_node('duplicate', **g.nodes['r'])
            g.add_edge('r', 'u', edge_type='DFG'); g.add_edge('u', 'duplicate', edge_type='DFG')
            f = policy._visible_features(g, ['r', 'u', 'duplicate'], max_len=75)
            self.assertEqual(f['reads'], {'r'})
            self.assertNotIn('duplicate', f['visible'])

        def test_dependency_preference_and_diversity(self):
            g = self.graph(); paths = [['dst', 'r'], ['u', 'r'], ['s', 'r']]
            selected = policy._select_display_paths(g, paths, paths[:2], {tuple(p): 10 for p in paths}, 2)
            # The path showing TWO distinct reads wins; second cannot spend a
            # slot repeating either read just to inflate selected-path coverage.
            self.assertEqual(selected[0], ['s', 'r'])
            one_read = paths[:2]
            selected = policy._select_display_paths(g, one_read, one_read, {tuple(p): 10 for p in paths}, 2)
            self.assertEqual(selected[0], ['u', 'r'])

        def test_fallback_and_k(self):
            g = self.graph(); paths = [['u', 'dst']]
            self.assertEqual(policy._select_display_paths(g, paths, paths, {}, 2), paths)
            self.assertEqual(policy._select_display_paths(g, paths, paths, {}, 0), paths)
            self.assertEqual(len(policy._select_display_paths(g, [['u', 'r']], [['u', 'r']], {}, 1)), 1)

        def test_balanced_arguments_and_masked_decoys(self):
            self.assertEqual(policy._arguments('memcpy(d, helper(p,n), n)'), ['d', 'helper(p,n)', 'n'])
            self.assertIsNone(policy._arguments('memcpy(d, p, n'))
            g = self.graph(); g.nodes['r'].update(code='"memcpy(d,p,n)"')
            self.assertIsNone(policy._read_names(g, 'r'))

    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(PolicyTests))
    raise SystemExit(not result.wasSuccessful())


if __name__ == '__main__':
    if '--isolated' in sys.argv: isolated()
    else: unittest.main()
