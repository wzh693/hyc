import json
import unittest
import networkx as nx
from . import architecture as a


def graph():
    g = nx.MultiDiGraph()
    for n, code, kind, name, line in [
        ('1', 'n = size;', 'CALL', '<operator>.assignment', 1),
        ('2', 'if (n < cap)', 'CONTROL_STRUCTURE', '', 2),
        ('3', 'memcpy(dst, src, n);', 'CALL', 'memcpy', 3),
        ('4', 'return 0;', 'RETURN', '', 4)]:
        g.add_node(n, code=code, node_type=kind, name=name, line_number=line)
    g.add_edge('1', '3', edge_type='REACHING_DEF')
    g.add_edge('2', '3', edge_type='CDG')
    g.add_edge('4', '3', edge_type='CFG')
    return g


SOURCE = 'n = size;\nif (n < cap)\nmemcpy(dst, src, n);\nreturn 0;'


class PrototypeTests(unittest.TestCase):
    def test_shared_forward_exactly_once(self):
        calls = []
        def scorer(g, source):
            calls.append(1)
            return {n: .25 for n in g}
        result = a.run(graph(), SOURCE, 0, scorer, lambda **kw: dict(
            text='{"verdict":"Benign","action":"Stop"}', finish_reason='stop'))
        self.assertEqual(len(calls), 1)
        self.assertEqual(result['main_pred'], result['final_pred'])
        self.assertEqual(result['security_net']['mode'], 'shadow')

    def test_invalid_scores_never_fallback(self):
        for scores in ({'1': 1.0}, {n: float('nan') for n in graph()}, {n: .5 for n in graph()}):
            with self.assertRaises(ValueError):
                a.compress(graph(), scores, a.Settings())

    def test_budget_conflict_not_silent(self):
        with self.assertRaises(ValueError):
            a.compress(graph(), {n: .25 for n in graph()}, a.Settings(graph_budget=1))

    def test_force_keep_and_estimated_budget(self):
        compressed, receipt = a.compress(graph(), {'1': .4, '2': .3, '3': .1, '4': .2},
                                         a.Settings(graph_budget=12, minimum_nodes=0))
        self.assertIn('3', compressed)
        self.assertLessEqual(receipt['estimated_tokens'], 12)

    def test_no_cfg_as_control_dependence(self):
        _, audit = a.dependence_slice(graph(), ['3'], SOURCE, 0,
                                      a.Settings(source_chars=200), {n: .25 for n in graph()})
        self.assertEqual(audit['source_lines'], [1, 2, 3])
        self.assertNotIn('CFG', [w[2] for w in audit['dependence_witnesses']])

    def test_helper_and_arithmetic_are_eligible(self):
        self.assertTrue(a.criterion(dict(node_type='CALL', name='ReadProfileByte', code='ReadProfileByte(p,n)')))
        self.assertTrue(a.criterion(dict(node_type='CALL', name='<operator>.multiplication', code='a * b')))
        self.assertFalse(a.criterion(dict(node_type='BLOCK', code='a * b')))

    def test_literals_cannot_spoof_dangerous_api(self):
        self.assertFalse(a.sink(dict(node_type='CALL', code='log_message("memcpy(a,b,n)")')))

    def test_criteria_ranked_by_same_scores_and_source_mapping(self):
        g = graph()
        g.nodes['4']['line_number'] = 400
        selected = a.select_criteria(g, {'1': .6, '2': .1, '3': .2, '4': .1}, SOURCE, 0, a.Settings())
        self.assertEqual(selected, ['1', '3'])

    def test_path_feasibility_precedes_same_score_ranking(self):
        g = graph()
        g.nodes['1']['code'] = 'a' * 2000
        selected = a.rank_paths(g, [('1', '3'), ('3',)], {n: .25 for n in g}, a.Settings(path_chars=300))
        self.assertEqual(selected, [('3',)])

    def test_no_container_or_ast_in_retrieved_paths(self):
        g = graph()
        g.add_node('5', node_type='BLOCK', code=SOURCE)
        g.add_edge('5', '3', edge_type='AST')
        scores = {n: .2 for n in g}
        compressed, _ = a.compress(g, scores, a.Settings())
        self.assertNotIn('5', compressed)
        paths, _ = a.paths_to(g, ['3'], a.Settings(), scores=scores)
        self.assertFalse(any('5' in p for p in paths))

    def test_container_is_not_sink(self):
        self.assertFalse(a.sink(dict(node_type='BLOCK', code='memcpy(a,b,n);')))

    def test_path_serializer_omits_whole_units(self):
        g = graph()
        g.nodes['3']['code'] = 'memcpy(' + 'x' * 1000 + ');'
        text, displayed = a.serialize_paths(g, [('1', '3')], 300)
        self.assertEqual((text, displayed), ('', []))

    def test_risk_proxy_deduplicates_sink(self):
        signal = a.danger_signal(graph(), [('1', '3'), ('2', '3')], {3}, 0)
        self.assertEqual(signal['sink_count'], 1)
        self.assertTrue(signal['sink_anchored'])

    def test_missing_mapping_prevents_anchoring(self):
        signal = a.danger_signal(graph(), [('3',)], {3}, 100)
        self.assertFalse(signal['sink_anchored'])

    def test_three_state_strict_parse(self):
        for text in ('no vulnerability detected', '{"verdict":"Benign"', '[]', '{"verdict":"Safe"}'):
            self.assertEqual(a.decode(text)['verdict'], 'Uncertain')

    def test_mismatched_calibration_refused(self):
        with self.assertRaises(ValueError):
            a.verify(0, {}, dict(status='passed'), 'model', 'policy')

    def test_calibrated_override_keeps_positive(self):
        receipt = dict(status='passed', scope='development', model_sha256='m',
                       policy_sha256='p', calibration_groups=2, threshold=2.)
        signal = dict(sink_anchored=True, score=2.5)
        self.assertEqual(a.verify(None, signal, receipt, 'm', 'p')[0], 1)
        self.assertEqual(a.verify(1, signal, receipt, 'm', 'p')[0], 1)

    def test_bounded_adaptation_new_paths_only(self):
        g = graph()
        # Compress only sink. The query can recover real incoming dependence.
        cfg = a.Settings(graph_budget=12, minimum_nodes=0, path_chars=2000)
        replies = iter([
            dict(verdict='Uncertain', action='Query', reason='length origin missing',
                 target='3', edge_types=['REACHING_DEF']),
            dict(verdict='Vulnerable', hypothesis='bounds', action='Query', reason='guard missing',
                 target='3', edge_types=['CDG']),
            dict(verdict='Vulnerable', hypothesis='bounds', action='Stop')])
        result = a.run(g, SOURCE, 0, lambda g, s: {n: .25 for n in g},
            lambda **kw: dict(text=json.dumps(next(replies)), finish_reason='stop'), cfg)
        self.assertEqual(len(result['trace']), 3)
        self.assertTrue(result['trace'][0]['query']['new_paths'])
        self.assertIn('PRIOR:', result['trace'][1]['request']['messages'][1]['content'])
        self.assertEqual(result['final_pred'], 1)

    def test_bad_query_target_stops(self):
        result = a.run(graph(), SOURCE, 0, lambda g, s: {n: .25 for n in g},
            lambda **kw: dict(text=json.dumps(dict(verdict='Uncertain', action='Query',
                reason='missing', target='not-a-node', edge_types=['CFG'])), finish_reason='stop'))
        self.assertEqual(len(result['trace']), 1)
        self.assertIn('query_rejected', result['trace'][0])

    def test_length_finish_is_uncertain(self):
        result = a.run(graph(), SOURCE, 0, lambda g, s: {n: .25 for n in g},
            lambda **kw: dict(text='{"verdict":"Benign","action":"Stop"}', finish_reason='length'))
        self.assertIsNone(result['main_pred'])


if __name__ == '__main__':
    unittest.main()
