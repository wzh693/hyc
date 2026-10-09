import contextlib
import ast
import importlib
import io
import os
import tempfile
import unittest
from unittest.mock import patch
import networkx as nx
from linearization.backward_slice import backward_evidence_slice

loop_module = importlib.import_module('reasoning.reasoning_loop')


def graph():
    g = nx.MultiDiGraph()
    for node, code, line in [('a', 'p = input;', 1), ('b', 'if (n < cap)', 2),
                             ('c', 'memcpy(dst,p,n);', 3), ('d', 'unrelated();', 4)]:
        g.add_node(node, code=code, line_number=line, node_type='CALL')
    g.add_edge('a', 'c', edge_type='REACHING_DEF')
    g.add_edge('b', 'c', edge_type='CDG')
    g.add_edge('d', 'c', edge_type='CFG')
    return g


SOURCE = 'p = input;\nif (n < cap)\nmemcpy(dst,p,n);\nunrelated();'
BENIGN = 'HYPOTHESIS: Benign\nACTION: {"action":"Stop","reason":"bounds checked"}\nREASONING: checked bounds'
GAP = 'HYPOTHESIS: Uncertain\nACTION: {"action":"ExpandDFG","reason":"missing data dependency"}\nREASONING: input dependency not shown'


class SliceTests(unittest.TestCase):
    def test_dependence_not_cfg(self):
        text, audit = backward_evidence_slice(graph(), [['c']], SOURCE)
        self.assertEqual(audit['source_lines'], [1, 2, 3])
        self.assertNotIn('unrelated', text)
        self.assertEqual(audit['dependence_edges'], {'REACHING_DEF': 1, 'CDG': 1})

    def test_wrapped_offsets(self):
        g = graph()
        for _, attrs in g.nodes(data=True):
            attrs['line_number'] += 3
        text, audit = backward_evidence_slice(g, [['c']], SOURCE, line_offset=3)
        self.assertIn('p = input', text)
        self.assertEqual(audit['unmapped_nodes'], 0)

    def test_budget_keeps_whole_lines(self):
        text, audit = backward_evidence_slice(graph(), [['c']], SOURCE, max_chars=16)
        self.assertEqual(text, 'memcpy(dst,p,n);')
        self.assertEqual(audit['omitted_lines'], 2)

    def test_no_criteria_fallback(self):
        text, audit = backward_evidence_slice(graph(), [['d']], SOURCE)
        self.assertEqual(text, '')
        self.assertTrue(audit['fallback'])


class LoopTests(unittest.TestCase):
    def test_exit_gap_is_recognized(self):
        output = 'HYPOTHESIS: Memory Leak\nREASONING: no free shown in slice, need exit path'
        self.assertTrue(loop_module._needs_evidence_expansion(output, 'ExpandCFG'))
        self.assertFalse(loop_module._needs_evidence_expansion(output, 'Stop'))

    def run_loop(self, responses, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()), patch.object(
                loop_module, 'query_llm_with_retry', side_effect=responses) as query:
            result = loop_module.reasoning_loop(graph(), [['c']], SOURCE, '', {},
                max_steps=2, use_slice=False, use_output_contract=True,
                use_expansion=True, **kwargs)
        return result, query

    def test_clear_benign_one_call(self):
        result, query = self.run_loop([(BENIGN, 10)])
        self.assertEqual(query.call_count, 1)
        self.assertEqual(result['decision_status'], 'Benign')

    def test_missing_action_is_uncertain_no_retry(self):
        result, query = self.run_loop([('HYPOTHESIS: Buffer Overflow\nREASONING: ' + 'x'*200, 10)])
        self.assertEqual(query.call_count, 1)
        self.assertEqual(result['decision_status'], 'Uncertain')
        self.assertTrue(result['module_audit']['output_incomplete'])

    def test_full_graph_expansion_and_final_benign(self):
        full = graph()
        full.add_node('new', code='n = checked_length;', node_type='CALL')
        with patch.object(loop_module, '_execute_action', return_value=[['c', 'new']]) as expand:
            result, query = self.run_loop([(GAP, 10), (BENIGN, 11)], full_graph=full)
        self.assertIs(expand.call_args.args[3], full)
        self.assertIn('checked_length', query.call_args.args[0])
        self.assertEqual(query.call_count, 2)
        self.assertEqual(result['decision_status'], 'Benign')
        self.assertEqual(result['tokens_used'], 21)

    def test_duplicate_paths_do_not_trigger_second_call(self):
        with patch.object(loop_module, '_execute_action', return_value=[['c']]):
            result, query = self.run_loop([(GAP, 10)])
        self.assertEqual(query.call_count, 1)
        self.assertEqual(result['module_audit']['stop_reason'], 'no_new_evidence')

    def test_max_steps_is_per_call(self):
        with self.assertRaises(ValueError):
            loop_module.reasoning_loop(graph(), [], SOURCE, '', {}, max_steps=0)


class PipelineTests(unittest.TestCase):
    def test_production_entrypoints_delegate_to_shared_pipeline(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        for name in ('analyze','evaluate_hgl','evaluate_devign','robustness_eval'):
            tree = ast.parse((root/'modes'/f'{name}.py').read_text(encoding='utf-8'))
            calls = [n.func.id for n in ast.walk(tree) if isinstance(n,ast.Call)
                     and isinstance(n.func,ast.Name)]
            self.assertIn('run_hgl_pipeline', calls)
            self.assertNotIn('reasoning_loop', calls)

    def test_new_removal_configs_are_independent(self):
        from evaluation.ablation import ABLATION_CONFIGS
        for name in ('no_slice','no_output_contract','no_expansion','no_safety_net'):
            self.assertEqual(ABLATION_CONFIGS[name]['pipeline_ablation'], name)
            self.assertTrue(ABLATION_CONFIGS[name]['use_constr_reason'])

    def test_expansion_removal_never_executes_action(self):
        with patch.object(loop_module,'query_llm_with_retry',return_value=(GAP,10)), patch.object(
                loop_module,'_execute_action') as expand, contextlib.redirect_stdout(io.StringIO()):
            result = loop_module.reasoning_loop(graph(),[['c']],SOURCE,'',{},
                use_expansion=False,use_output_contract=True,max_steps=2)
        expand.assert_not_called()
        self.assertEqual(result['module_audit']['stop_reason'],'expansion_ablation')

    def test_abstentions_not_hidden_in_accuracy(self):
        from evaluation.metrics import compute_long_range_metrics
        metrics = compute_long_range_metrics([
            {'label':1, 'prediction':1}, {'label':0, 'prediction':None},
            {'label':1, 'prediction':None}])['overall']
        self.assertEqual(metrics['accuracy'], 1/3)
        self.assertEqual(metrics['accuracy_valid'], 1)
        self.assertEqual(metrics['coverage'], 1/3)
        self.assertEqual(metrics['accuracy_all'], 1/3)
        self.assertEqual(metrics['f1_conservative'], .5)

    def test_no_discarded_learned_scores_or_unused_summaries(self):
        from graph.pipeline import run_hgl_pipeline
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, 'source.c')
            # Fixture only, not a repository edit.
            with open(path, 'w', encoding='utf-8') as f:
                f.write(SOURCE)
            with contextlib.ExitStack() as stack:
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                stack.enter_context(patch('graph.pipeline.build_cpg', return_value=folder))
                stack.enter_context(patch('graph.pipeline.find_export_files', return_value=('n', 'e')))
                stack.enter_context(patch('graph.pipeline.load_graph', return_value=graph()))
                stack.enter_context(patch('graph.pipeline.summarize_graph', side_effect=lambda g, **kw:g))
                stack.enter_context(patch('graph.pipeline.extract_all_candidate_paths', return_value=[['c']]))
                stack.enter_context(patch('graph.pipeline.retrieve_topk', return_value=[['c']]))
                stack.enter_context(patch('learning.scorer.summarize_enabled', return_value=False))
                stack.enter_context(patch('learning.scorer.path_rank_enabled', return_value=False))
                scorer = stack.enter_context(patch('learning.scorer.score_nodes'))
                summary = stack.enter_context(patch('graph.pipeline.summarize_function'))
                stack.enter_context(patch('graph.pipeline.reasoning_loop', return_value={
                    'vulnerability_type':'Unknown', 'decision_status':'Uncertain', 'module_audit':{}}))
                stack.enter_context(patch('config.COMPACT_THREE_PART_CONTEXT', True))
                details = run_hgl_pipeline(path, SOURCE, 'fixture', folder, object(),
                                           return_details=True)
            scorer.assert_not_called()
            summary.assert_not_called()
            self.assertIsNone(details['prediction'])
            self.assertFalse(details['module_audit']['learned_scoring'])

    def test_inactive_scorer_does_not_load_model(self):
        import learning.scorer as scorer
        with patch.object(scorer, 'USE_LEARNED_SUMMARIZE', False), patch.object(
                scorer, 'USE_LEARNED_PATH_RANK', False), patch.object(scorer, 'get_node_scorer') as load:
            self.assertFalse(scorer.summarize_enabled())
            self.assertFalse(scorer.path_rank_enabled())
            load.assert_not_called()


if __name__ == '__main__':
    unittest.main()
