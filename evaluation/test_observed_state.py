import unittest
import contextlib
import importlib
import io
from unittest.mock import patch
import networkx as nx
from planning.state_memory import ProgramState, create_program_state
from planning.observed_state import ObservedProgramState, observations, mask_noncode
from reasoning.reasoning_loop import _update_program_state
from reasoning.explanation import generate_explanation
from linearization.typed_paths import build_hierarchical_context
from evaluation.audit_state_semantics import CASES


class ObservedStateTests(unittest.TestCase):
    def test_default_factory_is_legacy(self):
        with patch('config.OBSERVED_STATE_CANDIDATE', False):
            self.assertIs(type(create_program_state()), ProgramState)
        with patch('config.OBSERVED_STATE_CANDIDATE', True):
            self.assertIs(type(create_program_state()), ObservedProgramState)

    def test_noncode_excluded_and_offsets_preserved(self):
        code = '/* free(p);\np->x; */\nputs("free(q); q->x;");\nfree(P);'
        self.assertEqual(len(mask_noncode(code)), len(code))
        events = observations(code)
        self.assertEqual([(e['variable'], e['state'], e['line']) for e in events],
                         [('P', 'free-call', 4)])

    def test_argument_positions_and_balanced_calls(self):
        code = 'sscanf(src,"%s,%s",A,B); fscanf(fp,fmt,&C); scanf("%s",D); read(fd(),E,n);'
        self.assertEqual([e['variable'] for e in observations(code) if e['state']=='input-call'],
                         ['A', 'B', 'C', 'D', 'E'])
        self.assertFalse(observations('read(fd, nested(x,y), n);'))

    def test_allocation_target_not_size_case_preserved(self):
        state = ObservedProgramState()
        graph = nx.MultiDiGraph()
        graph.add_node('n', code='P = malloc(n);', label='CALL')
        _update_program_state(state, '', graph, [['n'], ['n']], 1)
        _update_program_state(state, '', graph, [['n']], 2)
        self.assertEqual([(e['variable'], e['state']) for e in state.events], [('P', 'alloc-call')])
        self.assertIsNone(state.is_freed_and_used('P'))

    def test_exact_location_dedup_preserves_distinct_operations(self):
        code = 'void f(void *p) {\nfree(p);\np=malloc(n);\nfree(p);\n}'
        state = ObservedProgramState()
        state.track_vars(code)
        before = len(state.events)
        state.track_vars(code)
        state.observe_graph_node('alloc', {'code':'p=malloc(n);'}, 1)
        self.assertEqual(len(state.events), before)
        self.assertEqual(sum(e['state']=='free-call' for e in state.events), 2)
        with self.assertRaises(ValueError): state.track_vars('free(other);')

    def test_no_conditional_or_lifetime_claim_from_counterexamples(self):
        for name, code, probe, var, expected, rationale in CASES:
            state = ObservedProgramState()
            state.track_vars(code)
            self.assertIsNone(getattr(state, probe)(var), name)
            self.assertEqual(state.get_current_state(var), 'unknown')
            self.assertNotIn('->', state.dump())
            self.assertTrue(all(e['certainty']=='may' and e['scope']=='unresolved' for e in state.events))

    def test_alias_is_copy_observation_not_propagation(self):
        events = observations('struct S *q=p; free(p); q->x=1;')
        copy = next(e for e in events if e['state']=='copy')
        self.assertEqual((copy['variable'], copy['detail']), ('q','p'))
        self.assertNotIn('alias-propagated', [e['state'] for e in events])

    def test_ambiguous_pointer_target_and_graph_container_omitted(self):
        self.assertFalse(any(e['state']=='alloc-call' for e in observations('*p=malloc(n);')))
        state = ObservedProgramState()
        for field in ('label', '_label', 'node_type'):
            state.observe_graph_node('block', {field:'BLOCK','code':'free(p);'}, 1)
        self.assertFalse(state.events)

    def test_budget_serialization_never_splits_units(self):
        for _, code, _, _, _, _ in CASES:
            state = ObservedProgramState()
            legacy = ProgramState()
            state.track_vars(code)
            legacy.track_vars(code)
            for limit in (0, 10, 14, 30, 150, 350, 400):
                rendered = state.render(limit)
                self.assertLessEqual(len(rendered), len(legacy.dump().strip()[:limit]))
                self.assertLessEqual(len(rendered.encode()), len(legacy.dump().strip()[:limit].encode()))
                self.assertTrue(not rendered or rendered=='MAY;unordered:' or rendered.endswith(';'))

    def test_candidate_prompt_only_state_diff(self):
        code = 'void f(int c, struct S *p) {\nif(c) free(p);\nelse p->x=1;\n}'
        contexts = []
        for enabled in (False, True):
            with patch('config.OBSERVED_STATE_CANDIDATE', enabled):
                contexts.append(build_hierarchical_context(nx.MultiDiGraph(), code, '', {}, [], include_state=True))
        self.assertEqual(contexts[0].split('STATE:')[0], contexts[1].split('STATE:')[0])
        self.assertIn('MAY;unordered:', contexts[1])
        self.assertLessEqual(len(contexts[1].encode()), len(contexts[0].encode()))

    def test_explanation_does_not_use_unknown_as_safe(self):
        state = ObservedProgramState()
        state.track_vars('free(p); p->x=1;')
        report = generate_explanation(nx.MultiDiGraph(), 'Use-After-Free', [], state, 'test')
        self.assertIn('unresolved', report)
        self.assertIn('No type-specific safety/vulnerability claim', report)

    def test_reasoning_entrypoint_uses_candidate_with_mocked_model(self):
        loop = importlib.import_module('reasoning.reasoning_loop')
        graph = nx.MultiDiGraph()
        graph.add_node('free', code='free(p);', node_type='CALL')
        answer = 'HYPOTHESIS: no vulnerability detected\nREASONING: test only\nACTION: {"action":"Stop","reason":"test"}'
        with patch('config.OBSERVED_STATE_CANDIDATE', True), patch.object(
                loop, 'query_llm_with_retry', return_value=(answer, 1)) as query, contextlib.redirect_stdout(io.StringIO()):
            result = loop.reasoning_loop(graph, [['free']], 'void f(void *p) { free(p); }', '', {},
                max_steps=1, use_slice=False, use_output_contract=False, use_expansion=False)
        self.assertIsInstance(result['program_state'], ObservedProgramState)
        self.assertIn('MAY;unordered:', query.call_args.args[0])
        self.assertIn('unresolved', result['explanation'])
        self.assertEqual(sum(e['state']=='free-call' for e in result['program_state'].events), 1)


if __name__=='__main__': unittest.main()
