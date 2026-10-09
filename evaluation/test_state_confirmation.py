import unittest
from unittest.mock import patch
from types import SimpleNamespace
import networkx as nx
from evaluation.check_observed_state_cache import compare_prompts
from linearization.typed_paths import build_hierarchical_context
from reasoning.prompts import build_user_prompt
from planning.state_memory import create_program_state
import evaluation.evaluate_wiring_quality as runner


class StateConfirmationTests(unittest.TestCase):
    def prompts(self):
        code='void f(int c, struct S *p) {\nif(c) free(p);\nelse p->x=1;\n}'
        prompts=[]
        for name in ('control','state_disabled','observed_state'):
            with patch('config.OBSERVED_STATE_CANDIDATE',name=='observed_state'):
                state=create_program_state()
                state.track_vars(code)
                context=build_hierarchical_context(nx.MultiDiGraph(),code,'',{},[],include_state=name!='state_disabled')
                prompts.append(build_user_prompt('',context,state.dump(),1))
        return prompts

    def test_shadow_actual_renderer_three_arms(self):
        audit=compare_prompts(*self.prompts())
        self.assertIn('MAY;unordered:',audit['candidate_state'])

    def test_shadow_rejects_nonstate_change(self):
        prompts=self.prompts()
        prompts[2]=prompts[2].replace('SRC:', 'CHANGED:')
        with self.assertRaises(ValueError):compare_prompts(*prompts)

    def test_shadow_rejects_budget_growth(self):
        prompts=self.prompts()
        prompts[2]=prompts[2].replace('MAY;unordered:', 'MAY;unordered:'+'x'*200)
        with self.assertRaises(ValueError):compare_prompts(*prompts)

    def test_observed_vs_disabled_contrast_and_full_failure_accounting(self):
        profiles={'control':(0,0,0),'state_disabled':(0,0,0),'observed_state':(0,0,0)}
        samples=[{'sample_id':'s1','target':1},{'sample_id':'s2','target':0}]
        rows=[{'sample_id':s['sample_id'],'profile':p,'repeat':r,'target':s['target'],
               'prediction':None,'error':'mock failure'} for s in samples for p in profiles for r in (1,2)]
        with patch.object(runner,'PROFILES',profiles),patch.object(runner,'REPEAT_PROFILES',tuple(profiles)):
            report=runner.summarize(rows,{'samples':samples},[],bootstrap=20)
        self.assertIn('observed_state-vs-state_disabled',report['paired_group_intervals'])
        self.assertEqual(report['metrics']['observed_state/r1']['n'],2)
        self.assertEqual(report['metrics']['observed_state/r1']['errors'],2)

    def test_effective_candidate_flag_failclosed(self):
        with self.assertRaises(ValueError):
            runner.effective_configuration(SimpleNamespace(OBSERVED_STATE_CANDIDATE=False),
                                           {'OBSERVED_STATE_CANDIDATE':'1'})


if __name__=='__main__':unittest.main()
