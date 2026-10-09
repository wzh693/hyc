import contextlib
import importlib
import io
import tempfile
from pathlib import Path
import json
import unittest
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch
from evaluation.evaluate_wiring_quality import score, summarize, PROFILES, REPEAT_PROFILES
from evaluation.evaluate_wiring_quality import effective_configuration
from evaluation.build_clean_protocol import inventory_exposure


class QualityTests(unittest.TestCase):
    def test_package_import_does_not_preload_experiment_config(self):
        child=subprocess.run([sys.executable,'-c',
            "import sys,evaluation; assert 'config' not in sys.modules; from evaluation import ABLATION_CONFIGS; assert 'full' in ABLATION_CONFIGS"],
            capture_output=True,text=True)
        self.assertEqual(child.returncode,0,child.stderr)

    def test_actual_settings_must_match_before_calling_model(self):
        config=SimpleNamespace(TYPE_COVERAGE_PROMPT=False,MAX_REASONING_STEPS=2)
        with self.assertRaises(ValueError):
            effective_configuration(config,{'TYPE_COVERAGE_PROMPT':'1'})
        self.assertEqual(effective_configuration(config,{'MAX_REASONING_STEPS':'2'}),
                         {'MAX_REASONING_STEPS':2})

    def test_abstentions_have_full_denominator(self):
        metric=score([{'target':1,'prediction':1},{'target':0,'prediction':None},
                      {'target':1,'prediction':None}])
        self.assertEqual(metric['accuracy'],1/3)
        self.assertEqual(metric['f1'],.5)
        self.assertEqual(metric['coverage'],1/3)

    def test_complete_factorial_and_repeat_receipts_required(self):
        samples=[{'sample_id':'a','group_id':'one','target':1},
                 {'sample_id':'b','group_id':'two','target':0}]
        rows=[dict(s,profile=p,repeat=r,prediction=s['target']) for s in samples
              for r,ps in ((1,PROFILES),(2,REPEAT_PROFILES)) for p in ps]
        report=summarize(rows,{'samples':samples},[],bootstrap=100)
        self.assertEqual(report['metrics']['control/r1']['accuracy'],1)
        self.assertEqual(report['paired_group_intervals']['combined-vs-control']['group_delta_f1_ci95'],[0,0])
        self.assertFalse(report['auto_promoted'])
        with self.assertRaises(ValueError):
            summarize(rows[:-1],{'samples':samples},[],bootstrap=100)
        with self.assertRaises(ValueError):
            summarize(rows+[rows[0]],{'samples':samples},[],bootstrap=100)

    def test_index_exposure_scan_does_not_require_historical_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);directory=root/'output/devign_previous';directory.mkdir(parents=True)
            (directory/'manifest.json').write_text(json.dumps([{'idx':3,'source_sha256':'abc'}]))
            exposed,hashes,artifacts=inventory_exposure(root,10,read_sources=False)
        self.assertEqual(exposed,{3})
        self.assertEqual(hashes,{'abc'})
        self.assertEqual(len(artifacts),1)

    def test_expansion_does_not_route_from_truncated_keyword_fallback(self):
        module=importlib.import_module('reasoning.reasoning_loop')
        from evaluation.test_pipeline_wiring import graph,SOURCE
        output='HYPOTHESIS: Uncertain\nREASONING: missing dataflow evidence, need more information'
        with contextlib.redirect_stdout(io.StringIO()), patch.object(
                module,'query_llm_with_retry',return_value=(output,10)) as query, patch.object(
                module,'_execute_action') as expand:
            result=module.reasoning_loop(graph(),[['c']],SOURCE,'',{},max_steps=2,
                                         use_expansion=True,use_output_contract=False)
        expand.assert_not_called()
        self.assertEqual(query.call_count,1)
        self.assertEqual(result['module_audit']['stop_reason'],'no_requested_gap')


if __name__=='__main__':
    unittest.main()
