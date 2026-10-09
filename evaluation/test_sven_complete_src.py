"""Source-policy and full-denominator checks; no paid model calls."""
import contextlib
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
from evaluation.evaluate_sven_complete_src import source_only_request, compare_source_requests, checked_rows, summarize


def request(src):
    return dict(model='deepseek-chat', temperature=0, max_tokens=150,
                messages=[{'role': 'system', 'content': 'unchanged'},
                          {'role': 'user', 'content': 'SRC:\n'+src+'\n\nDEP PATHS:\nP1\n\nSTATE:\nstate'}])


class SourceRecipeTests(unittest.TestCase):
    def test_only_source_changes_and_verbatim_scope(self):
        code = 'if (i < n) {\n return a[i];\n}\nreturn a[j];'
        a = request('if (i < n)\nreturn a[i];\nreturn a[j];')
        b = source_only_request(a, code)
        self.assertTrue(compare_source_requests(a, b, code))
        self.assertIn(code, b['messages'][1]['content'])
        self.assertEqual(a['messages'][0], b['messages'][0])
        b['messages'][1]['content'] += 'changed state'
        with self.assertRaises(ValueError): compare_source_requests(a, b, code)

    def test_explicit_large_source_fallback_no_midline_truncation(self):
        b = source_only_request(request('legacy'), 'x'*6001)
        self.assertIn('exceeds complete-slice cap', b['messages'][1]['content'])
        self.assertIn('legacy\n\nDEP PATHS:', b['messages'][1]['content'])
        self.assertNotIn('x'*100, b['messages'][1]['content'])

    def test_missing_or_duplicate_scheduled_rows_rejected(self):
        m = {'samples': [{'idx': 0}], 'profiles': ['control'], 'repeats': [1, 2]}
        with self.assertRaises(ValueError): checked_rows([], [], m)

    def test_failures_retained_and_no_control_no_gain_claim(self):
        s = dict(idx=0, target=1, cwe='CWE-125', group_id='g', sample_id='x', source_sha256='h')
        m = dict(samples=[s], profiles=['complete_src'], repeats=[1, 2], scope='test')
        rows = [dict(s, profile='complete_src', repeat=r, prediction=None, error='failure', tokens_used=0) for r in (1, 2)]
        report = summarize(rows, [], m)
        self.assertEqual(report['scheduled_results'], 2)
        self.assertEqual(report['metrics']['complete_src/r1']['fn'], 1)
        self.assertEqual(report['metrics']['complete_src/r1']['accuracy'], 0)
        self.assertFalse(report['exploratory_support'])
        self.assertFalse(report['functional_gate'])

    def test_actual_isolated_pipeline_in_fresh_process(self):
        result = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), '--isolated-tests'],
                                capture_output=True, encoding='utf8', errors='replace')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)


def isolated_suite():
    # The rejected candidate is historical, not the active development source.
    run = ROOT/'output/sven_complete_src_eval_20261008'
    manifest = json.loads((run/'manifest.json').read_text(encoding='utf-8-sig'))
    SOURCE = run/'code_snapshot'
    for name, expected in manifest['code_hashes'].items():
        if hashlib.sha256((SOURCE/name).read_bytes()).hexdigest() != expected:
            raise ValueError('Rejected candidate snapshot changed: '+name)
    settings = json.loads((ROOT/'baselines/type_coverage_reconstructed_20261008/baseline.json').read_text(encoding='utf-8-sig'))['settings']
    os.environ.update(settings); os.environ.update(COMPLETE_SOURCE_SLICE='0', OPENAI_API_KEY='offline-not-a-key')
    sys.dont_write_bytecode = True; sys.path.insert(0, str(SOURCE))
    config = importlib.import_module('config')
    pipeline = importlib.import_module('graph.pipeline')
    api = importlib.import_module('reasoning.llm_api')
    typed = importlib.import_module('linearization.typed_paths')
    import networkx as nx
    import tempfile
    class IsolatedPolicyTests(unittest.TestCase):
        def setUp(self):
            self.addCleanup(setattr, config, 'COMPLETE_SOURCE_SLICE', False)

        def context(self, code, enabled):
            config.COMPLETE_SOURCE_SLICE = enabled
            return typed.build_hierarchical_context(nx.MultiDiGraph(), code, '', {}, [], include_state=True)

        def test_scope_and_assignment_preserved(self):
            code = 'int read(char *p, int n) {\n if (n < 1) {\n return -1;\n }\n p += 3;\n n = n - 3;\n return p[n];\n}\n'
            a, b = self.context(code, False), self.context(code, True)
            self.assertIn(code, b)
            self.assertNotEqual(a, b)
            self.assertEqual(a.split('\n\nDEP PATHS:', 1)[1], b.split('\n\nDEP PATHS:', 1)[1])

        def test_comments_and_literals_are_not_rewritten(self):
            code = 'int f() {\n /* if } */\n const char *s = "return {";\n return s[0];\n}'
            self.assertIn(code, self.context(code, True))

        def test_repeated_lines_and_order_preserved(self):
            code = 'int f(char *p) {\n p++;\n p++;\n p++;\n return *p;\n}'
            self.assertIn(code, self.context(code, True))

        def test_cap_fallback_is_not_silent_or_truncated(self):
            code = 'int f() {\n'+(' int x = 0;\n'*600)+' return x;\n}'
            value = self.context(code, True)
            self.assertIn('exceeds complete-slice cap', value)
            old = self.context(code, False).split('SRC:\n', 1)[1].split('\n\nDEP PATHS:', 1)[0]
            self.assertIn(old, value)

        def test_dependency_path_counts_stay_legacy(self):
            g = nx.MultiDiGraph(); g.add_node('n', node_type='CALL', code='p[i]')
            paths = [['n'] for _ in range(10)]
            for code in ('int f(){ return p[i]; }', 'int f(){\n'+(' x++;\n'*1000)+'return p[i]; }'):
                config.COMPLETE_SOURCE_SLICE = False
                a = typed.build_hierarchical_context(g, code, '', {}, paths)
                config.COMPLETE_SOURCE_SLICE = True
                b = typed.build_hierarchical_context(g, code, '', {}, paths)
                self.assertEqual(a.split('\n\nDEP PATHS:', 1)[1], b.split('\n\nDEP PATHS:', 1)[1])

        def test_actual_pipeline_request_matches_independent_recipe(self):
            code = 'int f(char *p, int n) {\n if (n < 1) { return 0; }\n p += 3;\n n = n - 3;\n return p[n];\n}'
            graph = nx.MultiDiGraph()
            graph.add_node('1', node_type='METHOD', code='f', name='f', line_number=1)
            graph.add_node('2', node_type='CALL', code='p[n]', name='<operator>.indirectIndexAccess', line_number=5)
            graph.add_edge('1', '2', edge_type='AST')
            def blocked(*a, **k): raise AssertionError('External access forbidden')
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory)/'source.c'; source.write_text(code, encoding='utf8')
                captured = []
                def mock(**kw):
                    captured.append(kw)
                    return SimpleNamespace(model='offline-mock', usage=SimpleNamespace(total_tokens=0, prompt_tokens=0, completion_tokens=0),
                        choices=[SimpleNamespace(finish_reason='stop', message=SimpleNamespace(content='HYPOTHESIS: no vulnerability detected\nACTION: {"action":"Stop"}'))])
                client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=mock)))
                with patch.object(api, 'create_client', blocked), patch.object(socket.socket, 'connect', blocked), \
                        patch('subprocess.Popen', blocked), patch.object(pipeline, 'build_cpg', return_value='mock'), \
                        patch.object(pipeline, 'find_export_files', return_value=('mock.dot', None)), \
                        patch.object(pipeline, 'load_graph', side_effect=lambda *a, **k: graph.copy()), contextlib.redirect_stdout(io.StringIO()):
                    config.COMPLETE_SOURCE_SLICE = False
                    a = pipeline.run_hgl_pipeline(str(source), code, 'mock', directory, client, 4096, return_details=True)
                    config.COMPLETE_SOURCE_SLICE = True
                    b = pipeline.run_hgl_pipeline(str(source), code, 'mock', directory, client, 4096, return_details=True)
                self.assertEqual(len(captured), 2)
                compare_source_requests(captured[0], captured[1], code)
                self.assertEqual(a['prediction'], b['prediction'])
                self.assertEqual(a['orig_nodes'], b['orig_nodes'])
                self.assertEqual(a['compressed_nodes'], b['compressed_nodes'])
                self.assertEqual(captured[1]['max_tokens'], 150)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(IsolatedPolicyTests))
    return result.wasSuccessful()


if __name__ == '__main__':
    if '--isolated-tests' in sys.argv: raise SystemExit(0 if isolated_suite() else 1)
    unittest.main()
