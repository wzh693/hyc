"""Active foundation identity and synthetic graph-guided wiring; zero LLM calls."""
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
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'development/type_coverage_reconstructed_20261008/src'
BASE = ROOT/'baselines/type_coverage_reconstructed_20261008/baseline.json'


def verify_foundation():
    receipt = json.loads(BASE.read_text(encoding='utf-8-sig'))
    names = {p.relative_to(SOURCE).as_posix() for p in SOURCE.rglob('*.py')}
    if names != {name.replace('\\', '/') for name in receipt['code_hashes']}:
        raise ValueError('Active source inventory differs from frozen foundation')
    for name, expected in receipt['code_hashes'].items():
        if hashlib.sha256((SOURCE/name).read_bytes()).hexdigest() != expected:
            raise ValueError('Active foundation changed: '+name)
    return receipt


class FoundationTests(unittest.TestCase):
    def test_all_47_active_source_hashes(self):
        self.assertEqual(len(verify_foundation()['code_hashes']), 47)

    def test_isolated_graph_guided_pipeline(self):
        result = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), '--isolated'],
                                capture_output=True, encoding='utf8', errors='replace')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)


def isolated_suite():
    receipt = verify_foundation()
    os.environ.update(receipt['settings'])
    os.environ.update(OPENAI_API_KEY='offline-not-a-key', COMPLETE_SOURCE_SLICE='1')
    # Even an obsolete candidate environment flag cannot change the restored code.
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(SOURCE))
    import networkx as nx
    config = importlib.import_module('config')
    typed = importlib.import_module('linearization.typed_paths')
    pipeline = importlib.import_module('graph.pipeline')
    api = importlib.import_module('reasoning.llm_api')

    class GraphGuidedTests(unittest.TestCase):
        def test_rejected_candidate_absent_and_settings_preserved(self):
            self.assertFalse(hasattr(config, 'COMPLETE_SOURCE_SLICE'))
            self.assertTrue(config.TYPE_COVERAGE_PROMPT)
            self.assertFalse(config.FOCUSED_GRAPH_ANCHORS)
            self.assertEqual(config.MAX_REASONING_STEPS, 2)

        def test_anchor_scope_is_current_graph_not_topk_only(self):
            graph = nx.MultiDiGraph()
            graph.add_node('read', code='source[index]', node_type='CALL')
            graph.add_node('other', code='capacity = n', node_type='CALL')
            anchors = typed._collect_graph_anchors(graph, [['read']])
            self.assertIn(typed._norm_code('capacity = n'), anchors)
            self.assertEqual(anchors, typed._collect_graph_anchors(graph, []))
            # Diagnostic invariant of the chosen base, not an assertion of quality.

        def test_real_pipeline_uses_graph_and_bounded_mock_request(self):
            code = 'int f(char *p, int n) {\n if (n < 1) { return 0; }\n return p[0];\n}'
            graph = nx.MultiDiGraph()
            graph.add_node('1', node_type='METHOD', code='f', name='f', line_number=1)
            graph.add_node('2', node_type='CALL', code='p[0]', name='<operator>.indirectIndexAccess', line_number=3)
            graph.add_edge('1', '2', edge_type='AST')
            captured = []
            def blocked(*args, **kwargs):
                raise AssertionError('External access forbidden in offline test')
            def mock(**kwargs):
                captured.append(kwargs)
                return SimpleNamespace(model='offline-mock', usage=SimpleNamespace(total_tokens=0, prompt_tokens=0, completion_tokens=0),
                    choices=[SimpleNamespace(finish_reason='stop', message=SimpleNamespace(content='HYPOTHESIS: no vulnerability detected\nACTION: {"action":"Stop"}'))])
            client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=mock)))
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory)/'source.c'
                source.write_text(code, encoding='utf8')
                with patch.object(api, 'create_client', blocked), patch.object(socket.socket, 'connect', blocked), \
                        patch('subprocess.Popen', blocked), patch.object(pipeline, 'build_cpg', return_value='mock'), \
                        patch.object(pipeline, 'find_export_files', return_value=('mock.dot', None)), \
                        patch.object(pipeline, 'load_graph', side_effect=lambda *a, **k: graph.copy()), \
                        patch.object(pipeline, 'summarize_graph', wraps=pipeline.summarize_graph) as compression, \
                        patch.object(pipeline, 'retrieve_topk', wraps=pipeline.retrieve_topk) as retrieval, \
                        contextlib.redirect_stdout(io.StringIO()):
                    result = pipeline.run_hgl_pipeline(str(source), code, 'mock', directory, client, 4096, return_details=True)
                self.assertEqual(compression.call_count, 1)
                self.assertEqual(retrieval.call_count, 1)
                self.assertEqual(len(captured), 1)
                self.assertEqual(captured[0]['max_tokens'], 150)
                prompt = captured[0]['messages'][1]['content']
                self.assertTrue(prompt.startswith('SRC:\n'))
                self.assertIn('\n\nDEP PATHS:', prompt)
                self.assertIn('STATE:', prompt)
                self.assertEqual(result['reasoning_steps'], 1)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(GraphGuidedTests))
    return result.wasSuccessful()


if __name__ == '__main__':
    if '--isolated' in sys.argv:
        raise SystemExit(0 if isolated_suite() else 1)
    unittest.main()
