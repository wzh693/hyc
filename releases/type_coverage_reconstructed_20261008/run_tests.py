"""Portable offline checks. Synthetic/fixed answers are not model quality scores."""
import contextlib
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import socket
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
PROFILE = json.loads((ROOT/'profile.json').read_text(encoding='utf-8-sig'))
os.environ.update(PROFILE['settings'])
os.environ.update(OPENAI_API_KEY='offline-not-a-key', OPENAI_BASE_URL='https://api.deepseek.com/v1',
                  LLM_MODEL='deepseek-chat')
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT/'src'))
import config
import networkx as nx
pipeline = importlib.import_module('graph.pipeline')
loop = importlib.import_module('reasoning.reasoning_loop')
api = importlib.import_module('reasoning.llm_api')
prompts = importlib.import_module('reasoning.prompts')
importlib.import_module('learning.scorer')


class PortableBaselineTests(unittest.TestCase):
    def test_complete_source_hashes(self):
        self.assertEqual(len(PROFILE['source_hashes']), 47)
        for name, expected in PROFILE['source_hashes'].items():
            self.assertEqual(hashlib.sha256((ROOT/'src'/name).read_bytes()).hexdigest(), expected, name)

    def test_isolated_imports_and_effective_flags(self):
        for module in (config, pipeline, loop, api, prompts):
            self.assertTrue(Path(module.__file__).resolve().is_relative_to(ROOT/'src'))
        for name, expected in PROFILE['settings'].items():
            if hasattr(config, name):
                actual = getattr(config, name)
                value = expected == '1' if isinstance(actual, bool) else int(expected) if isinstance(actual, int) else expected
                self.assertEqual(actual, value, name)

    def test_type_coverage_and_verdict_vocabulary(self):
        prompt = prompts.get_system_prompt('SRC:\nint n = a[i];')
        self.assertIn('Out-of-Bounds Read', prompt)
        self.assertIn('Integer Overflow', prompt)
        for text, expected in [('out-of-bounds read', 'Out-of-Bounds Read'),
                               ('integer overflow', 'Integer Overflow'), ('use-after-free', 'Use-After-Free'),
                               ('no vulnerability detected', 'Unknown')]:
            self.assertEqual(loop._extract_vulnerability_type('HYPOTHESIS: '+text), expected)

    def test_actual_pipeline_with_observed_mock_client(self):
        source = ROOT/'fixtures/read_index.c'
        code = source.read_text(encoding='utf8')
        graph = nx.MultiDiGraph()
        graph.add_node('1', node_type='METHOD', code='read_index', name='read_index', line_number=1)
        graph.add_node('2', node_type='CALL', code='buffer == 0', name='<operator>.equals', line_number=2)
        graph.add_node('3', node_type='CALL', code='buffer[index]', name='<operator>.indirectIndexAccess', line_number=3)
        graph.add_edge('1', '2', edge_type='AST')
        graph.add_edge('2', '3', edge_type='CFG')
        graph.add_edge('2', '3', edge_type='REACHING_DEF')
        def blocked(*a, **kw): raise AssertionError('External access forbidden in portable tests')
        for verdict, expected in [('out-of-bounds read', 1), ('integer overflow', 1),
                                  ('use-after-free', 1), ('no vulnerability detected', 0)]:
            requests = []
            def fake(**request):
                requests.append(request)
                answer = 'OBSERVATION: mock fixture\nHYPOTHESIS: '+verdict+'\nREASONING: fixed mock answer\nACTION: {"action":"Stop","reason":"fixture"}'
                return SimpleNamespace(model='offline-mock', usage=SimpleNamespace(total_tokens=0, prompt_tokens=0, completion_tokens=0),
                    choices=[SimpleNamespace(finish_reason='stop', message=SimpleNamespace(content=answer))])
            client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=fake)))
            with patch.object(api, 'create_client', blocked), patch.object(socket.socket, 'connect', blocked), \
                    patch('subprocess.Popen', blocked), patch.object(pipeline, 'build_cpg', return_value='offline-export'), \
                    patch.object(pipeline, 'find_export_files', return_value=('offline.dot', None)), \
                    patch.object(pipeline, 'load_graph', side_effect=lambda *a, **k: graph.copy()), \
                    patch.object(pipeline.os, 'makedirs'), contextlib.redirect_stdout(io.StringIO()):
                result = pipeline.run_hgl_pipeline(str(source), code, 'mock', str(ROOT/'fixtures'), client, 4096, return_details=True)
            self.assertEqual(result['prediction'], expected)
            self.assertEqual(len(requests), 1)
            self.assertEqual(requests[0]['max_tokens'], 150)
            self.assertEqual(result['reasoning_steps'], 1)

    def test_aggregate_result_does_not_claim_historical_score(self):
        result = json.loads((ROOT/'smoke_summary.json').read_text(encoding='utf-8-sig'))
        self.assertEqual(result['scheduled_results'], 60)
        self.assertEqual(result['api_accounting']['successful_invocations'], 60)
        self.assertEqual(result['first_requests_verified'], 60)
        self.assertFalse(PROFILE['historical_score_transferable'])
        self.assertNotEqual(result['metrics']['1']['f1'], PROFILE['historical_f1_reference'])


if __name__ == '__main__': unittest.main(verbosity=2)
