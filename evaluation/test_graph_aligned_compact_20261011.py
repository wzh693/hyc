"""Synthetic checks, not model-quality scores. No model or network."""
import contextlib
import importlib.util
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
import networkx as nx

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'development/graph_aligned_compact_candidate_20261011/src'
spec = importlib.util.spec_from_file_location('isolated_alignment', SOURCE/'linearization/aligned_evidence.py')
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class AlignmentTests(unittest.TestCase):
    def graph(self):
        graph = nx.MultiDiGraph()
        for node,line in [('length',1),('guard',2),('read',3),('unrelated',4)]:
            graph.add_node(node, code=node, line_number=line, node_type='CALL')
        graph.add_edge('length','read',edge_type='DFG')
        graph.add_edge('guard','read',edge_type='CDG')
        graph.add_edge('unrelated','read',edge_type='CFG')
        return graph

    def test_complete_units_and_budget(self):
        graph = self.graph()
        graph.nodes['read']['code'] = 'a'*500
        text,displayed,omitted = evidence.pack_paths(graph,[['length','read'],['guard']],200)
        self.assertEqual(displayed,[['guard']])
        self.assertEqual(omitted,[['length','read']])
        self.assertEqual(json.loads(text)[0]['c'],'guard')

    def test_no_partial_long_node(self):
        graph = self.graph()
        graph.nodes['read']['code'] = 'a'*2000
        self.assertEqual(evidence.pack_paths(graph,[['read']])[0],'')

    def test_original_dependence_not_cfg(self):
        text,audit = evidence.aligned_slice(self.graph(),[['read']], 'length\nguard\nread\nunrelated')
        self.assertEqual(text,'length\nguard\nread')
        self.assertEqual(audit['criteria_node_ids'],['read'])
        self.assertNotIn('unrelated',audit['visited_node_ids'])

    def test_intermediate_node_is_criterion(self):
        _,audit = evidence.aligned_slice(self.graph(),[['length','read']], 'length\nguard\nread\nunrelated')
        self.assertEqual(audit['criteria_node_ids'],['length','read'])

    def test_unmapped_stays_unknown(self):
        graph = self.graph()
        graph.nodes['read']['line_number'] = 99
        _,audit = evidence.aligned_slice(graph,[['read']], 'length\nguard\nread\nunrelated')
        self.assertIn('read',audit['unmapped_nodes'])

    def test_empty_no_unrelated_fallback(self):
        text,audit = evidence.aligned_slice(self.graph(),[], 'length\nguard\nread\nunrelated')
        self.assertEqual(text,'')
        self.assertFalse(audit['fallback'])

    def test_whole_lines_and_offset(self):
        text,audit = evidence.aligned_slice(self.graph(),[['read']], 'guard\nread\nunrelated',1,5)
        self.assertEqual(text,'read')
        self.assertEqual(audit['source_lines'],[2])

    def test_missing_edge_rejected(self):
        with self.assertRaises(ValueError):
            evidence.pack_paths(self.graph(),[['read','length']])

    def test_synthetic_pipeline_isolated(self):
        result = subprocess.run([sys.executable,'-B',str(Path(__file__).resolve()),'--isolated'],
            cwd=ROOT,capture_output=True,text=True,encoding='utf8',errors='replace')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)


def isolated():
    receipt=json.loads((ROOT/'baselines/type_coverage_reconstructed_20261008/baseline.json').read_text(encoding='utf8'))
    os.environ.update(receipt['settings'])
    os.environ.update(OPENAI_API_KEY='offline-not-a-key',RECORD_REASONING_TRACE='1')
    sys.path.insert(0,str(SOURCE))
    from graph import pipeline
    code='int f(char *p) {\n return p[0];\n}'
    graph=nx.MultiDiGraph()
    graph.add_node('1',node_type='METHOD',code='f',name='f',line_number=1)
    graph.add_node('2',node_type='CALL',code='p[0]',name='<operator>.indirectIndexAccess',line_number=2)
    graph.add_edge('1','2',edge_type='AST')
    def blocked(*a,**k):
        raise AssertionError('External operation')
    for finish,expected in [('stop',True),('length',True)]:
        calls=[]
        def mock(**request):
            calls.append(request)
            return SimpleNamespace(model='offline-mock',usage=SimpleNamespace(total_tokens=0,prompt_tokens=0,completion_tokens=0),
                choices=[SimpleNamespace(finish_reason=finish,message=SimpleNamespace(content=
                    'HYPOTHESIS: Uncertain\nACTION: {"action":"Stop","reason":"missing bounds"}\nREASONING: Missing bounds'))])
        client=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=mock)))
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'source.c'
            source.write_text(code,encoding='utf8')
            with patch.object(socket.socket,'connect',blocked), patch('subprocess.Popen',blocked), \
                    patch.object(pipeline,'build_cpg',return_value='mock'), \
                    patch.object(pipeline,'find_export_files',return_value=('mock',None)), \
                    patch.object(pipeline,'load_graph',return_value=graph), contextlib.redirect_stdout(io.StringIO()):
                result=pipeline.run_hgl_pipeline(str(source),code,'synthetic',directory,client,return_details=True)
        assert len(calls)==1 and calls[0]['max_tokens']==150
        assert 'exactly these three lines' in calls[0]['messages'][0]['content']
        assert result['arbitrate']['decision_status']=='Uncertain'
        assert not any(n=='learning' or n.startswith('learning.') or n=='torch' for n in sys.modules)
    print('Synthetic pipeline/compact contract/truncation/no-model checks passed')


if __name__=='__main__':
    if '--isolated' in sys.argv:
        isolated()
    else:
        unittest.main()
