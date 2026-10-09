import unittest
from unittest.mock import patch,Mock
from types import SimpleNamespace
import networkx as nx
from evaluation.evaluate_full_graph_pairs import graph_facts,pair


class FullGraphTests(unittest.TestCase):
    def test_body_and_ast_not_graph_operation_facts(self):
        g=nx.MultiDiGraph()
        g.add_node(1,node_type='BLOCK',code='free(p);',line_number=1)
        g.add_node(2,node_type='CALL',code='free(p)',line_number=2)
        g.add_node(3,node_type='RETURN',code='return 0;',line_number=3)
        g.add_edge(1,2,edge_type='CFG');g.add_edge(2,3,edge_type='AST')
        self.assertEqual(graph_facts(g),'')
        g.add_edge(2,3,edge_type='CFG')
        self.assertIn('--CFG-->',graph_facts(g))
        self.assertLessEqual(len(graph_facts(g,10)),10)

    def test_same_full_source_and_output_budget(self):
        response=SimpleNamespace(model='mock',usage=SimpleNamespace(total_tokens=10),
            choices=[SimpleNamespace(message=SimpleNamespace(content='benign'),finish_reason='stop')])
        create=Mock(return_value=response)
        client=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
        with patch('evaluation.evaluate_full_graph_pairs.create_client',return_value=client):
            rows=pair({'idx':2,'target':1,'group_id':'g'},'int f(){return 0;}','L1 --CFG--> L2')
        self.assertEqual(create.call_count,2)
        self.assertTrue(all(c.kwargs['max_tokens']==16 for c in create.call_args_list))
        self.assertEqual(rows[0]['source_prompt_sha256'],rows[1]['source_prompt_sha256'])
        self.assertTrue(all(r['prediction']==0 for r in rows))


if __name__=='__main__':unittest.main()
