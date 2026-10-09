import unittest
import networkx as nx
from linearization.evidence_groups import pack_evidence_groups


class EvidenceGroupTests(unittest.TestCase):
    def fixture(self):
        source = 'if (n > cap)\nreturn;\nmemcpy(dst,p,n);\nunrelated_padding_statement_long();'
        graph = nx.MultiDiGraph()
        for node, line in [('g',1),('e',2),('s',3),('u',4)]:
            graph.add_node(node, line_number=line, code=source.splitlines()[line-1],
                           node_type='RETURN' if node=='e' else 'CALL')
        graph.add_edge('g','s',edge_type='CDG')
        graph.add_edge('g','e',edge_type='CDG')
        graph.add_edge('g','u',edge_type='CFG')
        return graph,source

    def test_group_and_same_payload_budget(self):
        graph,source=self.fixture()
        kept,a=pack_evidence_groups(graph,['s'],source,[3,4],line_offset=0,max_chars=100)
        self.assertTrue({1,2,3} <= set(kept))
        self.assertNotIn('u',a['groups'][0]['exit_node_ids'])
        self.assertLessEqual(a['grouped_chars'],a['plain_chars'])
        self.assertLessEqual(a['grouped_utf8_bytes'],a['plain_utf8_bytes'])
        self.assertTrue(a['groups'][0]['mapped_lines_complete_in_output'])

    def test_oversize_falls_back_not_partial(self):
        graph,source=self.fixture()
        kept,a=pack_evidence_groups(graph,['s'],source,[3],line_offset=0,max_chars=100)
        self.assertEqual(kept,[3])
        self.assertTrue(a['fallback_to_plain'])
        self.assertFalse(a['groups'][0]['admitted'])

    def test_cfg_exit_is_not_control_dependency(self):
        graph,source=self.fixture()
        graph.remove_edge('g','e')
        graph.add_edge('g','e',edge_type='CFG')
        kept,a=pack_evidence_groups(graph,['s'],source,[3,4],line_offset=0,max_chars=100)
        self.assertNotIn(2,kept)
        self.assertEqual(a['groups'][0]['exit_node_ids'],[])

    def test_cap_and_offset(self):
        graph,source=self.fixture()
        for _,attrs in graph.nodes(data=True):attrs['line_number']+=10
        kept,a=pack_evidence_groups(graph,['s'],source,[3,4],line_offset=10,max_chars=100,max_nodes=1)
        self.assertEqual(kept,[3,4])
        self.assertTrue(a['groups'][0]['traversal_capped'])


if __name__=='__main__':unittest.main()
