"""Reuse atomic policy tests plus strict AST ownership regressions in isolation."""
import subprocess
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]


class V2(unittest.TestCase):
    def test_v2_isolated(self):
        result=subprocess.run([sys.executable,'-B',str(Path(__file__).resolve()),'--isolated'],cwd=ROOT,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)


def isolated():
    sys.path.insert(0,str(ROOT))
    from evaluation import test_graph_evidence_cards as old
    old.SOURCE=ROOT/'development/graph_evidence_cards_v2_candidate_20261009/src'
    # Run extra ownership cases first; old suite then exits with its own status.
    sys.path.insert(0,str(old.SOURCE))
    import networkx as nx
    from linearization.evidence_cards import pack_graph_evidence,assignment_lhs
    class Ownership(unittest.TestCase):
        def graph(self):
            g=nx.MultiDiGraph()
            for nid,code,name,kind in [('r','memcpy(d,p,n)','memcpy','CALL'),
                ('i','n','n','IDENTIFIER'),('u','n = end - p','<operator>.assignment','CALL'),
                ('a','end - p','<operator>.subtraction','CALL')]:
                g.add_node(nid,code=code,name=name,node_type=kind)
            g.add_edge('u','i',edge_type='AST');g.add_edge('i','r',edge_type='REACHING_DEF')
            return g
        def body(self,g): return pack_graph_evidence(g,['i','r'],260,lambda node:'')
        def test_owned_expression_restored(self):
            g=self.graph();self.assertIn('AST_BOUND_UPDATE#u:n = end - p',self.body(g))
            receipt=next(iter(g.graph['display_selection_receipt'].values()))
            self.assertEqual(receipt['witnesses']['u'],[('u','i',0,'AST'),('i','r',0,'REACHING_DEF')])
        def test_no_dependency_no_restoration(self):
            g=self.graph();g.remove_edge('i','r');g.add_edge('i','r',edge_type='CFG')
            self.assertNotIn('n = end - p',self.body(g))
        def test_ambiguous_parent_refused(self):
            g=self.graph();g.add_node('v',code='n = 4',name='<operator>.assignment',node_type='CALL');g.add_edge('v','i',edge_type='AST')
            self.assertNotIn('n = end - p',self.body(g));self.assertNotIn('n = 4',self.body(g))
        def test_wrong_lhs_refused(self):
            g=self.graph();g.nodes['u']['code']='d = n';self.assertNotIn('d = n',self.body(g))
        def test_preincrement_binding(self):
            self.assertEqual(assignment_lhs(dict(node_type='CALL',name='<operator>.preIncrement',code='++n')),'n')
        def test_method_cannot_bridge(self):
            g=self.graph();g.remove_edge('i','r');g.add_node('m',code='whole body',node_type='METHOD')
            g.add_edge('i','m',edge_type='DFG');g.add_edge('m','r',edge_type='DFG')
            self.assertNotIn('n = end - p',self.body(g))
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Ownership))
    if not result.wasSuccessful(): raise SystemExit(1)
    old.isolated()


if __name__=='__main__':
    if '--isolated' in sys.argv: isolated()
    unittest.main()
