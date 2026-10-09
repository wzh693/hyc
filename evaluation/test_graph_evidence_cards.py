"""Synthetic engineering checks, isolated from root/foundation imports."""
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'development/graph_evidence_cards_candidate_20261009/src'


class Isolation(unittest.TestCase):
    def test_isolated_suite(self):
        result=subprocess.run([sys.executable,'-B',str(Path(__file__).resolve()),'--isolated'],cwd=ROOT,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('Ran 10 tests',result.stderr)


def isolated():
    sys.path.insert(0,str(SOURCE))
    import networkx as nx
    from linearization.evidence_cards import pack_graph_evidence, read_names, ancestors, arguments
    class Cards(unittest.TestCase):
        def graph(self):
            g=nx.MultiDiGraph()
            for nid,code,name in [('u','n -= off','<operator>.assignmentMinus'),
                ('r','memcpy(destination_buffer, source_buffer + off, n)','memcpy'),
                ('c','n > 0','<operator>.greaterThan'),('d','destination_buffer = malloc(n)','<operator>.assignment'),
                ('z','off += 1','<operator>.assignmentPlus')]:
                g.add_node(nid,code=code,name=name,node_type='CALL')
            g.add_edge('u','r',edge_type='REACHING_DEF'); g.add_edge('c','r',edge_type='CDG')
            g.add_edge('d','r',edge_type='DFG'); g.add_edge('z','r',edge_type='CFG')
            return g
        def pack(self,g=None,budget=260,path=None):
            return pack_graph_evidence(g if g is not None else self.graph(),path or ['d','r'],budget,lambda node:'')
        def test_long_node_whole(self):
            g=self.graph(); self.assertGreater(len(g.nodes['r']['code']),35)
            self.assertIn(g.nodes['r']['code'],self.pack(g))
        def test_upstream_update_not_on_path(self):
            text=self.pack(); self.assertIn('UPSTREAM_UPDATE#u:n -= off',text)
        def test_cfg_not_dependence(self):
            self.assertNotIn('off += 1',self.pack())
        def test_destination_not_source_capacity(self):
            self.assertNotIn('UPSTREAM_UPDATE#d',self.pack())
        def test_overbudget_no_partial_expression(self):
            g=self.graph(); g.nodes['r']['code']='memcpy(d, '+('p_'*160)+', n)'
            text=self.pack(g)
            self.assertNotIn('memcpy',text); self.assertLessEqual(len(text),260)
            receipt=next(iter(g.graph['display_selection_receipt'].values()))
            self.assertTrue(any(x['node']=='r' and x['reason']=='whole_expression_over_budget' for x in receipt['omitted']))
        def test_guard_not_dominance(self):
            text=self.pack(); self.assertIn('scope unknown',text); self.assertIn('UPSTREAM_CONDITION#c:n > 0',text)
        def test_witness_chain(self):
            g=self.graph(); self.pack(g)
            receipt=next(iter(g.graph['display_selection_receipt'].values()))
            self.assertEqual(receipt['witnesses']['u'],[('u','r',0,'REACHING_DEF')])
        def test_traversal_bounded(self):
            g=self.graph()
            for i in range(180): g.add_node(str(i),code='n -= 1'); g.add_edge(str(i),'r',edge_type='DFG')
            found,capped=ancestors(g,'r'); self.assertLessEqual(len(found),128); self.assertTrue(capped)
        def test_read_decoys_and_write_only(self):
            g=self.graph(); g.add_node('x',node_type='CALL',name='<operator>.indexAccess',code='p[i]')
            g.add_node('a',node_type='CALL',name='<operator>.assignment',code='p[i] = v')
            g.add_edge('a','x',edge_type='AST'); self.assertIsNone(read_names(g,'x'))
            g.nodes['r']['code']='"memcpy(d,p,n)"'; self.assertIsNone(read_names(g,'r'))
        def test_arguments_and_tiny_budget(self):
            self.assertEqual(arguments('f(p+(i*2), n)'),['p+(i*2)','n'])
            self.assertIsNone(arguments('f(p[), n)')); self.assertEqual(self.pack(budget=0),'')
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Cards))
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__=='__main__':
    if '--isolated' in sys.argv: isolated()
    unittest.main()
