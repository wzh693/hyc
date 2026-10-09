import unittest
import networkx as nx
from linearization.evidence_windows import source_windows


class WindowTests(unittest.TestCase):
    def test_retains_local_guard_operation_and_return(self):
        src='int f(){\n if (bad) {\n free(p);\n return 0;\n }\n use(p);\n}'
        g=nx.MultiDiGraph(); g.add_node(1,node_type='CALL',code='free(p)',line_number=3)
        out=source_windows(src,g,[[1]],100)
        self.assertIn('if (bad)',out); self.assertIn('free(p);',out); self.assertIn('return 0;',out)

    def test_budget_never_clips_operation(self):
        src='int f(){\n strcpy(destination, extremely_long_source_expression);\n}'
        g=nx.MultiDiGraph(); g.add_node(1,node_type='CALL',code='strcpy(a,b)',line_number=2)
        out=source_windows(src,g,[],20)
        self.assertLessEqual(len(out),20); self.assertNotIn('strcpy',out)

    def test_body_and_literal_not_operation(self):
        src='int f(){\n puts("free(p)");\n}'
        g=nx.MultiDiGraph(); g.add_node(1,node_type='BLOCK',code=src,line_number=1)
        self.assertEqual(source_windows(src,g,[],100),'')

    def test_source_literals_are_preserved(self):
        src='int f(){\n strcpy(p, "a b");\n return 0;\n}'
        g=nx.MultiDiGraph(); g.add_node(1,node_type='CALL',code='strcpy(p,"a b")',line_number=2)
        self.assertIn('"a b"',source_windows(src,g,[],100))

    def test_multiline_signature(self):
        src='int f(int x,\n int y)\n{\n free(p);\n return 0;\n}'
        g=nx.MultiDiGraph(); g.add_node(1,node_type='CALL',code='free(p)',line_number=4)
        self.assertIn('int y)',source_windows(src,g,[],100))


if __name__ == '__main__': unittest.main()
