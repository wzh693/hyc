import unittest
import networkx as nx
from graph.security_net_graph import zero_token_graph_verify


def graph(codes, edges):
    g = nx.MultiDiGraph()
    for n, text in enumerate(codes):
        g.add_node(n, code=text, node_type='CALL')
    for a, b, kind in edges:
        g.add_edge(a, b, edge_type=kind)
    return g


class GraphSecurityTests(unittest.TestCase):
    def verdict(self, codes, edges, paths=None):
        g = graph(codes, edges)
        return zero_token_graph_verify(0, g, paths if paths is not None else [list(g)])

    def test_exclusive_free_and_use(self):
        pred, _ = self.verdict(['flag', 'free(p)', 'p[0]'], [(0,1,'CFG'), (0,2,'CFG')])
        self.assertEqual(pred, 0)

    def test_exclusive_frees(self):
        pred, _ = self.verdict(['flag', 'free(p)', 'free(p)'], [(0,1,'CFG'), (0,2,'CFG')])
        self.assertEqual(pred, 0)

    def test_reachable_use_and_double_free(self):
        for end in ['p[0]', 'free(p)']:
            pred, audit = self.verdict(['free(p)', end], [(0,1,'CFG')])
            self.assertEqual(pred, 1)
            self.assertEqual(audit['audit_tokens'], 0)

    def test_reassignment_kills_lifetime(self):
        pred, _ = self.verdict(['free(p)', 'p = alloc()', 'p[0]'],
                               [(0,1,'CFG'), (1,2,'CFG')])
        self.assertEqual(pred, 0)

    def test_sink_must_be_retrieved(self):
        pred, _ = self.verdict(['free(p)', 'p[0]'], [(0,1,'CFG')], [[0]])
        self.assertEqual(pred, 0)

    def test_ast_cannot_prove_execution(self):
        pred, _ = self.verdict(['free(p)', 'p[0]'], [(0,1,'AST')])
        self.assertEqual(pred, 0)

    def test_taint_needs_same_argument_and_data_flow(self):
        edges = [(0,1,'CFG'), (0,1,'REACHING_DEF')]
        for source, sink, expected in [('read(fd,a,n)', 'system(fixed_command)', 0),
                                       ('read(fd,a,n)', 'system(a)', 1)]:
            pred, _ = self.verdict([source, sink], edges)
            self.assertEqual(pred, expected)
        self.assertEqual(self.verdict(['read(fd,a,n)', 'system(a)'], [(0,1,'CFG')])[0], 0)

    def test_body_nodes_and_comments_do_not_trigger(self):
        g = graph(['free(p); p[0]'], [(0,0,'CFG')])
        g.nodes[0]['node_type'] = 'BLOCK'
        self.assertEqual(zero_token_graph_verify(0,g,[[0]])[0], 0)
        self.assertEqual(self.verdict(['/* free(p) */', 'p[0]'], [(0,1,'CFG')])[0], 0)

    def test_positive_is_preserved_missing_graph(self):
        self.assertEqual(zero_token_graph_verify(1, nx.MultiDiGraph(), [])[0], 1)

    def test_pointer_clearing_release_not_plain_double_free(self):
        self.assertEqual(self.verdict(['av_freep(&p)', 'av_freep(&p)'], [(0,1,'CFG')])[0], 0)


if __name__ == '__main__': unittest.main()
