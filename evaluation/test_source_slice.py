import unittest
from unittest.mock import patch

from linearization.typed_paths import _slice_source


@patch('config.SOURCE_SLICE_ASSIGNMENT_FIX', True)
class SourceSliceTests(unittest.TestCase):
    def test_focused_anchors_keep_path_and_danger_not_unrelated_initializers(self):
        import networkx as nx
        from linearization.typed_paths import _collect_graph_anchors, _norm_code
        graph = nx.MultiDiGraph()
        graph.add_node('init', code='ordinary_value = 0', node_type='CALL')
        graph.add_node('size', code='size = count * width', node_type='CALL')
        graph.add_node('copy', code='memcpy(dst, src, size)', node_type='CALL')
        with patch('config.FOCUSED_GRAPH_ANCHORS', True):
            anchors = _collect_graph_anchors(graph, [['size']])
        self.assertNotIn(_norm_code('ordinary_value = 0'), anchors)
        self.assertIn(_norm_code('size = count * width'), anchors)
        self.assertIn(_norm_code('memcpy(dst, src, size)'), anchors)

    def test_size_and_index_updates_survive(self):
        code = "void f(void) {\nsize = n + 1;\ni++;\n--remaining;\n*p = value;\n}"
        result = _slice_source(code, max_chars=600)
        for statement in ("size = n + 1;", "i++;", "--remaining;", "*p = value;"):
            self.assertIn(statement, result)

    def test_block_comment_does_not_become_evidence(self):
        code = "void f(void) {\n/* example\n *p = bad;\n */\n*p = good;\n}"
        result = _slice_source(code, max_chars=600)
        self.assertNotIn("bad", result)
        self.assertIn("*p = good;", result)

    def test_recovered_statements_respect_existing_budget(self):
        code = "void f(void) {\nsize = n + 1;\n" + "\n".join(
            f"buffer[{i}] = size;" for i in range(80)
        ) + "\n}"
        self.assertLessEqual(len(_slice_source(code, max_chars=600)), 600)


if __name__ == "__main__":
    unittest.main()
