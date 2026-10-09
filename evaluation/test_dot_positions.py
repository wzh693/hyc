import contextlib
import io
import unittest
from unittest.mock import mock_open,patch
from graph.load_graph import load_graph_from_dot


class PositionTests(unittest.TestCase):
    def load(self,text):
        with patch('graph.load_graph.os.path.exists',return_value=True), \
                patch('builtins.open',mock_open(read_data=text)),contextlib.redirect_stdout(io.StringIO()):
            return load_graph_from_dot('mock.dot')

    def test_quoted_and_unquoted_positions(self):
        g=self.load('"1" [label="CALL" CODE="p[0]" LINE_NUMBER="3" COLUMN_NUMBER="5"];\n'
                    '"2" [label="CALL" CODE="free(p)" LINE_NUMBER=7 COLUMN_NUMBER=2];')
        self.assertEqual(g.nodes['1']['line_number'],3)
        self.assertEqual(g.nodes['1']['column_number'],5)
        self.assertEqual(g.nodes['2']['line_number'],7)

    def test_literal_cannot_spoof_line_number(self):
        g=self.load('"1" [label="CALL" CODE="log(LINE_NUMBER=99)" LINE_NUMBER="4"];')
        self.assertEqual(g.nodes['1']['line_number'],4)

    def test_no_position_is_not_invented(self):
        g=self.load('"1" [label="CALL" CODE="puts(\\\"LINE_NUMBER=12\\\")" NAME="puts"];')
        self.assertNotIn('line_number',g.nodes['1'])


if __name__=='__main__':unittest.main()
