import unittest
from evaluation.compare_converged_evidence_20261011 import jaccard, compare


class EvidenceComparisonTests(unittest.TestCase):
    def test_empty_jaccard(self):
        self.assertEqual(jaccard([], []), 1.)

    def test_jaccard_set_semantics(self):
        self.assertEqual(jaccard(['a', 'a', 'b'], ['b', 'c']), 1/3)

    def test_actual_request_and_visible_change(self):
        def result(node, request):
            return dict(compression={'kept_node_ids': [node]}, selected_criteria=[node],
                trace=[dict(request=request, evidence=dict(source_lines=[1], displayed_paths=[[node]]))])
        pair = compare(result('a', 'x'), result('b', 'y'))
        self.assertTrue(pair['request_changed'])
        self.assertEqual(pair['visible_node_jaccard'], 0.)
        self.assertEqual(pair['source_line_jaccard'], 1.)


if __name__ == '__main__':
    unittest.main()
