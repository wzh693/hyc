import unittest
from unittest.mock import patch
import networkx as nx
from evaluation.audit_evidence_preservation import classify_lines, src_segment, visible_lines
from linearization.backward_slice import backward_evidence_slice


class EvidencePreservationTests(unittest.TestCase):
    def test_lineage_changes_no_slice_text_or_selection(self):
        graph = nx.MultiDiGraph()
        graph.add_node('guard', code='if (n < cap)', line_number=1)
        graph.add_node('sink', code='memcpy(dst, p, n);', line_number=2)
        graph.add_edge('guard', 'sink', edge_type='CDG')
        source = 'if (n < cap)\nmemcpy(dst, p, n);'
        with patch('config.RECORD_REASONING_TRACE', False):
            plain, a = backward_evidence_slice(graph, [['sink']], source, max_chars=20)
        with patch('config.RECORD_REASONING_TRACE', True):
            traced, b = backward_evidence_slice(graph, [['sink']], source, max_chars=20)
        self.assertEqual(plain, traced)
        self.assertEqual(a['source_lines'], b['source_lines'])
        self.assertNotIn('criteria_node_ids', a)
        self.assertEqual(b['criteria_node_ids'], ['sink'])
        self.assertEqual(b['selected_source_lines'], [1, 2])
        self.assertEqual(b['budget_omitted_source_lines'], [1])

    def test_duplicates_remain_ambiguous(self):
        visible, ambiguous = visible_lines('if (x)\nfree(p);\nfree(p);', 'free(p);')
        self.assertEqual(visible, set())
        self.assertEqual(ambiguous, {2, 3})

    def test_exact_not_substring_matching(self):
        visible, _ = visible_lines('free(ptr);\nif (n < cap)', 'free(p);\nif (n < cap)')
        self.assertEqual(visible, {2})

    def test_mask_comments_and_strings(self):
        facts = classify_lines('// free(p);\nchar *s="if (x)";\nif (n < cap)\nfree(p);')
        self.assertEqual(facts['lifetime'], {4})
        self.assertEqual(facts['guard_candidate'], {3})

    def test_section_boundary_and_absence(self):
        self.assertEqual(src_segment('SRC:\nfree(p);\n\nDEP PATHS:\nfree(q);'), 'free(p);')
        with self.assertRaises(ValueError):
            src_segment('DEP PATHS:\nfree(q);')


if __name__ == '__main__':
    unittest.main()
