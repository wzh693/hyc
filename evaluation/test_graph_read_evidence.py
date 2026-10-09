"""Audit rules only; do not certify predictions or safety."""
import unittest
from evaluation.audit_graph_read_evidence import extract_facts, related_facts, sections, matching_nodes, summarize
import networkx as nx


class ReadEvidenceTests(unittest.TestCase):
    def test_comments_and_strings_do_not_create_reads(self):
        reads, _, _ = extract_facts('/* memcpy(d,s,n); */\nchar *x="a[i] strchr(p,0)";\n// return *p;\nreturn a[i];')
        self.assertEqual(len(reads), 1)
        self.assertEqual(reads[0]['line'], 4)

    def test_copy_uses_source_and_scan_contract_stays_unknown(self):
        reads, _, _ = extract_facts("memcpy(dest, source + off, width);\nptr = strchr(line, ' ');")
        self.assertEqual(reads[0]['target'], 'source + off')
        self.assertEqual(reads[0]['width'], 'width')
        self.assertEqual(reads[1]['target'], 'line')
        self.assertIsNone(reads[1]['width'])
        self.assertEqual(reads[1]['capacity_contract'], 'unknown')

    def test_comparison_reads_both_inputs_and_nested_args(self):
        reads, _, _ = extract_facts('memcmp(a, helper(b, c), n);')
        self.assertEqual([r['target'] for r in reads], ['a', 'helper(b, c)'])

    def test_index_write_and_declaration_not_counted_as_reads(self):
        reads, _, _ = extract_facts('char buffer[100];\na[i] = 0;\na[i] += b[j];\nreturn a[k];')
        self.assertEqual([r['offset'] for r in reads], ['i', 'j', 'k'])

    def test_inline_function_array_read_not_treated_as_declaration(self):
        reads, _, _ = extract_facts('int f() { return a[i]; }')
        self.assertEqual(len(reads), 1)

    def test_relation_is_not_an_ordering_proof(self):
        reads, updates, guards = extract_facts('return p[n];\nn -= off;\nif (n < total) {}\nif (unrelated < 0) {}')
        us, gs = related_facts(reads[0], updates, guards)
        self.assertEqual(len(us), 1)
        self.assertEqual(len(gs), 1)
        self.assertGreater(us[0]['line'], reads[0]['line'])

    def test_unknown_element_width_description_is_not_source_variable(self):
        reads, updates, guards = extract_facts('return p[i];\nwidth = capacity;\nif (width < 0) {}')
        us, gs = related_facts(reads[0], updates, guards)
        self.assertEqual(us, [])
        self.assertEqual(gs, [])

    def test_whole_body_or_wrong_line_is_not_operation_mapping(self):
        graph = nx.MultiDiGraph()
        graph.add_node('body', node_type='BLOCK', code='return p[n];', line_number=12)
        graph.add_node('wrong', node_type='CALL', code='p[n]', line_number=13)
        graph.add_node('actual', node_type='CALL', code='p[n]', line_number=12)
        value = dict(expression='p[n]', line=2, end_line=2)
        self.assertEqual(matching_nodes(graph, value, 10), {'actual'})

    def test_context_sections_do_not_include_state_or_exploration(self):
        self.assertEqual(sections('SRC:\np[i]\n\nDEP PATHS:\nP1: p[i]\n\nSTATE:\nstate\n\nEXPLORATION STATE:\nmore'), ('p[i]', 'P1: p[i]'))

    def test_failure_remains_in_scheduled_denominator(self):
        values = summarize([dict(idx=0, cwe='x', source_sha256='s', group_id='g', error='failed')])['all']
        self.assertEqual(values['scheduled_rows'], 1)
        self.assertEqual(values['failed_rows'], 1)
        self.assertEqual(values['source_sha256_macro']['src_exact']['eligible_units'], 0)


if __name__ == '__main__': unittest.main()
