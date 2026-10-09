"""Regression tests for the low-token vulnerability verdict parser."""

import unittest
from unittest.mock import patch
import networkx as nx

from reasoning.reasoning_loop import _extract_vulnerability_type, parse_binary_verdict


class ReasoningVerdictTests(unittest.TestCase):
    def test_prior_summary_preserves_verdict_without_growing_budget(self):
        from reasoning.prompts import _summarize_prior
        answer = ('OBSERVATION: ' + 'irrelevant ' * 40 + '\n'
                  'HYPOTHESIS: no vulnerability detected\n'
                  'REASONING: allocation size is not shown\nACTION: Stop')
        summary = _summarize_prior(answer)
        self.assertLessEqual(len(summary), 150)
        self.assertIn('no vulnerability detected', summary)
        self.assertIn('allocation size is not shown', summary)
        self.assertEqual(_summarize_prior('plain answer'), 'plain answer')

    def test_evidence_routing_requires_both_gap_and_expansion(self):
        from reasoning.reasoning_loop import _needs_evidence_expansion
        self.assertTrue(_needs_evidence_expansion('allocation size is not shown', 'ExpandDFG'))
        self.assertFalse(_needs_evidence_expansion('allocation size is not shown', 'Stop'))
        self.assertFalse(_needs_evidence_expansion('the size is bounded', 'ExpandDFG'))

    def test_sink_does_not_block_requested_second_pass(self):
        from reasoning.reasoning_loop import reasoning_loop
        graph = nx.MultiDiGraph()
        graph.add_node('source', code='size = n * width', node_type='CALL')
        graph.add_node('copy', code='memcpy(dst, src, size)', node_type='CALL')
        graph.add_edge('source', 'copy', edge_type='REACHING_DEF')
        first = ('HYPOTHESIS: no vulnerability detected\n'
                 'REASONING: allocation size is not shown\n'
                 'ACTION: {"action":"ExpandDFG","reason":"size origin missing"}')
        second = 'HYPOTHESIS: integer overflow\nREASONING: size wraps before copy'
        with patch('config.USE_ZERO_TOKEN_SECURITY_NET', True), \
                patch('config.F1_EVIDENCE_ROUTING', True), \
                patch('reasoning.reasoning_loop.MAX_REASONING_STEPS', 2), \
                patch('reasoning.reasoning_loop.query_llm_with_retry',
                      side_effect=[(first, 42), (second, 31)]) as query:
            result = reasoning_loop(graph, [['copy']], 'memcpy(dst, src, size);', '', {})
        self.assertEqual(query.call_count, 2)
        self.assertEqual(result['vulnerability_type'], 'Integer Overflow')
        self.assertEqual(result['tokens_used'], 73)
    def test_structural_verifier_does_not_inherit_api_presence_override(self):
        from reasoning.reasoning_loop import reasoning_loop
        graph = nx.MultiDiGraph()
        graph.add_node('copy', code='memcpy(dst, src, n)', node_type='CALL')
        answer = 'HYPOTHESIS: buffer overflow (unverified -- insufficient evidence)'
        with patch('reasoning.reasoning_loop.query_llm_with_retry', return_value=(answer, 42)) as query:
            with patch('config.USE_ZERO_TOKEN_SECURITY_NET', True):
                result = reasoning_loop(graph, [['copy']], 'memcpy(dst, src, n);', '', {})
            self.assertEqual(result['vulnerability_type'], 'Unknown')
            self.assertEqual(result['tokens_used'], 42)
            self.assertEqual(query.call_count, 1)
            with patch('config.USE_ZERO_TOKEN_SECURITY_NET', False):
                legacy = reasoning_loop(graph, [['copy']], 'memcpy(dst, src, n);', '', {})
            self.assertEqual(legacy['vulnerability_type'], 'Generic Vulnerability')

    def test_extracts_sven_cwe_125_vocabulary(self):
        self.assertEqual(_extract_vulnerability_type(
            "HYPOTHESIS: out-of-bounds read\nREASONING: index exceeds length"
        ), "Out-of-Bounds Read")
        self.assertEqual(_extract_vulnerability_type(
            "HYPOTHESIS: OOB write\nREASONING: copy exceeds destination"
        ), "Buffer Overflow")

    def test_extracts_sven_cwe_190_vocabulary(self):
        self.assertEqual(_extract_vulnerability_type(
            "HYPOTHESIS: integer overflow\n"
            "REASONING: multiplication wraps before allocation"
        ), "Integer Overflow")
        self.assertEqual(parse_binary_verdict(
            "integer overflow before allocation"
        ), 1)

    def test_explicit_negative_still_wins_over_vulnerability_terms(self):
        self.assertEqual(_extract_vulnerability_type(
            "HYPOTHESIS: no vulnerability detected\n"
            "REASONING: integer overflow is guarded"
        ), "Unknown")
        self.assertEqual(parse_binary_verdict(
            "no vulnerability: integer overflow is checked"
        ), 0)
        self.assertEqual(_extract_vulnerability_type(
            "HYPOTHESIS: buffer overflow (unverified -- insufficient evidence)"
        ), "Unknown")


if __name__ == "__main__":
    unittest.main()
