"""Model output contract and token receipts, without network calls."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from reasoning.llm_api import query_llm, get_call_metadata, reset_call_metadata
from reasoning.prompts import get_system_prompt


class ReceiptTests(unittest.TestCase):
    def test_type_routing_uses_operations_not_metadata(self):
        from reasoning.prompts import needs_expanded_types
        self.assertTrue(needs_expanded_types('SRC:\nx = a[i];\n\nDEP PATHS:\nnone'))
        self.assertTrue(needs_expanded_types('SRC:\nsize = n * width;\n\nDEP PATHS:\nnone'))
        self.assertFalse(needs_expanded_types('SRC:\nfree(p);\n\nDEP PATHS:\nCALL[x] CWE-190'))
        self.assertFalse(needs_expanded_types('SRC:\np = malloc(sizeof(*p));\n\nDEP PATHS:\nnone'))
        self.assertFalse(needs_expanded_types('SRC:\n/* x = a[i]; */ puts("size = n * width;");\n\nDEP PATHS:\nnone'))

    def test_type_coverage_only_adds_supported_types(self):
        from reasoning.prompts import SYSTEM_PROMPT
        with patch('config.COMPACT_VERDICT_PROMPT', False), patch('config.TYPE_COVERAGE_PROMPT', True):
            prompt = get_system_prompt()
        self.assertEqual(prompt, SYSTEM_PROMPT.replace('Buffer Overflow, Taint',
            'Buffer Overflow, Out-of-Bounds Read, Integer Overflow, Taint'))

    def test_compact_prompt_changes_format_not_auditing_policy(self):
        from reasoning.prompts import SYSTEM_PROMPT
        with patch('config.COMPACT_VERDICT_PROMPT', True):
            prompt = get_system_prompt()
        self.assertLess(prompt.index('HYPOTHESIS:'), prompt.index('REASONING:'))
        self.assertTrue(prompt.startswith(SYSTEM_PROMPT.split('\nFormat:', 1)[0]))

    def test_receipt_preserves_truncation_and_usage(self):
        response = SimpleNamespace(model='test-model',
            usage=SimpleNamespace(total_tokens=170, prompt_tokens=20, completion_tokens=150),
            choices=[SimpleNamespace(finish_reason='length',
                                     message=SimpleNamespace(content='HYPOTHESIS: uncertain'))])
        create = unittest.mock.Mock(return_value=response)
        client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
        answer, usage = query_llm('test', client)
        self.assertEqual(usage, 170)
        self.assertEqual(get_call_metadata()['finish_reason'], 'length')
        self.assertEqual(create.call_args.kwargs['max_tokens'], 150)
        reset_call_metadata()
        self.assertEqual(get_call_metadata(), {})


if __name__ == '__main__':
    unittest.main()
