import unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch
from evaluation.evaluate_clean_direct import call


class DirectTests(unittest.TestCase):
    def test_full_source_is_not_truncated_or_labeled(self):
        source='int f(){\n'+('x++;\n'*2000)+'return 0;\n}'
        response=SimpleNamespace(model='mock',usage=SimpleNamespace(total_tokens=100),
            choices=[SimpleNamespace(finish_reason='stop',message=SimpleNamespace(content='benign'))])
        create=Mock(return_value=response)
        client=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
        with patch('evaluation.evaluate_clean_direct.create_client',return_value=client):
            record=call({'idx':1,'target':1,'group_id':'g'},source)
        content=create.call_args.kwargs['messages'][0]['content']
        self.assertIn(source,content)
        self.assertNotIn('target',content)
        self.assertEqual(record['prediction'],0)


if __name__ == '__main__': unittest.main()
