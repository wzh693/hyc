import unittest
from evaluation.build_clean_protocol import code_hash, Groups


class CleanProtocolTests(unittest.TestCase):
    def test_split_validator_rejects_shared_commit(self):
        from evaluation.verify_clean_protocol import validate
        def row(idx):
            return {'idx':idx,'source_sha256':str(idx),'group_id':str(idx),
                    'project':'p','commit_id':'same'}
        with self.assertRaises(ValueError): validate({'dev':[row(0)],'test':[row(1)]})

    def test_model_change_invalidates_prediction_cache(self):
        from unittest.mock import patch
        from modes.compare_devign import _pipeline_fingerprint
        with patch('config.LLM_MODEL','control-model'):
            baseline = _pipeline_fingerprint()
        with patch('config.LLM_MODEL','different-model'):
            self.assertNotEqual(baseline,_pipeline_fingerprint())

    def test_format_and_comments_are_grouped(self):
        self.assertEqual(code_hash('int f(){return x+1;}'), code_hash('int f() { /*note*/ return x + 1; }'))

    def test_literal_whitespace_is_not_erased(self):
        self.assertNotEqual(code_hash('puts("a b");'), code_hash('puts("ab");'))

    def test_comment_marker_in_literal_is_preserved(self):
        self.assertNotEqual(code_hash('puts("//x");'),code_hash('puts("//y");'))

    def test_connected_groups_are_transitive(self):
        g = Groups(4); g.join(0,1); g.join(1,2)
        self.assertEqual(g.find(0),g.find(2))
        self.assertNotEqual(g.find(0),g.find(3))


if __name__ == '__main__': unittest.main()
