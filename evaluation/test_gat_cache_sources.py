import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from learning.train_gat import load_cache_sources


class CacheSourcesTests(unittest.TestCase):
    def test_duplicate_ids_fail_instead_of_overwriting(self):
        with tempfile.TemporaryDirectory() as directory:
            paths=[Path(directory)/x for x in ('a','b')]
            for path in paths:
                path.mkdir();(path/'meta.json').write_text(json.dumps({'f':{'target':1,'idx':1}}))
            with patch('learning.train_gat._load_or_build_graphs',return_value={'f':{}}):
                with self.assertRaises(ValueError):load_cache_sources([str(p) for p in paths])

    def test_separate_metadata_bound_and_failures_counted(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory);(path/'meta.json').write_text(json.dumps({'f':{'target':1,'idx':1},'bad':{'idx':2,'target':0,'error':'parse'}}))
            with patch('learning.train_gat._load_or_build_graphs',return_value={'f':{}}):
                meta,graphs,receipts=load_cache_sources([str(path)])
            self.assertEqual((len(meta),len(graphs),receipts[0]['requested_rows']),(2,1,2))
            self.assertEqual(len(receipts[0]['metadata_sha256']),64)


if __name__=='__main__':unittest.main()
