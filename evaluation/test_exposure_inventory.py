import json
from pathlib import Path
import tempfile
import unittest
from evaluation.build_clean_protocol import inventory_exposure,code_hash


class ExposureInventoryTests(unittest.TestCase):
    def test_interrupted_manifest_and_new_meta_are_not_missed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);cache=root/'output/devign_new';cache.mkdir(parents=True)
            (cache/'manifest.json').write_text(json.dumps([{'idx':4},{'idx':5}]))
            (cache/'meta.json').write_text(json.dumps({'a':{'idx':4,'error':'parse'}}))
            source=cache/'sample_000005';source.mkdir();(source/'source.c').write_text('int f() { return 1; }')
            exposed,hashes,artifacts=inventory_exposure(root,10)
            self.assertEqual(exposed,{4,5})
            self.assertIn(code_hash('int f() { return 1; }'),hashes)
            self.assertEqual(len(artifacts),2)

    def test_preserves_legacy_training_and_bounds_indices(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);cache=root/'output/train_cpg';cache.mkdir(parents=True)
            (cache/'meta.json').write_text(json.dumps({'a':{'idx':2},'b':{'idx':-1},'c':{'idx':100}}))
            self.assertEqual(inventory_exposure(root,10)[0],{2})


if __name__=='__main__':unittest.main()
