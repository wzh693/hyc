import unittest
import hashlib
import json
from pathlib import Path
import tempfile
from learning.grouped_split import partition_groups, split_holdout,grouped_split


class GroupedTrainingTests(unittest.TestCase):
    def test_group_never_crosses_holdout(self):
        membership={f'f{i}':i//3 for i in range(300)}
        train,hold=partition_groups(membership,42)
        self.assertTrue(train and hold)
        self.assertFalse({membership[f] for f in train}&{membership[f] for f in hold})
        self.assertEqual((train,hold),partition_groups(dict(reversed(list(membership.items()))),42))

    def test_calibration_not_used_for_epoch_selection(self):
        membership={f'f{i}':i//3 for i in range(300)}
        train,hold=partition_groups(membership,42)
        selection,calibration=split_holdout(membership,hold,42)
        self.assertTrue(selection and calibration)
        self.assertEqual(set(selection)|set(calibration),set(hold))
        self.assertFalse({membership[f] for f in selection}&{membership[f] for f in calibration})

    def test_new_cache_source_identity_is_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)
            blob=json.dumps([{'func':'int f() { return 1; }','target':1,'project':'qemu'}]).encode()
            (path/'data.json').write_bytes(blob)
            (path/'audit.json').write_text(json.dumps({'dataset_sha256':hashlib.sha256(blob).hexdigest()}))
            (path/'clone_pairs.json').write_text(json.dumps({'exact':[],'near':[]}))
            for extra in ({'source_raw_sha256':'wrong'},{'source_sha256':'wrong'},{'project':'other'}):
                with self.assertRaises(ValueError):
                    grouped_split({'f':{'idx':0,'target':1,**extra}},['f'],path/'data.json',path,42)


if __name__=='__main__':unittest.main()
