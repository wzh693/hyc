import unittest
from learning.calibrate_gat import validate_split,choose_threshold


class CalibrationTests(unittest.TestCase):
    def test_rejects_shared_group(self):
        with self.assertRaises(ValueError):
            validate_split({'train':['a'],'holdout':['b'],'calibration':['c'],
                            'group_membership':{'a':1,'b':2,'c':1}})

    def test_rejects_legacy_two_way_split(self):
        with self.assertRaises(ValueError):
            validate_split({'train':['a'],'holdout':['b']})

    def test_abstains_without_precision(self):
        chosen,_=choose_threshold([(.9,0,'a'),(.9,0,'b'),(.6,1,'c')])
        self.assertIsNone(chosen)

    def test_frozen_grid_chooses_widest_eligible(self):
        chosen,_=choose_threshold([(.8,1,'a'),(.7,1,'b'),(.6,0,'c'),(.3,0,'d')])
        self.assertEqual(chosen['threshold'],.5)


if __name__=='__main__':unittest.main()
