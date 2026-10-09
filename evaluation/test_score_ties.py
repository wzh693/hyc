import unittest
import numpy as np
from learning.scorer import _percentile_penalties


class TieTests(unittest.TestCase):
    def test_equal_attention_does_not_invent_order(self):
        np.testing.assert_allclose(_percentile_penalties([0,0,1]),[-.75,-.75,0])

    def test_permutation_equivariance(self):
        values=np.array([0,0,.1,.1,.8]);order=np.array([4,2,0,3,1])
        np.testing.assert_allclose(_percentile_penalties(values)[order],_percentile_penalties(values[order]))

    def test_no_information_is_neutral(self):
        np.testing.assert_array_equal(_percentile_penalties([.5]*4),np.zeros(4))
        np.testing.assert_array_equal(_percentile_penalties([1]),[0])

    def test_invalid_output_rejected(self):
        with self.assertRaises(ValueError):_percentile_penalties([0,float('nan')])


if __name__=='__main__':unittest.main()
