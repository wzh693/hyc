import unittest
from evaluation.diagnose_converged_gat_20261010 import metrics


class DiagnosticMetricTests(unittest.TestCase):
    def test_fixed_threshold_and_perfect_auc(self):
        result = metrics([dict(target=0, probability=.1), dict(target=1, probability=.5)])
        self.assertEqual(result['n'], 2)
        self.assertEqual(result['auc'], 1.)
        self.assertEqual(result['balanced_accuracy'], 1.)
        self.assertEqual(result['predicted_positive'], 1)

    def test_ties_and_inverted_ranking_are_not_repaired(self):
        self.assertEqual(metrics([dict(target=0, probability=.5),
                                  dict(target=1, probability=.5)])['auc'], .5)
        self.assertEqual(metrics([dict(target=0, probability=.9),
                                  dict(target=1, probability=.1)])['auc'], 0.)

    def test_single_class_auc_is_undefined(self):
        result = metrics([dict(target=1, probability=.4)])
        self.assertIsNone(result['auc'])
        self.assertIsNone(result['balanced_accuracy'])
        self.assertEqual(result['positive'], 1)


if __name__ == '__main__':
    unittest.main()
