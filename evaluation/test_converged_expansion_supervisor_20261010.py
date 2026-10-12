import unittest
from evaluation.run_converged_expansion_background_20261010 import phase_plan


class SupervisorTests(unittest.TestCase):
    def test_incomplete_preparation_resumes_then_audits(self):
        self.assertEqual([name for name, _ in phase_plan(False, False, False, False)],
            ['prepare', 'readiness_audit', 'train_once', 'prediction_replay_audit'])

    def test_completed_preparation_is_not_rebuilt(self):
        self.assertEqual([name for name, _ in phase_plan(True, False, False, False)],
            ['readiness_audit', 'train_once', 'prediction_replay_audit'])

    def test_completed_training_is_not_retrained(self):
        self.assertEqual([name for name, _ in phase_plan(True, True, True, False)],
            ['readiness_audit', 'prediction_replay_audit'])

    def test_partial_training_is_not_overwritten(self):
        with self.assertRaises(ValueError):
            phase_plan(True, True, False, False)

    def test_inconsistent_completion_is_rejected(self):
        with self.assertRaises(ValueError):
            phase_plan(False, True, True, False)
        with self.assertRaises(ValueError):
            phase_plan(False, False, False, True)


if __name__ == '__main__':
    unittest.main()
