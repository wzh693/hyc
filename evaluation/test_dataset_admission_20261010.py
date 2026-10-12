import ast
from pathlib import Path
import unittest
from evaluation.audit_dataset_admission_20261010 import sink_summary

ROOT = Path(__file__).resolve().parents[1]


class AdmissionTests(unittest.TestCase):
    def test_fixed_positive_is_reported_not_silently_relabelled(self):
        result = sink_summary([dict(patch_id='p', version='fixed', label=1, sink_reason='cwe_api:free')], set())
        self.assertEqual(result['versions']['fixed']['loader_derived_positive'], 1)

    def test_missing_sink_is_not_dropped(self):
        result = sink_summary([], {('p', 'vulnerable')})
        self.assertEqual(result['metadata_keys_without_sink'], 1)
        self.assertEqual(result['versions']['vulnerable']['loader_derived_negative'], 1)

    def test_invalid_label_is_rejected(self):
        with self.assertRaises(ValueError):
            sink_summary([dict(patch_id='p', version='fixed', label=2)], set())

    def test_training_epoch_loop_is_unchanged(self):
        paths = ('development/converged_graph_v2_candidate_20261010/train_minimal_gat.py',
                 'evaluation/train_converged_gat_wd_20261010.py')
        loops = []
        for path in paths:
            tree = ast.parse((ROOT/path).read_text(encoding='utf8'))
            main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
            loop = next(n for n in main.body if isinstance(n, ast.For) and isinstance(n.target, ast.Name) and n.target.id == 'epoch')
            loops.append(ast.dump(loop))
        self.assertEqual(*loops)

    def test_optimizer_only_adds_weight_decay(self):
        paths = ('development/converged_graph_v2_candidate_20261010/train_minimal_gat.py',
                 'evaluation/train_converged_gat_wd_20261010.py')
        calls = []
        for path in paths:
            tree = ast.parse((ROOT/path).read_text(encoding='utf8'))
            calls.append(next(n for n in ast.walk(tree) if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute) and n.func.attr == 'Adam'))
        weight_decay = next(k for k in calls[1].keywords if k.arg == 'weight_decay')
        self.assertEqual(ast.literal_eval(weight_decay.value), .001)
        calls[1].keywords.remove(weight_decay)
        self.assertEqual(ast.dump(calls[0]), ast.dump(calls[1]))


if __name__ == '__main__':
    unittest.main()
