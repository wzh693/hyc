import ast
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from evaluation.prepare_converged_expansion_20261010 import selected_objects

ROOT = Path(__file__).resolve().parents[1]


class ExpansionTests(unittest.TestCase):
    def test_only_selected_objects_are_decoded(self):
        rows = [dict(func='unselected'), dict(func='selected'), dict(func='unselected2')]
        original = json.loads
        with patch('evaluation.prepare_converged_expansion_20261010.json.loads', wraps=original) as decoder:
            result = list(selected_objects(json.dumps(rows).encode(), {1}))
        self.assertEqual(result, [(1, rows[1])])
        self.assertEqual(decoder.call_count, 1)

    def test_nested_strings_braces_escapes_and_unicode(self):
        rows = [dict(func='} [ " \\ 中文', nested=[{'x': [True, None]}]), dict(func='ok')]
        self.assertEqual(list(selected_objects(json.dumps(rows, ensure_ascii=False).encode(), {0, 1})), list(enumerate(rows)))

    def test_missing_requested_id_is_rejected(self):
        with self.assertRaises(ValueError):
            list(selected_objects(b'[{}]', {2}))

    def test_trailing_comma_is_rejected(self):
        with self.assertRaises(ValueError):
            list(selected_objects(b'[{},  ]', {0}))

    def test_unterminated_input_is_rejected(self):
        with self.assertRaises(ValueError):
            list(selected_objects(b'[{"func":"missing}', {0}))

    def test_trailing_input_is_rejected(self):
        with self.assertRaises(ValueError):
            list(selected_objects(b'[{}]{}', {0}))

    def test_training_epoch_loop_is_unchanged(self):
        loops = []
        for path in ('development/converged_graph_v2_candidate_20261010/train_minimal_gat.py',
                     'evaluation/train_converged_expanded_20261010.py'):
            tree = ast.parse((ROOT/path).read_text(encoding='utf8'))
            main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
            loop = next(n for n in main.body if isinstance(n, ast.For) and isinstance(n.target, ast.Name) and n.target.id == 'epoch')
            loops.append(ast.dump(loop))
        self.assertEqual(*loops)

    def test_optimizer_is_original_adam_without_decay(self):
        calls = []
        for path in ('development/converged_graph_v2_candidate_20261010/train_minimal_gat.py',
                     'evaluation/train_converged_expanded_20261010.py'):
            tree = ast.parse((ROOT/path).read_text(encoding='utf8'))
            calls.append(next(n for n in ast.walk(tree) if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute) and n.func.attr == 'Adam'))
        self.assertEqual(ast.dump(calls[0]), ast.dump(calls[1]))


if __name__ == '__main__':
    unittest.main()
