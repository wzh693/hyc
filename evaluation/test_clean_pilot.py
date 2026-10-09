import unittest
from evaluation.build_clean_development_pilot import select_rows


class PilotTests(unittest.TestCase):
    def test_deterministic_group_sampling_without_labels(self):
        rows=[{'idx':i,'group_id':str(i//2)} for i in range(40)]
        selected=select_rows(rows,10,20261005)
        self.assertEqual(selected,select_rows(list(reversed(rows)),10,20261005))
        self.assertEqual(len({r['group_id'] for r in selected}),10)
        self.assertTrue(all(r['idx']%2==0 for r in selected))


if __name__ == '__main__': unittest.main()
