import unittest
from evaluation.build_development_graph_cache import select_unexposed


class DevelopmentCacheTests(unittest.TestCase):
    def test_excludes_whole_group_and_keeps_deterministic_sampling(self):
        rows=[{'idx':i,'group_id':str(i//2)} for i in range(80)]
        exclusions=[rows[0],rows[20]]
        selected=select_unexposed(rows,exclusions,30,20261006)
        self.assertEqual(selected,select_unexposed(list(reversed(rows)),exclusions,30,20261006))
        self.assertFalse({r['group_id'] for r in selected}&{'0','10'})
        self.assertEqual(len({r['group_id'] for r in selected}),30)

    def test_refuses_to_silently_shrink_batch(self):
        with self.assertRaises(ValueError):
            select_unexposed([{'idx':0,'group_id':'a'}],[],2,1)


if __name__=='__main__':unittest.main()
