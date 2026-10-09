import random
import hashlib
import json
import unittest
from evaluation.quarantine_near_clones import canonical_tokens, similar90, clone_pairs, quarantine
from evaluation.build_clean_protocol import Groups
from evaluation.verify_clean_protocol import validate_dataset


class CloneTests(unittest.TestCase):
    def test_consistent_renaming(self):
        self.assertEqual(canonical_tokens('int f(int x){return x+1;}'),
                         canonical_tokens('int g(int z){return z+1;}'))
        self.assertNotEqual(canonical_tokens('return x+x;'),canonical_tokens('return x+y;'))

    def test_literal_and_keyword_preserved(self):
        self.assertNotEqual(canonical_tokens('puts("a b");'),canonical_tokens('puts("ab");'))
        self.assertNotEqual(canonical_tokens('if(x) return x;'),canonical_tokens('while(x) return x;'))

    def test_prefix_join_matches_exhaustive(self):
        rng=random.Random(42)
        sets={i:sorted(rng.sample(range(30),rng.randint(10,25))) for i in range(80)}
        sets[80]=list(sets[0]); sets[81]=sorted(set(sets[0])|{31})
        expected={tuple(sorted((i,j))) for i,a in sets.items() for j,b in sets.items()
                  if i<j and similar90(a,b)}
        actual={tuple(sorted(pair)) for pair in clone_pairs(sets)}
        self.assertEqual(expected,actual)

    def test_history_propagates_and_cross_split_quarantines(self):
        g=Groups(5);g.join(0,1);g.join(2,3)
        kept,reasons=quarantine(g,{'dev':[{'idx':1},{'idx':2},{'idx':4}], 'test':[{'idx':3}]},5)
        self.assertEqual(kept,{'dev':[4],'test':[]})
        self.assertEqual(reasons,{'touches_prior_excluded_group':1,'cross_partition_clone':2})

    def test_dataset_version_mismatch_rejected(self):
        blob=json.dumps([{'func':'int f(){}'}]).encode()
        with self.assertRaises(ValueError): validate_dataset({},blob,'wrong')
        validate_dataset({},blob,hashlib.sha256(blob).hexdigest())


if __name__ == '__main__': unittest.main()
