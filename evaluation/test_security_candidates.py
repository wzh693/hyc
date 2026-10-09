import unittest
from evaluation.audit_security_signal_candidates import candidate_signal


class CandidateTests(unittest.TestCase):
    def test_comments_and_literals_do_not_create_frees(self):
        for source in ('/* free(p); */ return p[0];', 'puts("free(p)"); return p[0];',
                       '// free(p);\nreturn p[0];', "char c = '\\''; /* free(p); */ p[0];"):
            self.assertEqual(candidate_signal(source).score, 0)

    def test_real_call_with_literal_is_not_removed(self):
        self.assertEqual(candidate_signal('sprintf(dst, "%s", src);').unbounded_calls, 1)

    def test_unrelated_free_does_not_end_the_first_lifetime(self):
        self.assertEqual(candidate_signal('free(p); free(q); return p[0];').uaf_chains, 1)

    def test_reassignment_still_ends_the_first_lifetime(self):
        self.assertEqual(candidate_signal('free(p); p = alloc(); free(q); return p[0];').uaf_chains, 0)


if __name__ == '__main__':
    unittest.main()
