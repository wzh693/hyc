import unittest

from graph.security_net import extract_security_signal, zero_token_verify


class SecurityNetTests(unittest.TestCase):
    def test_noncode_free_does_not_flip_a_negative(self):
        for code in ('/* free(p); */ return p[0];', 'puts("free(p)"); return p[0];',
                     '// free(p);\nreturn p[0];'):
            pred, record = zero_token_verify(0, code)
            self.assertEqual(pred, 0)
            self.assertEqual(record['signal']['score'], 0)

    def test_other_objects_release_does_not_hide_uaf(self):
        self.assertEqual(extract_security_signal('free(p); free(q); return p[0];').uaf_chains, 1)

    def test_free_then_deref_is_uaf(self):
        signal = extract_security_signal("free(p); return p->value;")
        self.assertEqual(signal.uaf_chains, 1)
        self.assertGreaterEqual(signal.score, 4)

    def test_reassignment_ends_old_lifetime(self):
        signal = extract_security_signal("free(p); p = alloc(); return p->value;")
        self.assertEqual(signal.uaf_chains, 0)

    def test_double_free_is_high_confidence(self):
        signal = extract_security_signal("free(p); cleanup(); free(p);")
        self.assertEqual(signal.double_free_chains, 1)
        self.assertGreaterEqual(signal.score, 5)

    def test_verifier_is_one_way(self):
        pred, record = zero_token_verify(0, "free(p); return p[0];", threshold=4)
        self.assertEqual(pred, 1)
        self.assertTrue(record["flipped"])
        pred, record = zero_token_verify(1, "return 0;", threshold=4)
        self.assertEqual(pred, 1)
        self.assertFalse(record["flipped"])


if __name__ == "__main__":
    unittest.main()
