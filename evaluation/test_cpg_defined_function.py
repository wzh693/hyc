import unittest
from graph.build_cpg import _has_defined_function


class DefinedFunctionTests(unittest.TestCase):
    def test_full_name_cannot_impersonate_name(self):
        self.assertFalse(_has_defined_function('"1" [label="METHOD" FULL_NAME="a.c:<global>" '
            'IS_EXTERNAL="false" CODE="<global>" NAME="<global>"];'))

    def test_external_function_is_not_a_body(self):
        self.assertFalse(_has_defined_function('"1" [label="METHOD" CODE="f() { }" '
            'IS_EXTERNAL="true" NAME="f"];'))

    def test_multiline_array_body_is_preserved(self):
        self.assertTrue(_has_defined_function('"1" [label="METHOD" CODE="int f() {\n return a[2];\n}" '
            'IS_EXTERNAL="false" NAME="f"];\n"2" [label="BLOCK" CODE="{ return a[2]; }"];\n'
            '"1" -> "2" [label="AST"];'))

    def test_long_signature_uses_ast_body_not_method_code(self):
        self.assertTrue(_has_defined_function('"1" [label="METHOD" CODE="int f(int a, ..." '
            'IS_EXTERNAL="false" NAME="f"];\n"2" [label="BLOCK" CODE="{ return 1; }"];\n'
            '"1" -> "2" [label="AST"];'))

    def test_macro_stub_empty_block_is_not_a_body(self):
        self.assertFalse(_has_defined_function('"1" [label="METHOD" CODE="int RENAME(f)" '
            'IS_EXTERNAL="false" NAME="RENAME"];\n"2" [label="BLOCK" CODE="<empty>"];\n'
            '"1" -> "2" [label="AST"];'))

    def test_code_cannot_spoof_attributes(self):
        self.assertFalse(_has_defined_function(r'"1" [label="METHOD" CODE="{ NAME=\"f\" IS_EXTERNAL=\"false\" }" NAME="<global>" IS_EXTERNAL="true"];'))

    def test_prototype_and_missing_external_marker_abstain(self):
        self.assertFalse(_has_defined_function('"1" [label="METHOD" CODE="int f();" NAME="f" IS_EXTERNAL="false"];'))
        self.assertFalse(_has_defined_function('"1" [label="METHOD" CODE="int f() {}" NAME="f"];'))


if __name__=='__main__':unittest.main()
