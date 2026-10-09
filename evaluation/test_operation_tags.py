import unittest
from unittest.mock import patch
from linearization.typed_paths import _node_security_hit


class OperationTagTests(unittest.TestCase):
    def hit(self, **node):
        with patch('config.STRICT_OPERATION_TAGS', True):
            return _node_security_hit(node)

    def test_container_body_is_not_a_release(self):
        for kind in ('BLOCK','CONTROL_STRUCTURE','METHOD'):
            self.assertEqual(self.hit(node_type=kind,code='if(x) { free(p); }'), ('',''))

    def test_actual_release(self):
        self.assertEqual(self.hit(node_type='CALL',code='free(p)',name='free'), ('FREE','free'))

    def test_method_name_does_not_pollute_call(self):
        self.assertEqual(self.hit(node_type='CALL',code='cleanup(p)',method='free'), ('',''))

    def test_nested_api_is_not_outer_operation(self):
        self.assertEqual(self.hit(node_type='CALL',code='log("free(p)")'), ('',''))
        self.assertEqual(self.hit(node_type='CALL',code='x = malloc(4)'), ('',''))

    def test_identifier_is_not_call(self):
        self.assertEqual(self.hit(node_type='IDENTIFIER',code='free'), ('',''))


if __name__ == '__main__': unittest.main()
