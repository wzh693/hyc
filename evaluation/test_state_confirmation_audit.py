import unittest
from evaluation.audit_state_confirmation import verify_requests
from evaluation import test_state_confirmation as fixture


class StateReceiptTests(unittest.TestCase):
    def requests(self):
        return [{'model':'same','max_tokens':150,'temperature':0,
                 'messages':[{'role':'system','content':'same'}, {'role':'user','content':prompt}]}
                for prompt in fixture.StateConfirmationTests().prompts()]

    def test_receipts_only_state(self):
        self.assertIn('candidate_state',verify_requests(*self.requests()))

    def test_parameter_change_rejected(self):
        requests=self.requests()
        requests[2]['max_tokens']=200
        with self.assertRaises(ValueError):verify_requests(*requests)

    def test_system_policy_change_rejected(self):
        requests=self.requests()
        requests[2]['messages'][0]['content']='changed'
        with self.assertRaises(ValueError):verify_requests(*requests)


if __name__=='__main__':unittest.main()
