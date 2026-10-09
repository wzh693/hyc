"""Characterize legacy routing bottlenecks; no proposed policy activated."""
import unittest
import importlib
from unittest.mock import patch
import networkx as nx
import config
loop=importlib.import_module('reasoning.reasoning_loop')


class SvenRoutingDiagnosisTests(unittest.TestCase):
    def characterize_stop(self,hypothesis):
        graph=nx.MultiDiGraph();graph.add_node('n',code='int i;',label='LOCAL')
        answer=(f'HYPOTHESIS: {hypothesis}\nREASONING: missing loop bound for i\n'
                'ACTION: {"action":"ExpandDFG","reason":"need loop bound"}')
        with patch.multiple(config,EVIDENCE_EXPANSION=False,USE_BACKWARD_SLICE=False,
                            BOUNDED_OUTPUT_CONTRACT=False,BUDGETED_EVIDENCE_GROUPS=False,
                            STEP1_CONFIRM_STOP=True,SELECTIVE_SECOND_PASS=True,
                            F1_EVIDENCE_ROUTING=False,USE_ZERO_TOKEN_SECURITY_NET=True,
                            RECORD_REASONING_TRACE=True), \
                patch.object(loop,'query_llm_with_retry',return_value=(answer,0)) as query, \
                patch.object(loop,'_execute_action',return_value=[]) as execute:
            result=loop.reasoning_loop(graph,[['n']],'int f() { return 0; }','',{},
                                       max_steps=2,use_expansion=None)
            self.assertEqual(query.call_count,1)
            execute.assert_not_called()
        return result

    def test_complete_benign_gap_request_still_suppressed(self):
        result=self.characterize_stop('no vulnerability detected')
        self.assertEqual(result['module_audit']['stop_reason'],'no_requested_gap')

    def test_typed_hypothesis_suppresses_complete_gap_request(self):
        result=self.characterize_stop('out-of-bounds read')
        self.assertEqual(result['module_audit']['stop_reason'],'confirmed_first_step')

    def test_action_anchor_is_path_endpoint_not_requested_variable(self):
        graph=nx.MultiDiGraph();graph.add_nodes_from(['loop_bound_i','other_sink'])
        class Engine:
            def __init__(self):self.nodes=[]
            def expand_dataflow(self,node,**kwargs):self.nodes.append(node);return []
        engine=Engine()
        loop._execute_action(engine,'ExpandDFG',[['loop_bound_i','other_sink']],graph)
        self.assertEqual(engine.nodes,['other_sink'])


if __name__=='__main__':unittest.main()
