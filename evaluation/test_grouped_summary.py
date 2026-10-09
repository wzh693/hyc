import json
from pathlib import Path
import tempfile
import unittest
from evaluation.summarize_wiring_quality import analyze
from evaluation.evaluate_wiring_quality import score


class GroupedSummaryTests(unittest.TestCase):
    def test_grouped_repeats_and_failed_rows_remain_in_denominator(self):
        samples=[{'sample_id':'good','target':1},{'sample_id':'failed','target':0}]
        profiles={'control':[0,0,0],'slice_only':[1,0,0],'grouped_slice':[1,0,0]}
        rows=[]
        calls=[]
        metrics={}
        accounting={}
        for repeat in (1,2):
            for profile in profiles:
                group={'admitted':True,'control_node_ids':['g'],'exit_node_ids':['e']}
                row=dict(samples[0],profile=profile,repeat=repeat,
                         prediction=0 if repeat==2 else 1,
                         arbitrate={'main_pred':0 if repeat==2 else 1,
                            'reasoning_trace':[{'step':1}],
                            'module_audit':{'backward_slice':{'atomic_groups':{
                                'enabled':profile=='grouped_slice','groups':[group]}}}})
                failed=dict(samples[1],profile=profile,repeat=repeat,prediction=None,error='prep')
                rows.extend([row,failed])
                calls.append(dict(sample_id='good',profile=profile,repeat=repeat,
                    request={'messages':[{'role':'user','content':'same'}]},
                    answer=str(repeat),prompt_tokens=100))
                name=f'{profile}/r{repeat}'
                metrics[name]=score([row,failed])
                accounting[name]={'total_tokens':110,'truncated_calls':0,'invocations':1}
        manifest={'samples':samples,'profiles':profiles,'repeat_profiles':list(profiles)}
        report={'metrics':metrics,'api_accounting':accounting,'paired_group_intervals':{},
                'repeat_sensitivity':{},'limitations':[]}
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for name,obj in (('manifest',manifest),('report',report)):
                (root/f'{name}.json').write_text(json.dumps(obj),encoding='utf-8')
            for name,obj in (('results',rows),('api_receipts',calls)):
                (root/f'{name}.jsonl').write_text('\n'.join(map(json.dumps,obj)),encoding='utf-8')
            result=analyze(root)
        self.assertEqual(result['configurations'][0]['n'],2)
        self.assertEqual(result['configurations'][0]['mean_actual_tokens'],55)
        self.assertEqual(result['grouped_mechanism']['grouped_slice/r1']['admitted_with_control_and_exit'],1)
        diag=result['paired_prompt_diagnostics']['grouped_slice-r2-vs-r1']
        self.assertEqual(diag['evaluable_first_request_pairs'],1)
        self.assertEqual(diag['identical_first_messages'],1)
        self.assertEqual(diag['identical_messages_prediction_disagreements_both_single_step'],1)
        self.assertEqual(result['first_prompt_integrity']['available_first_requests']['grouped_slice/r2'],1)
        self.assertIsNone(result['first_prompt_integrity']['contract_vs_control_first_user_prompt_changes'])
        self.assertFalse(result['auto_promoted'])


if __name__=='__main__':unittest.main()
