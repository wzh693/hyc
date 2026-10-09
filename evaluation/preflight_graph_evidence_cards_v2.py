"""Fresh complete offline run for v2; all prior artifacts remain immutable."""
from evaluation import preflight_graph_evidence_cards as runner
from pathlib import Path

ROOT=runner.ROOT
runner.SOURCES=dict(runner.SOURCES,display=ROOT/'development/graph_evidence_cards_v2_candidate_20261009/src')
runner.TOOLS=runner.TOOLS+['evaluation/preflight_graph_evidence_cards_v2.py',
    'evaluation/verify_graph_evidence_cards_v2.py','evaluation/test_graph_evidence_cards_v2.py',
    'evaluation/GRAPH_EVIDENCE_CARDS_V2_PROTOCOL_20261009.md']
original_prepare=runner.prepare


def prepare():
    manifest,data=original_prepare(); manifest['policy']='whole_graph_evidence_v2'
    return manifest,data


if __name__=='__main__':
    # Child processes must use this launcher too; replace only module command
    # during dispatch, not any prediction operation or prior file.
    original_run=runner.subprocess.run
    def launch(command,**kwargs):
        command=list(command)
        if 'evaluation.preflight_graph_evidence_cards' in command:
            command[command.index('evaluation.preflight_graph_evidence_cards')]='evaluation.preflight_graph_evidence_cards_v2'
        return original_run(command,**kwargs)
    runner.subprocess.run=launch
    runner.prepare=prepare
    runner.main()
