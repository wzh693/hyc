"""Durable local supervisor; fixed pipeline, no automatic failed-row/model reruns."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback

from evaluation.prepare_converged_expansion_20261010 import ROOT, read, sha

RUN = ROOT/'output/converged_expansion_cpg_20261010'
TRAIN = ROOT/'output/converged_expanded_gat_training_20261010'
CONTROL = ROOT/'output/converged_expansion_supervisor_20261010'


def phase_plan(preparation_complete, training_directory_exists, training_complete, model_audited):
    if training_directory_exists and not training_complete:
        raise ValueError('Partial training exists: refuse automatic restart or overwrite')
    if training_complete and not preparation_complete:
        raise ValueError('Training without completed preparation')
    if model_audited and not training_complete:
        raise ValueError('Model audit without completed training')
    stages = []
    if not preparation_complete:
        stages.append(('prepare', ['evaluation.prepare_converged_expansion_20261010',
            '--output', str(RUN), '--resume']))
    stages.append(('readiness_audit', ['evaluation.audit_converged_expansion_20261010']))
    if not training_complete:
        stages.append(('train_once', ['evaluation.train_converged_expanded_20261010',
            '--output', str(TRAIN)]))
    if not model_audited:
        stages.append(('prediction_replay_audit', ['evaluation.audit_converged_expanded_model_20261010']))
    return stages


def progress():
    receipt = RUN/'preparation.jsonl'
    rows = [json.loads(line) for line in receipt.read_text(encoding='utf8').splitlines() if line.strip()] if receipt.exists() else []
    return dict(total=2344, completed=len(rows), prepared=sum(r['status']=='prepared' for r in rows),
                failed=sum(r['status']=='failed' for r in rows))


def write_state(state):
    state['updated_utc'] = datetime.now(timezone.utc).isoformat()
    # A currently appended receipt is allowed to be incomplete; retain last good count.
    try:
        state['preparation'] = progress()
    except json.JSONDecodeError:
        pass
    temporary = CONTROL/'state.json.tmp'
    temporary.write_text(json.dumps(state, indent=2), encoding='utf8')
    os.replace(temporary, CONTROL/'state.json')


def main():
    CONTROL.mkdir(exist_ok=True)
    lock = CONTROL/'runner.lock'
    # An orphaned lock requires an explicit process check, never automatic deletion.
    with lock.open('x', encoding='utf8') as handle:
        handle.write(str(os.getpid()))
    state = dict(status='starting', supervisor_pid=os.getpid(), child_pid=None, phase=None,
        source_sha256=sha(Path(__file__)), started_utc=datetime.now(timezone.utc).isoformat(),
        phases=[], paid_api_calls=0, note='Local pipeline; no scheduled wake-up or automatic notification')
    child = None
    try:
        protocol = read(RUN/'protocol.json')
        for name, expected in protocol['source_hashes'].items():
            if sha(ROOT/name) != expected:
                raise ValueError('Frozen source drift: '+name)
        for name, expected in protocol['tool_hashes'].items():
            if sha(name) != expected:
                raise ValueError('Frozen launcher drift')
        state['protocol_sha256'] = sha(RUN/'protocol.json')
        stages = phase_plan((RUN/'report.json').exists(), TRAIN.exists(),
                            (TRAIN/'report.json').exists(), (TRAIN/'audit.json').exists())
        state['planned_phases'] = [name for name, _ in stages]
        for phase, args in stages:
            state.update(status='running', phase=phase, child_pid=None)
            write_state(state)
            command = [sys.executable, '-B', '-m', *args]
            started = datetime.now(timezone.utc).isoformat()
            with (CONTROL/(phase+'.log')).open('a', encoding='utf8') as log:
                log.write('\n'+json.dumps(dict(started_utc=started, command=command))+'\n')
                log.flush()
                child = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                    env=dict(os.environ, PYTHONUTF8='1'),
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
                state['child_pid'] = child.pid
                write_state(state)
                while child.poll() is None:
                    time.sleep(10)
                    write_state(state)
                code = child.returncode
            state['phases'].append(dict(phase=phase, exit_code=code, started_utc=started,
                ended_utc=datetime.now(timezone.utc).isoformat()))
            state['child_pid'] = None
            if code != 0:
                raise RuntimeError(f'{phase} exited {code}; stopped without retry')
            child = None
        audit = read(TRAIN/'audit.json')
        if not audit.get('pass_audit'):
            raise ValueError('Final replay audit not passed')
        report = read(TRAIN/'report.json')
        state.update(status='complete', phase='complete',
            model_diagnostic_gate=report['model_diagnostic_gate'],
            selection_auc=report['selection']['auc'], calibration_auc=report['calibration']['auc'],
            calibration_balanced_accuracy=report['calibration']['balanced_accuracy_fixed_05'])
        write_state(state)
    except BaseException as exc:
        state.update(status='failed', error=repr(exc))
        write_state(state)
        traceback.print_exc()
        raise
    finally:
        # Removing only this supervisor's ephemeral exact lock, not experiment data.
        if child is None or child.poll() is not None:
            lock.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
