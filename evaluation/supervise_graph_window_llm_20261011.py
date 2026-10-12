"""Durable single-batch launcher: paid run once, offline audit once, no restart."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SUP = ROOT/'output/graph_window_llm_supervisor_20261011'
RUN = ROOT/'output/graph_window_llm1016_20261011'
PREFLIGHT = ROOT/'output/graph_window_runtime_preflight_v2_20261011'


def now():
    return datetime.now(timezone.utc).isoformat()


def main():
    if os.environ.get('PYTHONHASHSEED') != '0':
        raise ValueError('PYTHONHASHSEED=0 must be set before process launch')
    if SUP.exists() or RUN.exists():
        raise ValueError('No duplicate launch, resume, or rerun permitted')
    verification = json.loads((PREFLIGHT/'runtime_verification.json').read_text(encoding='utf8'))
    if not verification['passed'] or verification['rows'] != 1016:
        raise ValueError('Full runtime preflight required')
    SUP.mkdir()
    state = dict(status='running', phase='launch', pid=os.getpid(), started_utc=now(),
                 planned_results=1016, completed_results=0, child_pid=None, phases=[])
    def save():
        state['updated_utc'] = now()
        state['completed_results'] = sum(sum(1 for line in path.open(encoding='utf8') if line.strip())
            for path in (RUN/'control/results.jsonl',RUN/'display/results.jsonl') if path.exists())
        temp = SUP/'state.tmp'
        temp.write_text(json.dumps(state, indent=2), encoding='utf8')
        os.replace(temp, SUP/'state.json')
    save()
    stages = [
        ('llm_once', ['evaluation.run_graph_window_llm_20261011', '--output', str(RUN),
            '--preflight', str(PREFLIGHT), '--authorized-real-1016']),
        ('offline_replay_audit', ['evaluation.audit_graph_window_llm_20261011', '--run', str(RUN)])]
    try:
        for phase, args in stages:
            state['phase'] = phase
            with (SUP/(phase+'.log')).open('x', encoding='utf8') as log:
                process = subprocess.Popen([sys.executable, '-B', '-m', *args], cwd=ROOT,
                    stdout=log, stderr=subprocess.STDOUT,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
                state['child_pid'] = process.pid
                save()
                while process.poll() is None:
                    time.sleep(10)
                    save()
                state['phases'].append(dict(phase=phase, exit_code=process.returncode, ended_utc=now()))
                state['child_pid'] = None
                if process.returncode:
                    state['status'] = 'failed'
                    save()
                    return
        state.update(status='complete', phase='complete')
    except Exception as exc:
        state.update(status='failed', error=repr(exc))
    save()


if __name__ == '__main__':
    main()
