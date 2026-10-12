"""Isolated prompt-contract-only candidate on frozen display-first evidence."""
from types import FunctionType
from development.converged_graph_v2_candidate_20261010 import architecture as base
from development.converged_display_first_candidate_20261011 import architecture as evidence


_OLD_CONTRACT = '''Return one JSON object with verdict (Vulnerable, Benign,
Uncertain), hypothesis, reason, action (Stop or Query), and optionally target (exact
graph node id) and edge_types (DFG, REACHING_DEF, CDG, CONTROL_DEPENDENCE).'''
_NEW_CONTRACT = '''Return ONLY one compact JSON object, no markdown or surrounding prose.
Put verdict first (Vulnerable, Benign, Uncertain), then action (Stop or Query),
then reason: a brief English phrase of at most 32 ASCII characters.
For Stop, use ONLY verdict, action, reason; do not add a hypothesis narrative.
For Query, also include target (an exact visible graph node id) and edge_types
(a nonempty list from DFG, REACHING_DEF, CDG, CONTROL_DEPENDENCE).
Only for a Vulnerable Query, add hypothesis: a stable issue key of at most
8 ASCII characters, reused if the same issue persists (not an explanation).
Do not add any other fields. Keep the entire JSON within the 150-token output cap.
Do not convert missing evidence to Benign merely to shorten the answer.'''
if base.SYSTEM.count(_OLD_CONTRACT) != 1:
    raise ValueError('Frozen output contract drift')
SYSTEM = base.SYSTEM.replace(_OLD_CONTRACT, _NEW_CONTRACT)

# Only the system output contract differs. Frozen decoder, graph queries and
# evidence context are retained in a private environment, not patched globally.
_environment = dict(evidence._run.__globals__, SYSTEM=SYSTEM)
_run = FunctionType(base.run.__code__, _environment, base.run.__name__, base.run.__defaults__)


def run(graph, source, offset, scorer, invoke, cfg=base.Settings(), calibration=None):
    if calibration is not None:
        raise ValueError('Compact-output experiment permits shadow net only')
    return _run(graph, source, offset, scorer, invoke, cfg, None)
