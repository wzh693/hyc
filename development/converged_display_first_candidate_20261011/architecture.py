"""Isolated SRC-only display-first dependency slicing; frozen v2 is untouched."""
from types import FunctionType
from development.converged_graph_v2_candidate_20261010 import architecture as base


def context(graph, paths, source, offset, cfg, state, step, previous=None,
            *, slice_graph=None, scores=None):
    if previous is None:
        _, displayed = base.serialize_paths(graph, paths, cfg.path_chars)
        paths = displayed
    return base.context(graph, paths, source, offset, cfg, state, step, previous,
                        slice_graph=slice_graph, scores=scores)


# A private function environment substitutes only context. Never monkey-patch the
# imported frozen module, which is also the paired control in the same process.
_environment = dict(base.run.__globals__, context=context)
_run = FunctionType(base.run.__code__, _environment, base.run.__name__, base.run.__defaults__)


def run(graph, source, offset, scorer, invoke, cfg=base.Settings(), calibration=None):
    if calibration is not None:
        raise ValueError('Display-first experiment permits shadow security net only')
    return _run(graph, source, offset, scorer, invoke, cfg, None)
