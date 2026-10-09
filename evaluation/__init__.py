from evaluation.metrics import (
    compute_metrics, compute_long_range_metrics,
    compute_token_efficiency, compute_stability_metrics,
    compute_detailed_report, compute_code_reduction_metrics,
)
# Importing the package (including python -m evaluation...) must not preload
# config/reasoning before an experiment has installed its frozen environment.
from importlib import import_module as _import_module

_LAZY_EXPORTS = {
    'run_ablation_study': 'evaluation.ablation',
    'generate_ablation_report': 'evaluation.ablation',
    'ABLATION_CONFIGS': 'evaluation.ablation',
    'evaluate_robustness': 'evaluation.robustness',
    'generate_robustness_report': 'evaluation.robustness',
    'apply_transformations': 'evaluation.robustness',
    'TRANSFORMATIONS': 'evaluation.robustness',
}
__all__ = ['compute_metrics','compute_long_range_metrics','compute_token_efficiency',
           'compute_stability_metrics','compute_detailed_report','compute_code_reduction_metrics',
           *_LAZY_EXPORTS]


def __getattr__(name):
    if name not in _LAZY_EXPORTS:
        raise AttributeError(name)
    value = getattr(_import_module(_LAZY_EXPORTS[name]),name)
    globals()[name] = value
    return value
