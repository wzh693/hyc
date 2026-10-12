"""Conservatively register every newly materialized source in the legacy exposure inventory."""
import json
from evaluation.prepare_converged_expansion_20261010 import ROOT, read, sha


def main():
    source = ROOT/'output/converged_expansion_cpg_20261010/frozen_metadata.json'
    metadata = read(source)
    if len(metadata) != 2344:
        raise ValueError('Wrong exposure scope')
    output = ROOT/'output/devign_converged_expansion_exposure_20261010'
    output.mkdir(exist_ok=False)
    (output/'meta.json').write_text(json.dumps(metadata, indent=2), encoding='utf8')
    (output/'receipt.json').write_text(json.dumps(dict(source=str(source.relative_to(ROOT)),
        source_sha256=sha(source), registered=2344,
        reason='All admitted source objects materialized; conservative exposure, NOT completed training',
        paid_api_calls=0), indent=2), encoding='utf8')
    print(json.dumps(dict(registered=2344, role='source-prepared exposure, not model quality')))


if __name__ == '__main__':
    main()
