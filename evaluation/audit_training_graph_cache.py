"""Audit actual function bodies in a cache without labels guiding filtering."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from graph.build_cpg import _dot_has_func_method


def audit(directory):
    meta_bytes=(directory/'meta.json').read_bytes()
    meta=json.loads(meta_bytes)
    invalid=[]; valid=[]
    for fid,row in sorted(meta.items()):
        record={'sample_id':fid,'idx':row['idx'],'target':row['target']}
        dot=directory/fid/'export/export.dot'
        if row.get('error') or not _dot_has_func_method(str(dot)):
            record['reason']=row.get('error') or 'No internal METHOD with a direct nonempty AST BLOCK body'
            invalid.append(record)
        else:valid.append(record)
    return {'cache_directory':str(directory.resolve()),'metadata_sha256':hashlib.sha256(meta_bytes).hexdigest(),
        'requested':len(meta),'defined_function_graphs':len(valid),'invalid_graphs':len(invalid),
        'valid_labels':dict(Counter(str(r['target']) for r in valid)),
        'invalid_labels':dict(Counter(str(r['target']) for r in invalid)),
        'invalid_rows':invalid,'api_calls':0,
        'policy':'Filter on graph construction validity only, never on prediction/label; report denominator loss',
        'limitations':'A body BLOCK proves parser produced a function body, not complete or correct semantics'}


def main():
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();report=audit(a.directory)
    with a.output.open('x',encoding='utf8') as handle:json.dump(report,handle,indent=2)
    print(json.dumps({k:v for k,v in report.items() if k!='invalid_rows'},indent=2))


if __name__=='__main__':main()
