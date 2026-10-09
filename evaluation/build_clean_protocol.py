"""Conservative local exposure audit and commit/code-disjoint manifests. No API calls."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/|[A-Za-z_]\w*|\d+(?:\.\d+)?|[^\s]', re.S)


def code_hash(code):
    tokens = [m.group() for m in TOKEN.finditer(code)
              if not m.group().startswith(('//', '/*'))]
    return hashlib.sha256(json.dumps(tokens, ensure_ascii=False).encode('utf8')).hexdigest()


class Groups:
    def __init__(self, n): self.parent = list(range(n))
    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x
    def join(self, a, b): self.parent[self.find(b)] = self.find(a)


def inventory_exposure(root, n_raw, *, read_sources=True):
    """Include new cache manifests, even when preparation was interrupted."""
    exposed, historical_hashes, artifacts = set(), set(), []
    paths=set()
    if shutil.which('rg'):
        result=subprocess.run(['rg','--files','--hidden','--no-ignore',str(root/'output'),
            '-g','metadata.json','-g','meta.json','-g','manifest.json'],
            capture_output=True,text=True,encoding='utf-8',check=False)
        if result.returncode not in (0,1):
            raise RuntimeError('Exposure file inventory failed: '+result.stderr[:200])
        paths.update(Path(line) for line in result.stdout.splitlines() if line)
    else:
        for filename in ('metadata.json','meta.json','manifest.json'):
            paths.update((root/'output').rglob(filename))
    for path in sorted(paths):
        relative=str(path.relative_to(root))
        if 'devign' not in relative.lower() and path.parent.name!='train_cpg':continue
        payload=json.loads(path.read_text(encoding='utf8'))
        samples=payload.get('samples',list(payload.values())) if isinstance(payload,dict) else payload
        if not isinstance(samples,list):continue
        count=0
        for sample in samples:
            if not isinstance(sample,dict):continue
            idx=sample.get('idx')
            if not isinstance(idx,int) or not 0<=idx<n_raw:continue
            exposed.add(idx);count+=1
            if not read_sources:
                # Frozen protocol already excludes historical source/clone
                # groups. New-batch callers conservatively block each recorded
                # index's entire frozen group without rereading old code.
                if isinstance(sample.get('source_sha256'),str):
                    historical_hashes.add(sample['source_sha256'])
                continue
            candidates=[path.parent/'samples'/f'sample_{idx:06d}.c',
                        path.parent/f'sample_{idx:06d}'/'source.c']
            for source in candidates:
                if source.exists():
                    historical_hashes.add(code_hash(source.read_text(encoding='utf8',errors='replace')))
        if count:artifacts.append({'path':relative,'prepared_rows':count,'role':'conservative recorded exposure'})
    return exposed,historical_hashes,artifacts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dataset', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--seed', type=int, default=20261005)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.dataset is None:
        from config import DEVIGN_JSON_PATH
        args.dataset = Path(DEVIGN_JSON_PATH)
    raw_bytes = args.dataset.read_bytes()
    raw = json.loads(raw_bytes)
    hashes = [code_hash(r['func']) for r in raw]
    groups = Groups(len(raw))
    first_code, first_commit = {}, {}
    for idx, row in enumerate(raw):
        digest = hashes[idx]
        if digest in first_code: groups.join(idx, first_code[digest])
        else: first_code[digest] = idx
        if row.get('commit_id'):
            key = (row.get('project', ''), row['commit_id'])
            if key in first_commit: groups.join(idx, first_commit[key])
            else: first_commit[key] = idx
    exposed,historical_hashes,artifacts=inventory_exposure(root,len(raw))
    for idx, digest in enumerate(hashes):
        if digest in historical_hashes: exposed.add(idx)
    # Exclude conflicting labels across normalized identical source, not just rows.
    labels = defaultdict(set)
    for idx, row in enumerate(raw): labels[hashes[idx]].add(row['target'])
    conflicting = {h for h, targets in labels.items() if len(targets)>1}
    blocked = {groups.find(idx) for idx in exposed}
    blocked.update(groups.find(idx) for idx, h in enumerate(hashes) if h in conflicting)
    components = defaultdict(list)
    for idx in range(len(raw)): components[groups.find(idx)].append(idx)
    splits = {'development':[], 'validation':[], 'locked_test':[]}
    split_groups = Counter()
    for component, indices in sorted(components.items()):
        if component in blocked: continue
        identity = '\n'.join(sorted({hashes[i] for i in indices}))
        value = int(hashlib.sha256(f'{args.seed}:{identity}'.encode()).hexdigest()[:16],16)/2**64
        split = 'development' if value < .6 else 'validation' if value < .8 else 'locked_test'
        split_groups[split] += 1
        for idx in indices:
            row = raw[idx]
            # No source or labels in manifests; these are index manifests, not results.
            splits[split].append({'idx':idx, 'project':row.get('project',''),
                'commit_id':row.get('commit_id',''), 'source_sha256':hashes[idx],
                'group_id':hashlib.sha256(identity.encode()).hexdigest()})
    args.output.mkdir(parents=True, exist_ok=False)
    for name, rows in splits.items():
        (args.output/f'{name}.json').write_text(json.dumps(rows,indent=2),encoding='utf8')
    report = {'dataset_sha256':hashlib.sha256(raw_bytes).hexdigest(), 'seed':args.seed,
        'n_raw':len(raw), 'normalized_unique_source':len(first_code),
        'conflicting_source_groups':len(conflicting), 'historically_prepared_or_trained_rows':len(exposed),
        'excluded_rows_by_connected_group':sum(len(v) for k,v in components.items() if k in blocked),
        'split_counts':{name:{'rows':len(rows),'groups':split_groups[name],
            'labels_for_design_only':dict(Counter(raw[r['idx']]['target'] for r in rows)),
            'projects':dict(Counter(r['project'] for r in rows))} for name,rows in splits.items()},
        'artifacts':artifacts, 'api_calls':0,
        'limitations':['Exposure inventory only covers local recorded artifacts; absence is not proof of never-used data.',
            'Comments/format-equivalent copies and same commits are grouped; identifier-renamed/near-clones are not detected.',
            'Prepared historical batches are conservatively treated as exposed, even if some calls failed.',
            'Group sizes may be unequal. No label balancing or threshold selection on locked test.',
            'These supplemental disjoint splits are not the official benchmark folds.']}
    (args.output/'audit.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps({k:v for k,v in report.items() if k!='artifacts'},indent=2))


if __name__ == '__main__': main()
