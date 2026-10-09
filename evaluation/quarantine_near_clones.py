"""Code-only clone isolation. Never access predictions or tune on labels.

Identifier-normalized exact clones plus deterministic prefix-filtered 5-token
shingle Jaccard >= .90 for functions >= 60 tokens. No candidate caps/sampling.
This detects a defined token similarity, not all semantic clones.
"""
import argparse
from array import array
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import struct
from evaluation.build_clean_protocol import TOKEN, Groups, code_hash
from evaluation.verify_clean_protocol import validate

KEYWORDS = set('auto break case char const continue default do double else enum extern float for goto if '
               'inline int long register restrict return short signed sizeof static struct switch typedef '
               'union unsigned void volatile while _Alignas _Alignof _Atomic _Bool _Complex _Generic '
               '_Imaginary _Noreturn _Static_assert _Thread_local class namespace template typename '
               'public private protected virtual new delete try catch throw bool true false nullptr '
               'using friend operator this constexpr noexcept'.split())


def canonical_tokens(code):
    identifiers, result = {}, []
    for match in TOKEN.finditer(code):
        token = match.group()
        if token.startswith(('//','/*')):
            continue
        if re.fullmatch(r'[A-Za-z_]\w*',token) and token not in KEYWORDS:
            # Consistent references are preserved, names (including APIs) are
            # normalized conservatively for clone detection, NOT classification.
            if token not in identifiers: identifiers[token] = len(identifiers)
            token = '@id'+str(identifiers[token])
        result.append(token)
    return result


def similar90(a, b):
    if not a or not b or min(len(a),len(b))*10 < max(len(a),len(b))*9:
        return False
    required = (9*(len(a)+len(b))+18)//19
    i = j = common = 0
    while i < len(a) and j < len(b):
        if common + min(len(a)-i,len(b)-j) < required:
            return False
        if a[i] == b[j]: common += 1; i += 1; j += 1
        elif a[i] < b[j]: i += 1
        else: j += 1
    return common >= required


def clone_pairs(sets, progress=None):
    frequencies = Counter()
    for values in sets.values(): frequencies.update(values)
    index = defaultdict(list)
    for step, current in enumerate(sorted(sets,key=lambda n:(len(sets[n]),n)),1):
        values = sets[current]
        prefix_size = len(values)-(9*len(values)+9)//10+1
        prefix = sorted(values,key=lambda h:(frequencies[h],h))[:prefix_size]
        candidates = set()
        for h in prefix:
            candidates.update(n for n in index[h] if len(sets[n])*10 >= len(values)*9)
        for previous in sorted(candidates):
            if similar90(values,sets[previous]): yield previous,current
        for h in prefix: index[h].append(current)
        if progress and step%1000==0: progress(step,len(sets))


def quarantine(groups, splits, n_raw):
    membership = {r['idx']:name for name,rows in splits.items() for r in rows}
    components = defaultdict(list)
    for idx in range(n_raw): components[groups.find(idx)].append(idx)
    kept = {name:[] for name in splits}
    reasons = Counter()
    for root,indices in components.items():
        assigned = {membership[i] for i in indices if i in membership}
        if not assigned: continue
        reason = 'touches_prior_excluded_group' if any(i not in membership for i in indices) \
                 else 'cross_partition_clone' if len(assigned)>1 else None
        if reason:
            reasons[reason] += sum(i in membership for i in indices)
            continue
        name = next(iter(assigned))
        kept[name].extend(indices)
    return kept,dict(reasons)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--original',type=Path,default=Path('evaluation/protocol_20261005'))
    p.add_argument('--output',type=Path,required=True)
    a = p.parse_args()
    from config import DEVIGN_JSON_PATH
    blob = Path(DEVIGN_JSON_PATH).read_bytes()
    audit = json.loads((a.original/'audit.json').read_text(encoding='utf8'))
    if hashlib.sha256(blob).hexdigest()!=audit['dataset_sha256']:
        raise ValueError('dataset changed; cannot reuse index protocol')
    raw = json.loads(blob)
    splits = {name:json.loads((a.original/f'{name}.json').read_text(encoding='utf8'))
              for name in ('development','validation','locked_test')}
    validate(splits)
    groups = Groups(len(raw))
    first_code, first_commit, first_canonical = {}, {}, {}
    hashes, shingle_sets, vocabulary = [], {}, {}
    exact_pairs = []
    for idx,row in enumerate(raw):
        digest = code_hash(row['func']); hashes.append(digest)
        if digest in first_code: groups.join(idx,first_code[digest])
        else: first_code[digest]=idx
        if row.get('commit_id'):
            key = (row.get('project',''),row['commit_id'])
            if key in first_commit: groups.join(idx,first_commit[key])
            else: first_commit[key]=idx
        tokens = canonical_tokens(row['func'])
        canonical = hashlib.sha256(json.dumps(tokens,ensure_ascii=False).encode()).hexdigest()
        if canonical in first_canonical:
            previous = first_canonical[canonical]
            groups.join(idx,previous); exact_pairs.append((previous,idx))
        else:
            first_canonical[canonical]=idx
            if len(tokens)>=60:
                encoded = []
                for token in tokens:
                    if token not in vocabulary: vocabulary[token]=len(vocabulary)
                    encoded.append(vocabulary[token])
                shingles = {int.from_bytes(hashlib.blake2b(struct.pack('>5I',*encoded[i:i+5]),
                            digest_size=8).digest(),'big') for i in range(len(encoded)-4)}
                shingle_sets[idx]=array('Q',sorted(shingles))
        if (idx+1)%1000==0: print(f'Tokenized {idx+1}/{len(raw)}',flush=True)
    for name,rows in splits.items():
        for r in rows:
            if hashes[r['idx']]!=r['source_sha256']:
                raise ValueError('manifest source mismatch')
    near_pairs = []
    for x,y in clone_pairs(shingle_sets,lambda step,total:print(f'Joined {step}/{total}',flush=True)):
        groups.join(x,y); near_pairs.append((x,y))
    kept,reasons = quarantine(groups,splits,len(raw))
    original_rows = {r['idx']:r for rows in splits.values() for r in rows}
    output = {}
    for name,indices in kept.items():
        output[name] = [{**original_rows[idx], 'group_id':hashlib.sha256(
                        f'clone-v2:{groups.find(idx)}'.encode()).hexdigest()} for idx in sorted(indices)]
    validate(output)
    a.output.mkdir(parents=True,exist_ok=False)
    for name,rows in output.items():
        (a.output/f'{name}.json').write_text(json.dumps(rows,indent=2),encoding='utf8')
    report = {**audit,'parent_protocol':str(a.original), 'api_calls':0,
        'clone_method':'consistent identifier normalization; exact tokens plus 5-token-set Jaccard >= .90; >=60 tokens for fuzzy join',
        'clone_pair_counts':{'normalized_exact':len(exact_pairs),'near':len(near_pairs)},
        'quarantined_retained_rows':reasons,
        'split_counts':{name:{'rows':len(rows),'groups':len({r['group_id'] for r in rows})}
                        for name,rows in output.items()},
        'limitations':[x for x in audit['limitations'] if 'near-clones are not detected' not in x]+[
            'Only this normalized token clone definition is checked; not all semantic clones.',
            'All identifiers including API names normalize: conservative false clone merges are possible.',
            '5-token sets ignore ordering/multiplicity and use 64-bit hashes; collisions cause conservative false merges.',
            'Short functions have normalized exact checking only; fuzzy changes in them remain unchecked.',
            'All prior-excluded groups are quarantined conservatively, not only proven history exposure.',
            'No rows reassigned or threshold optimized using labels/predictions. Locked test still requires analysis/configuration freeze.']}
    (a.output/'audit.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    (a.output/'clone_pairs.json').write_text(json.dumps({'exact':exact_pairs,'near':near_pairs}),encoding='utf8')
    print(json.dumps({k:report[k] for k in ('clone_pair_counts','quarantined_retained_rows','split_counts')},indent=2))


if __name__ == '__main__': main()
