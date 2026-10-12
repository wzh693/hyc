"""Non-mutating wrapper-risk audit. Never invent missing types or scopes."""
import re
from linearization.source_mapping import source_line_offset


def audit_wrapper(source, wrapped):
    offset=source_line_offset(source,wrapped)
    pattern=r'/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    masked=re.sub(pattern,lambda m:''.join('\n' if c=='\n' else ' ' for c in m.group()),source)
    depth=0; underflow=False
    for char in masked:
        depth+=(char=='{')-(char=='}')
        underflow |= depth<0
    prefix='\n'.join(wrapped.splitlines()[:offset]) if offset<=len(wrapped.splitlines()) else ''
    return dict(line_mapping_valid=0<=offset<=len(wrapped.splitlines())-len(source.splitlines()),
        original_braces_balanced=not underflow and depth==0,
        synthetic_type_declarations=bool(re.search(r'\btypedef\b|\bstruct\b[^;]*\{',prefix)),
        synthetic_layouts_present=bool(re.search(r'\bstruct\s+\w+\s*\{',prefix)),
        policy='No inferred layout/width/scope/helper contract. Frozen wrapper is not repaired by this audit.',
        requires_source_recovery_for_semantic_certification=True)
