"""Conservative lexical observations, NOT a path-sensitive program-state solver.

Locations describe source occurrences, never feasible execution order, object
identity, successful allocation/input, dominating guards, or vulnerability facts.
"""
import re
from planning.state_memory import ProgramState


def mask_noncode(code):
    # Preserve offsets/newlines, including C translation-phase line splicing.
    code = re.sub(r'\\\r?\n', lambda m: ' ' * len(m.group()), code or '')
    pattern = r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/'
    return re.sub(pattern, lambda m: ''.join('\n' if c == '\n' else ' ' for c in m.group()), code)


def call_arguments(code, start):
    """Balanced delimiters; literals already masked. Unsupported input yields []."""
    stack, begin, args = ['('], start + 1, []
    pairs = {')': '(', ']': '[', '}': '{'}
    for pos in range(start + 1, len(code)):
        ch = code[pos]
        if ch in '([{':
            stack.append(ch)
        elif ch in ')]}':
            if not stack or stack[-1] != pairs[ch]:
                return []
            stack.pop()
            if not stack:
                return args + [(begin, code[begin:pos])]
        elif ch == ',' and len(stack) == 1:
            args.append((begin, code[begin:pos]))
            begin = pos + 1
    return []


def observations(source):
    code = mask_noncode(source)
    result = []

    def add(pos, var, kind, detail=''):
        result.append({'offset': pos, 'line': source.count('\n', 0, pos) + 1,
                       'variable': var, 'state': kind, 'detail': detail,
                       'certainty': 'may', 'scope': 'unresolved'})

    ident = r'[A-Za-z_]\w*'
    # Only simple lvalues; member/dereference/array targets remain unresolved.
    assignments = list(re.finditer(rf'(?<![\w.>])\b({ident})\s*=(?!=)', code))
    for match in assignments:
        prefix = code[max(0, code.rfind(';', 0, match.start()) + 1):match.start()]
        if re.search(r'(?:->|\.)\s*$', prefix):
            continue
        if prefix.rstrip().endswith('*') and not re.search(
                r'\b(?:char|int|void|long|short|struct\s+\w+)\s*\*\s*$', prefix):
            continue
        rhs = code[match.end():]
        alloc = re.match(r'\s*(?:\([^;=]*?\)\s*)?'
                         r'(malloc|calloc|realloc|alloca|mmap|av_malloc|av_calloc|'
                         r'av_mallocz|av_malloc_array|kmalloc|kzalloc)\s*\(', rhs)
        if alloc:
            add(match.start(), match.group(1), 'alloc-call', alloc.group(1))
        elif re.match(r'\s*getenv\s*\(', rhs):
            add(match.start(), match.group(1), 'input-call', 'getenv')
        else:
            alias = re.match(rf'\s*({ident})\s*;', rhs)
            if alias:
                add(match.start(), match.group(1), 'copy', alias.group(1))
            else:
                add(match.start(), match.group(1), 'assign')

    buffer_indices = {'recv': 1, 'recvfrom': 1, 'read': 1, 'fread': 0,
                      'fgets': 0, 'gets': 0}
    frees = {'free', 'av_free', 'kfree', 'av_freep', 'munmap'}
    for match in re.finditer(rf'\b({ident})\s*\(', code):
        api = match.group(1)
        args = call_arguments(code, code.index('(', match.start(), match.end()))
        indices = ([0] if api in frees else [buffer_indices[api]] if api in buffer_indices
                   else list(range(1 if api == 'scanf' else 2, len(args)))
                   if api in {'scanf', 'sscanf', 'fscanf'} else [])
        for index in indices:
            if index >= len(args):
                continue
            target = re.fullmatch(rf'\s*&?\s*({ident})\s*', args[index][1])
            if target:
                add(match.start(), target.group(1), 'free-call' if api in frees else 'input-call', api)

    for match in re.finditer(rf'\b({ident})\s*(?:->\s*{ident}|\[[^\]]+\])', code):
        add(match.start(), match.group(1), 'use')
    # Restrict unary '*' to syntactic expression starts; omit ambiguous declarations.
    for match in re.finditer(rf'(?:[=(,;{{}}]|\breturn)\s*\*\s*({ident})', code):
        add(code.index('*', match.start(), match.end()), match.group(1), 'use')
    for match in re.finditer(rf'\b({ident})\s*(==|!=)\s*(NULL|0)\b|!\s*({ident})\b', code):
        add(match.start(), match.group(1) or match.group(4), 'null-test', match.group(2) or '!')
    return sorted(result, key=lambda event: (event['offset'], event['state'], event['variable']))


class ObservedProgramState(ProgramState):
    observation_only = True

    def __init__(self):
        super().__init__()
        self.events = []
        self._identities = set()
        self._source = ''
        self._reference = ProgramState()

    def _record(self, event, identity, step):
        key = (identity, event['variable'], event['state'], event['detail'])
        if key in self._identities:
            return
        self._identities.add(key)
        self.events.append(dict(event, identity=identity, step=step))
        self.states.setdefault(event['variable'], []).append(
            dict(event, source=identity, step=step))

    def track_vars(self, code):
        if self._source and self._source != code:
            raise ValueError('One observed tracker must not mix different function sources')
        self._source = code
        if not self._reference.states:
            self._reference.track_vars(code)
        for event in observations(code):
            self._record(event, f"src:{event['offset']}", 0)

    def observe_graph_node(self, node_id, attributes, step):
        code = attributes.get('code', '')
        # METHOD/BLOCK code includes descendant text: never synthesize execution events.
        if attributes.get('node_type', attributes.get('label', attributes.get('_label', ''))) in {'METHOD', 'BLOCK'}:
            return
        # Reconcile only a unique exact fragment. Joern line offsets are not trusted.
        start = self._source.find(code) if code else -1
        unique = start >= 0 and self._source.find(code, start + 1) < 0
        for event in observations(code):
            if unique:
                offset = start + event['offset']
                event['offset'] = offset
                event['line'] = self._source.count('\n', 0, offset) + 1
                identity = f'src:{offset}'
            else:
                event['line'] = None
                identity = f'node:{node_id}:{event["offset"]}'
            self._record(event, identity, step)

    def get_current_state(self, var):
        return 'unknown'  # Lexical last occurrence is not runtime state.

    def is_freed_and_used(self, var):
        return None

    def is_double_free(self, var):
        return None

    def is_null_pointer_deref(self, var):
        return None

    def is_taint_propagation(self, var):
        return None

    def render(self, max_chars):
        reference = self._reference.dump().strip()
        cap = min(max_chars, len(reference)) if self._source else max_chars
        byte_cap = len(reference[:max_chars].encode()) if self._source else max_chars
        text = 'MAY;unordered:'
        if len(text) > cap or len(text.encode()) > byte_cap:
            return ''
        # Source-location order is for presentation only. Whole units, no arrows.
        for event in self.events:
            location = f'L{event["line"]}' if event['line'] is not None else 'G'
            detail = f'={event["detail"]}' if event['state'] == 'copy' else ''
            unit = f' {event["variable"]}:{event["state"]}{detail}@{location};'
            if len(text + unit) <= cap and len((text + unit).encode()) <= byte_cap:
                text += unit
        return text

    def dump(self):
        return self.render(350)

    def serialize(self):
        return self.dump()
