"""把 SVEN 切片包装为 Joern 可解析的 C 文件。

切片特征：
- 含函数签名（mark_context_stack, __get_data_block 等）
- 缺左大括号、缺右大括号、缺变量声明
- 有 if/for/while 缩进块但无大括号

策略：
1. 检测首行是否是函数签名（不含 { 且不以控制流关键字开头）
2. 在函数签名后插入 {
3. 在文件末尾追加 }
4. 包装在 extern "C" 不行（C 不是 C++），直接写 .c
5. 提供最小 typedef 让 Joern 能解析常见类型（避免 unknown type 错误）
"""
import json
import os
import re
import sys


# SVEN 切片常见类型，用 typedef/stub 让 Joern 不卡在 unknown type
TYPE_STUBS = """
typedef struct mrb_state mrb_state;
typedef struct mrb_context mrb_context;
typedef struct mrb_value mrb_value;
typedef struct inode inode;
typedef struct buffer_head buffer_head;
typedef struct MOVMuxContext MOVMuxContext;
typedef struct AVPacket AVPacket;
typedef struct MOVTrack MOVTrack;
typedef struct AC3HeaderInfo AC3HeaderInfo;
typedef struct eac3_info eac3_info;
typedef struct Image Image;
typedef struct ExceptionInfo ExceptionInfo;
typedef struct MagickPixelPacket MagickPixelPacket;
typedef struct PixelPacket PixelPacket;
typedef struct AVCodecContext AVCodecContext;
typedef struct AVFrame AVFrame;
typedef int sector_t;
typedef int pgoff_t;
typedef int ssize_t;
typedef int MagickRealType;
typedef int MagickSizeType;
typedef int QuantumType;
typedef int MagickBooleanType;
typedef int MagickStatusType;
typedef int MagickOffsetType;
typedef unsigned int MagickPixelType;
typedef int ptrdiff_t;
typedef int wchar_t;
typedef int AVRandomState;
typedef int GetByteContext;
typedef int AVCRC;
typedef int AVIOContext;
typedef int AVOption;
typedef int AVClass;
typedef int AVChannelLayout;
struct mrb_context { int stack; int stbase; int stend; int ci; int nregs; };
struct mrb_state { int dummy; };
struct inode { int i_blkbits; };
struct buffer_head { int b_size; };
struct map { int m_lblk; int m_len; int m_next_pgofs; };
"""


def is_function_signature(line):
    """判断一行是否像函数签名。"""
    s = line.strip()
    if not s:
        return False
    # 跳过控制流关键字开头的行
    if re.match(r'^(if|for|while|switch|return|else|do|case|default|break|continue|goto)\b', s):
        return False
    # 跳过纯大括号
    if s in ('{', '}', '});', '});'):
        return False
    # 函数签名特征：含括号且不以 ; 结尾
    if '(' in s and ')' in s and not s.endswith(';'):
        # 包含类型 + 函数名 + 参数列表
        return True
    return False


def wrap_slice(code, file_name):
    """把切片包装为可解析 C。返回 (wrapped_code, ok)。"""
    lines = code.split('\n')
    # 找到函数签名。SVEN 中很多签名跨多行，不能要求 '(' 与 ')' 位于
    # 同一行，否则会静默漏掉约一成样本并使评测产生选择偏差。
    sig_idx = -1
    sig_end = -1
    for i, ln in enumerate(lines):
        if is_function_signature(ln) and ln.count('(') == ln.count(')'):
            sig_idx = i
            sig_end = i
            break
        stripped = ln.strip()
        if ('(' in stripped and not stripped.endswith(';') and
                not re.match(r'^(if|for|while|switch)\b', stripped)):
            balance = 0
            for j in range(i, len(lines)):
                if j > i and re.match(r'^\s*(if|for|while|switch|return)\b', lines[j]):
                    # Missing parameters cannot be recovered from a sliced
                    # body. Never consume a later control/call ')' as signature.
                    prefix = '\n'.join('// ' + line for line in lines[:j])
                    body = '\n'.join(lines[j:])
                    wrapped = (TYPE_STUBS + '\nvoid sven_slice(void) {\n' +
                               prefix + '\n' + body + '\n}\n')
                    return wrapped, True, 'generic wrapper: incomplete signature'
                balance += lines[j].count('(') - lines[j].count(')')
                if ')' in lines[j] and balance <= 0:
                    sig_idx, sig_end = i, j
                    break
            if sig_idx >= 0:
                break
    if sig_idx < 0:
        # Last-resort wrapper keeps every labelled sample evaluable.  Joern's C
        # frontend tolerates unresolved identifiers/types inside a function far
        # better than top-level statements.
        wrapped = TYPE_STUBS + '\nvoid sven_slice(void) {\n' + code + '\n}\n'
        return wrapped, True, "generic wrapper"

    sig = '\n'.join(lines[sig_idx:sig_end + 1]).rstrip()
    # 去掉签名行尾可能的 {
    sig_clean = sig.rstrip('{').rstrip()
    # 标准化：函数签名后加 {
    new_lines = list(lines[:sig_idx]) + [sig_clean + ' {']
    body = lines[sig_end + 1:]
    # 缩进 body 让 AST 看起来正常
    new_lines.extend(body)
    new_lines.append('}')

    wrapped = TYPE_STUBS + '\n' + '\n'.join(new_lines) + '\n'
    return wrapped, True, "ok"


def main():
    hgl_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    src_json = os.environ.get(
        "SVEN_JSON_PATH", os.path.join(hgl_root, "sven_eval", "data", "sven_test.json")
    )
    out_dir = os.environ.get("SVEN_SRC_DIR", os.path.join(hgl_root, "sven_eval", "src_c"))
    os.makedirs(out_dir, exist_ok=True)
    data = json.load(open(src_json, encoding='utf-8'))

    ok_count = 0
    fail_count = 0
    manifest = []
    for i, item in enumerate(data):
        code = item['input']
        fn = item['file_name']
        # 用 index + fn 避免重名
        out_name = f"{i:04d}_{fn}"
        out_path = os.path.join(out_dir, out_name)
        wrapped, ok, reason = wrap_slice(code, fn)
        if ok:
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(wrapped)
            ok_count += 1
            manifest.append({
                'idx': i, 'file_name': fn, 'out_name': out_name,
                'label': 1 if item['output'] == 'VULNERABLE' else 0,
                'cwe': item['cwe'], 'wrapped': True, 'reason': reason,
            })
        else:
            fail_count += 1
            manifest.append({
                'idx': i, 'file_name': fn, 'out_name': None,
                'label': 1 if item['output'] == 'VULNERABLE' else 0,
                'cwe': item['cwe'], 'wrapped': False, 'reason': reason,
            })

    man_path = os.path.join(os.path.dirname(out_dir), 'data', 'manifest.json')
    with open(man_path, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2)
    print(f"OK: {ok_count}, FAIL: {fail_count}")
    print(f"Manifest: {man_path}")


if __name__ == '__main__':
    main()
