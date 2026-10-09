"""SVEN 数据集评测脚本。

复用 HGL-Vul 的 _run_hgl_pipeline，在 LLMxCPG 论文的 sven_test.json 上测试。
对比基准：LLMxCPG Table 4 SVEN Normal: Acc=0.6020, F1=0.7048
"""
import os
import sys
import json
import time
import argparse
import contextlib
from multiprocessing import Pool

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

# HGL-Vul 路径
HGL_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, HGL_ROOT)

from config import LLM_MODEL, LLM_API_KEY, LLM_BASE_URL
os.environ.setdefault("OPENAI_API_KEY", LLM_API_KEY)
os.environ.setdefault("OPENAI_BASE_URL", LLM_BASE_URL)
os.environ.setdefault("LLM_MODEL", LLM_MODEL)

from modes.compare_devign import _run_hgl_pipeline, _calc_metrics, _pipeline_fingerprint
from reasoning.llm_api import create_client

SVEN_JSON = os.environ.get("SVEN_JSON_PATH", os.path.join(HGL_ROOT, "sven_eval", "data", "sven_test.json"))
SRC_DIR = os.environ.get("SVEN_SRC_DIR", os.path.join(HGL_ROOT, "sven_eval", "src_c"))
CPG_CACHE = os.environ.get("SVEN_CPG_CACHE", os.path.join(HGL_ROOT, "sven_eval", "cpg_cache"))
OUTPUT_DIR = os.environ.get("SVEN_OUTPUT_DIR", os.path.join(HGL_ROOT, "sven_eval", "output"))
RUN_NAME = os.environ.get("SVEN_RUN_NAME", "hgl_vul")
TOKEN_BUDGET = 4096


def load_sven():
    """加载 sven_test.json，返回 [{idx, code, target, file_name, cwe}]"""
    data = json.load(open(SVEN_JSON, encoding='utf-8'))
    samples = []
    for i, item in enumerate(data):
        samples.append({
            'idx': i,
            'code': item['input'],
            'target': 1 if item['output'] == 'VULNERABLE' else 0,
            'file_name': item['file_name'],
            'cwe': item['cwe'],
        })
    return samples


def find_src_file(idx, file_name):
    """查找包装后的 .c 文件"""
    fn = f"{idx:04d}_{file_name}"
    path = os.path.join(SRC_DIR, fn)
    return path if os.path.exists(path) else None


def run_single(args):
    """单样本评测（用于多进程）"""
    sample, pipeline_fp = args
    idx = sample['idx']
    target = sample['target']
    file_name = sample['file_name']

    result = {
        'idx': idx, 'target': target, 'file_name': file_name,
        'cwe': sample['cwe'], 'mode': RUN_NAME,
        'pipeline_fp': pipeline_fp, 'prediction': None,
    }

    src_path = find_src_file(idx, file_name)
    if src_path is None:
        result['error'] = 'no_src_file'
        return result

    sample_id = f"{idx:04d}_{os.path.splitext(file_name)[0]}"
    sample_dir = os.path.join(CPG_CACHE, sample_id)

    try:
        # LLM client 必须在子进程内创建（OpenAI client 不可 pickle）
        from reasoning.llm_api import create_client
        client = create_client()
        code = sample['code']
        if os.environ.get("SVEN_QUIET", "0") == "1":
            with open(os.devnull, "w", encoding="utf-8") as sink, \
                    contextlib.redirect_stdout(sink):
                pred, raw_ans, tok, arb = _run_hgl_pipeline(
                    src_path, code, sample_id, sample_dir, client, TOKEN_BUDGET,
                )
        else:
            pred, raw_ans, tok, arb = _run_hgl_pipeline(
                src_path, code, sample_id, sample_dir, client, TOKEN_BUDGET,
            )
        result['prediction'] = pred
        # Keep the full bounded model answer so offline replay does not silently
        # lose a negation, final action or later-step conclusion.
        result['raw_answer'] = raw_ans
        result['tokens_used'] = tok
        result['arbitrate'] = arb
    except Exception as e:
        result['error'] = f"{type(e).__name__}: {str(e)[:300]}"
        result['prediction'] = None

    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--max-samples', type=int, default=0, help='0=all')
    parser.add_argument(
        '--indices', default='',
        help='Comma-separated dataset indices (useful for deterministic smoke tests)',
    )
    parser.add_argument('--resume', action='store_true', default=True)
    parser.add_argument('--no-resume', dest='resume', action='store_false')
    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    results_path = os.path.join(OUTPUT_DIR, 'sven_results.jsonl')

    # 加载数据
    samples = load_sven()
    print(f"Loaded {len(samples)} SVEN samples "
          f"(vul={sum(1 for s in samples if s['target']==1)}, "
          f"ben={sum(1 for s in samples if s['target']==0)})")

    if args.indices:
        requested = {int(value.strip()) for value in args.indices.split(',') if value.strip()}
        samples = [sample for sample in samples if sample['idx'] in requested]
        missing = requested - {sample['idx'] for sample in samples}
        if missing:
            parser.error(f"indices out of range: {sorted(missing)}")
        print(f"Selected indices: {sorted(requested)}")
    elif args.max_samples > 0:
        samples = samples[:args.max_samples]
        print(f"Limited to {len(samples)} samples")

    # Resume：加载已完成
    done_idx = set()
    if args.resume and os.path.exists(results_path):
        with open(results_path, encoding='utf-8') as f:
            for line in f:
                try:
                    r = json.loads(line)
                    if r.get('pipeline_fp') == _pipeline_fingerprint() and \
                       r.get('prediction') is not None:
                        done_idx.add(r['idx'])
                except Exception:
                    pass
        print(f"Resume: {len(done_idx)} already done")

    pending = [s for s in samples if s['idx'] not in done_idx]
    print(f"Pending: {len(pending)} samples, workers={args.workers}")

    if not pending:
        print("Nothing to do.")
    else:
        pipeline_fp = _pipeline_fingerprint()
        work = [(s, pipeline_fp) for s in pending]
        t0 = time.time()
        with Pool(processes=args.workers) as pool:
            for i, result in enumerate(pool.imap_unordered(run_single, work, chunksize=1)):
                with open(results_path, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(result, ensure_ascii=False) + '\n')
                elapsed = time.time() - t0
                done = i + 1
                rate = done / elapsed if elapsed > 0 else 0
                eta = (len(pending) - done) / rate if rate > 0 else 0
                mark = 'E' if result['prediction'] is None else \
                       ('✓' if result['prediction'] == result['target'] else '✗')
                err = f" err={result.get('error','')[:80]}" if result.get('error') else ''
                print(f"[{done}/{len(pending)}] {rate:.1f}/s eta={eta:.0f}s "
                      f"idx={result['idx']} t={result['target']} "
                      f"p={result['prediction']} {mark}{err}")

    # 计算指标
    print("\n" + "="*60)
    print("Final Metrics (HGL-Vul on SVEN)")
    print("="*60)
    latest_results = {}
    if os.path.exists(results_path):
        with open(results_path, encoding='utf-8') as f:
            for line in f:
                try:
                    r = json.loads(line)
                    if r.get('pipeline_fp') == _pipeline_fingerprint():
                        # Append-only retries leave an error row followed by a
                        # successful row for the same sample.  Metrics/reporting
                        # must represent each dataset index exactly once.
                        latest_results[r['idx']] = r
                except Exception:
                    pass
    all_results = list(latest_results.values())

    metrics = _calc_metrics(all_results)
    print(f"Samples evaluated: {metrics['n']}")
    print(f"Accuracy:  {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall:    {metrics['recall']:.4f}")
    print(f"F1:        {metrics['f1']:.4f}")
    print(f"\nReference (LLMxCPG Table 4 SVEN Normal):")
    print(f"  Acc=0.6020  F1=0.7048")

    # 按 CWE 分组
    from collections import defaultdict
    by_cwe = defaultdict(list)
    for r in all_results:
        by_cwe[r.get('cwe', 'unknown')].append(r)
    print("\nBy CWE:")
    for cwe, rs in sorted(by_cwe.items()):
        m = _calc_metrics(rs)
        print(f"  {cwe}: n={m['n']} acc={m['accuracy']:.4f} "
              f"f1={m['f1']:.4f} rec={m['recall']:.4f}")

    # 错误统计
    errors = [r for r in all_results if r.get('prediction') is None]
    if errors:
        print(f"\nErrors: {len(errors)} samples")
        err_types = defaultdict(int)
        for e in errors:
            err_types[e.get('error', 'unknown')[:80]] += 1
        for et, n in sorted(err_types.items(), key=lambda x: -x[1])[:5]:
            print(f"  {n}x: {et}")

    # 保存最终报告
    report = {
        'run_name': RUN_NAME,
        'pipeline_fp': _pipeline_fingerprint(),
        'llm_model': LLM_MODEL,
        'token_budget': TOKEN_BUDGET,
        'response_storage': 'full',
        'configuration': {
            name: os.environ.get(name, '') for name in (
                'NODE_IMPORTANCE_BACKEND',
                'USE_LEARNED_NODE_IMPORTANCE',
                'USE_LEARNED_SUMMARIZE',
                'USE_LEARNED_PATH_RANK',
                'MAX_REASONING_STEPS',
                'STEP1_CONFIRM_STOP',
                'SOURCE_SLICE_ASSIGNMENT_FIX',
                'COMPACT_THREE_PART_CONTEXT',
                'USE_LLM_ARBITRATION',
                'SELECTIVE_SECOND_PASS',
                'F1_EVIDENCE_ROUTING',
                'STRUCTURED_PRIOR_SUMMARY',
                'COMPACT_VERDICT_PROMPT',
                'FOCUSED_GRAPH_ANCHORS',
                'TYPE_COVERAGE_PROMPT',
                'TYPE_COVERAGE_ROUTING',
                'RECORD_REASONING_TRACE',
                'USE_ZERO_TOKEN_SECURITY_NET',
                'SECURITY_NET_THRESHOLD',
                'GRAPH_SECURITY_NET',
                'STRICT_OPERATION_TAGS',
            )
        },
        'metrics': metrics,
        'by_cwe': {cwe: _calc_metrics(rs) for cwe, rs in by_cwe.items()},
        'n_errors': len(errors),
        'n_total': len(all_results),
    }
    with open(os.path.join(OUTPUT_DIR, 'sven_report.json'), 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


if __name__ == '__main__':
    main()
