"""逐文件进程隔离运行本地回归套件。

背景(20261011 审查发现): 多个测试文件在模块级对候选源码目录做
sys.path.insert,而 `python -m unittest discover` 在单进程内共享
sys.modules 模块缓存——后导入的测试会拿到先前插入路径上解析到的
候选模块(或反过来,root 模块令候选子模块永远找不到)。全量 discover
曾因此出现 12 失败 + 1 导入错误,而每个文件单独运行全部通过。

用法:
    python -X utf8 -m evaluation.run_tests_isolated            # 全部 evaluation/test*.py
    python -X utf8 -m evaluation.run_tests_isolated test_semantic_repairs.py
退出码 0 = 全部通过;汇总写入 stdout。
"""
import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVAL = ROOT/'evaluation'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pattern', nargs='*', help='可选: 要运行的 test*.py 文件名')
    args = parser.parse_args()
    if args.pattern:
        files = [EVAL/p for p in args.pattern]
    else:
        files = sorted(EVAL.glob('test*.py'))
    failures = []
    total_tests = 0
    started = time.monotonic()
    for path in files:
        command = [sys.executable, '-X', 'utf8', '-m', 'unittest', '-v',
                   'evaluation.'+path.stem]
        result = subprocess.run(command, cwd=ROOT, capture_output=True,
                                text=True, encoding='utf8', errors='replace')
        summary_line = ''
        for line in result.stdout.splitlines():
            if line.startswith(('Ran ', 'OK', 'FAILED')):
                summary_line += line + ' '
        status = 'PASS' if result.returncode == 0 else 'FAIL'
        print(f'{status} {path.name:60s} {summary_line.strip()}')
        if result.returncode != 0:
            failures.append(path.name)
            # 保留失败详情供人工检查
            detail = [l for l in result.stdout.splitlines()
                      if l.startswith(('FAIL:', 'ERROR:'))]
            for line in detail:
                print('     ', line)
    elapsed = time.monotonic()-started
    print(f'\n{len(files)} files, {len(failures)} failed, {elapsed:.0f}s')
    if failures:
        print('FAILED FILES:', ', '.join(failures))
        raise SystemExit(1)
    print('ALL TEST FILES PASS (isolated processes)')


if __name__ == '__main__':
    main()
