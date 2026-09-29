"""
合成数据集生成器。

生成包含已知漏洞的 C/C++ 代码样本，用于：
  1. 快速原型验证（无需下载外部数据集）
  2. 可控实验（精确控制跳数、漏洞类型）
  3. 单元测试（验证各模块功能）
"""

import os
import random
import json
SYNTHETIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "synthetic")
SYNTHETIC_CONFIG = {
    "num_samples_per_type": 10,
    "num_benign_samples": 30,
    "min_hop": 2,
    "max_hop": 12,
    "seed": 42,
    "vulnerability_types": [
        "use_after_free", "double_free", "buffer_overflow",
        "taint_style", "memory_leak", "null_pointer_deref",
    ],
}


HEADER = r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

'''

TEMPLATES = {
    "use_after_free": {
        "short": HEADER + r'''void test_uaf_short() {
    char *p = (char *)malloc({size});
    if (p) {{
        strcpy(p, "{data}");
        free(p);
        printf("%c", p[0]); // BUG: use-after-free
    }}
}
''',
        "medium": HEADER + r'''void test_uaf_medium(int flag) {
    char *p = (char *)malloc({size});
    if (!p) return;
    strcpy(p, "{data}");
    if (flag > 0) {{
        free(p);
        p = NULL;
    }}
    if (flag <= 0) {{
        printf("%s", p);
    }}
    if (flag > 0) {{
        char *q = p; // BUG: p may be freed
        if (q) printf("%c", q[0]);
    }}
}
''',
        "long": HEADER + r'''void helper_free(char *x) {{ free(x); }}
int helper_check(char *x) {{ return x && x[0]; }}

void test_uaf_long(int a, int b) {
    char *p = (char *)malloc({size});
    if (!p) return;
    strcpy(p, "{data}");
    if (a > 10) {{
        if (b < 5) {{
            helper_free(p);
        }}
    }}
    if (a > 10 && b < 5) {{
        return;
    }}
    if (helper_check(p)) {{
        printf("%s", p); // BUG: may be freed by helper_free
    }}
}
''',
    },

    "double_free": {
        "short": HEADER + r'''void test_df_short() {
    char *p = (char *)malloc({size});
    if (p) {{
        free(p);
        free(p); // BUG: double free
    }}
}
''',
        "medium": HEADER + r'''void test_df_medium(int flag) {
    char *p = (char *)malloc({size});
    if (!p) return;
    if (flag == 1) {{
        free(p);
    }}
    if (flag == 2) {{
        free(p); // BUG: double free if flag==1 path also taken
    }}
}
''',
        "long": HEADER + r'''void cleanup(char *x) {{ if (x) free(x); }}

void test_df_long(int a, int b) {
    char *p = (char *)malloc({size});
    char *q = p;
    if (!p) return;
    if (a > 0) {{
        cleanup(p);
    }}
    if (b > 0) {{
        cleanup(q); // BUG: double free via alias
    }}
}
''',
    },

    "buffer_overflow": {
        "short": HEADER + r'''void test_bof_short() {
    char buf[{buf_size}];
    char *src = "{data}";
    strcpy(buf, src); // BUG: potential overflow
}
''',
        "medium": HEADER + r'''void test_bof_medium(int len) {
    char buf[{buf_size}];
    char *data = (char *)malloc(256);
    if (!data) return;
    recv(0, data, 256, 0);
    if (len > 0) {{
        memcpy(buf, data, len); // BUG: no bounds check
    }}
    free(data);
}
''',
        "long": HEADER + r'''int get_length() {{ return 256; }}

void test_bof_long(int fd) {
    char buf[{buf_size}];
    char *data = (char *)malloc(512);
    if (!data) return;
    int n = recv(fd, data, 512, 0);
    int len = get_length();
    if (n > 0 && len > 0) {{
        if (len > sizeof(buf)) {{
            len = sizeof(buf);
        }}
        memcpy(buf, data, len); // BUG: bound check bypassed in some paths
    }}
    free(data);
}
''',
    },

    "taint_style": {
        "short": HEADER + r'''void test_taint_short(int fd) {
    char cmd[64];
    recv(fd, cmd, 64, 0);
    system(cmd); // BUG: taint from network to system()
}
''',
        "medium": HEADER + r'''void process(char *input) {{ system(input); }}

void test_taint_medium(int fd) {
    char buf[128];
    int n = recv(fd, buf, 128, 0);
    if (n > 0) {{
        process(buf); // BUG: taint propagated through function call
    }}
}
''',
        "long": HEADER + r'''char *sanitize(char *input) {{
    static char buf[256];
    strcpy(buf, input);
    return buf;
}}

void execute(char *cmd) {{ system(cmd); }}

void test_taint_long(int fd) {
    char buf[128];
    recv(fd, buf, 128, 0);
    char *sanitized = sanitize(buf);
    if (strlen(sanitized) > 0) {{
        execute(sanitized); // BUG: sanitize is insufficient
    }}
}
''',
    },

    "memory_leak": {
        "short": HEADER + r'''void test_leak_short() {
    char *p = (char *)malloc({size});
    // BUG: no free, memory leak
}
''',
        "medium": HEADER + r'''void test_leak_medium(int flag) {
    char *p = (char *)malloc({size});
    if (!p) return;
    if (flag) {{
        return; // BUG: leak on this path
    }}
    free(p);
}
''',
        "long": HEADER + r'''void test_leak_long(int a, int b) {
    char *p = (char *)malloc({size});
    char *q = (char *)malloc({size});
    if (!p || !q) {{ free(p); free(q); return; }}
    if (a > 0) {{
        free(p);
        if (b > 0) return; // BUG: q leaked
    }}
    free(p);
    free(q);
}
''',
    },

    "null_pointer_deref": {
        "short": HEADER + r'''void test_null_short(char *p) {
    if (!p) return;
    *p = 'x'; // safe
    p = NULL;
    *p = 'y'; // BUG: null pointer dereference
}
''',
        "medium": HEADER + r'''void test_null_medium(char *p, int flag) {
    if (p) {{
        if (flag) {{
            p = NULL;
        }}
        *p = 'x'; // BUG: p may be NULL if flag is true
    }}
}
''',
        "long": HEADER + r'''char *get_ptr(int flag) {{
    static char buf[64];
    return flag ? buf : NULL;
}}

void test_null_long(int a, int b) {
    char *p = get_ptr(a);
    char *q = p;
    if (b > 0) {{
        q = get_ptr(0); // may return NULL
    }}
    *q = 'x'; // BUG: q may be NULL
}
''',
    },
}

BENIGN_TEMPLATES = [
    HEADER + r'''void benign_func_1() {
    char buf[64];
    char *p = (char *)malloc(64);
    if (p) {
        strcpy(p, "safe");
        if (strlen(p) < 64) {
            strcpy(buf, p);
        }
        free(p);
    }
    printf("%s", buf);
}
''',
    HEADER + r'''void benign_func_2(int n) {
    char *p = (char *)malloc(n);
    if (!p) return;
    memset(p, 0, n);
    if (n < 256) {
        snprintf(p, n, "value: %d", n);
    }
    free(p);
}
''',
    HEADER + r'''int benign_func_3(int a, int b) {
    int *p = (int *)malloc(sizeof(int) * 2);
    if (!p) return -1;
    p[0] = a;
    p[1] = b;
    int result = p[0] + p[1];
    free(p);
    return result;
}
''',
    HEADER + r'''void benign_func_4(char *input, int len) {
    char *buf = (char *)malloc(len + 1);
    if (!buf) return;
    if (len < 1024) {
        memcpy(buf, input, len);
        buf[len] = '\0';
        printf("%s", buf);
    }
    free(buf);
}
''',
    HEADER + r'''void benign_func_5() {
    char *a = (char *)malloc(32);
    char *b = (char *)malloc(32);
    if (a && b) {
        strcpy(a, "hello");
        strcpy(b, "world");
        printf("%s %s", a, b);
    }
    free(a);
    free(b);
}
''',
]


class SyntheticDatasetGenerator:
    """
    合成漏洞数据集生成器。

    生成包含已知漏洞类型和近似跳数的 C/C++ 代码样本，
    用于快速原型验证和可控实验。
    """

    def __init__(self, config: dict = None):
        self.config = config or SYNTHETIC_CONFIG
        self.random = random.Random(42)

    def generate(self, output_dir: str = None) -> list:
        """
        生成合成数据集。
        返回: list of samples
        """
        if output_dir is None:
            output_dir = SYNTHETIC_DIR
        os.makedirs(output_dir, exist_ok=True)

        samples = []
        sample_id = 0

        # 生成漏洞样本
        for vul_type in self.config["vulnerability_types"]:
            num_samples = self.config["num_samples_per_type"]
            templates = TEMPLATES.get(vul_type, {})
            if not templates:
                print(f"[Synthetic] 未知漏洞类型: {vul_type}")
                continue

            for i in range(num_samples):
                # 选择跳数级别
                hop_level = self.random.choice(["short", "medium", "long"])
                template = templates.get(hop_level, templates.get("short", ""))

                if not template:
                    continue

                # 填充模板参数
                size = self.random.choice([32, 64, 100, 128, 256])
                buf_size = self.random.choice([8, 16, 32, 64])
                data = self.random.choice([
                    "A" * 50, "B" * 100, "test_data", "hello_world",
                ])
                # 1. 先将 {{ 转换为 {（C代码中的花括号）
                # 2. 再替换占位符
                # 3. 最后将 }} 转换为 }（如果在替换占位符之后还有的话）
                code = template.replace("{{", "__LBRACE__").replace("}}", "__RBRACE__")
                code = code.replace("{size}", str(size)) \
                          .replace("{buf_size}", str(buf_size)) \
                          .replace("{data}", data)
                code = code.replace("__LBRACE__", "{").replace("__RBRACE__", "}")

                sample_id += 1
                sample = {
                    "id": sample_id,
                    "code": code,
                    "label": 1,  # 有漏洞
                    "vul_type": vul_type,
                    "cwe": self._vul_type_to_cwe(vul_type),
                    "hop_level": hop_level,
                    "hop_count": {"short": 2, "medium": 4, "long": 7}[hop_level],
                    "source": "synthetic",
                }
                samples.append(sample)

                # 写入文件
                fname = f"{vul_type}_{hop_level}_{sample_id}.c"
                filepath = os.path.join(output_dir, fname)
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(code)

        # 生成良性样本
        num_benign = self.config["num_benign_samples"]
        for i in range(num_benign):
            template = self.random.choice(BENIGN_TEMPLATES)
            # 将 {{ 转换为 {，}} 转换为 }
            code = template.replace("{{", "{").replace("}}", "}")
            sample_id += 1
            sample = {
                "id": sample_id,
                "code": code,
                "label": 0,  # 无漏洞
                "vul_type": "benign",
                "cwe": "",
                "hop_level": "none",
                "hop_count": 0,
                "source": "synthetic",
            }
            samples.append(sample)

            fname = f"benign_{sample_id}.c"
            filepath = os.path.join(output_dir, fname)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(code)

        # 保存元数据
        metadata = {
            "total_samples": len(samples),
            "vulnerable": len([s for s in samples if s["label"] == 1]),
            "benign": len([s for s in samples if s["label"] == 0]),
            "by_type": {},
            "by_hop": {},
        }
        for s in samples:
            vt = s.get("vul_type", "benign")
            metadata["by_type"][vt] = metadata["by_type"].get(vt, 0) + 1
            hl = s.get("hop_level", "none")
            metadata["by_hop"][hl] = metadata["by_hop"].get(hl, 0) + 1

        metadata_path = os.path.join(output_dir, "metadata.json")
        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        print(f"[Synthetic] 生成完成:")
        print(f"  总样本: {metadata['total_samples']}")
        print(f"  漏洞样本: {metadata['vulnerable']}")
        print(f"  良性样本: {metadata['benign']}")
        print(f"  按类型: {metadata['by_type']}")
        print(f"  按跳数: {metadata['by_hop']}")
        print(f"  输出目录: {output_dir}")

        return samples

    def _vul_type_to_cwe(self, vul_type: str) -> str:
        """漏洞类型到 CWE 编号的映射。"""
        mapping = {
            "use_after_free": "CWE-416",
            "double_free": "CWE-415",
            "buffer_overflow": "CWE-120",
            "taint_style": "CWE-78",
            "memory_leak": "CWE-401",
            "null_pointer_deref": "CWE-476",
        }
        return mapping.get(vul_type, "")


def generate_synthetic_dataset(output_dir: str = None) -> list:
    """便捷函数：生成合成数据集。"""
    generator = SyntheticDatasetGenerator()
    return generator.generate(output_dir)