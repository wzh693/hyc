import json
import os

HGL_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SVEN_JSON = os.environ.get(
    "SVEN_JSON_PATH", os.path.join(HGL_ROOT, "sven_eval", "data", "sven_test.json")
)
data = json.load(open(SVEN_JSON, encoding='utf-8'))
samples = [data[0], data[100], data[200], data[250]]
for i, s in enumerate(samples):
    print(f"--- sample {i} fn={s['file_name']} cwe={s['cwe']} label={s['output']} ---")
    print(s['input'])
    print()
