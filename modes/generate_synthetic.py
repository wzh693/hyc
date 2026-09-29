"""
Mode 2: 合成数据集生成
"""
import os
from config import SYNTHETIC_DIR


def mode_generate_synthetic(output_dir: str = None):
    """合成数据集生成。"""
    if output_dir is None:
        output_dir = SYNTHETIC_DIR

    from data.synthetic_generator import generate_synthetic_dataset
    print("=" * 60)
    print("  Mode 2: 合成数据集生成")
    print("=" * 60)
    samples = generate_synthetic_dataset(output_dir)
    print(f"[Done] 已生成 {len(samples)} 个样本到 {output_dir}")