"""
Devign 数据集加载器（支持 4 折交叉验证）。

与 VulnSC 论文的折分保持一致，确保实验可比性。
可用于 HGL-Vul 评测、消融实验和基线对比。

数据集格式:
  devign.json: list of {project, commit_id, target, func}
    - target: 0=benign, 1=vulnerable
    - func: C/C++ 源代码

折分来源:
  enhance/devign/{model}/{fold}/{train,test,valid}.jsonl 中的 idx 字段

控制变量说明:
  - 与 VulnSC 共享完全相同的 4 折划分（通过 idx 对齐）
  - 评测原始代码 func（非增强后的 func_en），对比纯图结构推理能力
  - 可扩展加载 func_en 以评估"语义补全+图推理"的联合效果
"""

import os
import json
import random
import tempfile
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class DevignSample:
    """单个 Devign 样本。"""
    idx: int                    # 全局索引（与增强数据对齐）
    project: str                # 项目名称（FFmpeg, QEMU 等）
    commit_id: str              # 提交哈希
    target: int                 # 标签 0=benign, 1=vulnerable
    func: str                   # 原始源代码
    func_en: Optional[str] = None  # VulnSC 增强后的代码（可选）
    fold: int = -1              # 所属折（0-3）
    split: str = ""             # train/test/valid


class DevignLoader:
    """
    Devign 数据集加载器。

    用法:
        loader = DevignLoader("path/to/devign.json")
        
        # 按折加载
        train = loader.get_fold(fold=0, split="train")
        test = loader.get_fold(fold=0, split="test")
        
        # 获取全部样本（不分折）
        all_samples = loader.get_all()
        
        # 加载增强代码
        loader.load_enhanced("path/to/enhance/devign/gpt4o")
    """

    def __init__(self, devign_json_path: str):
        self.devign_json_path = devign_json_path
        self.samples: List[DevignSample] = []
        self._fold_indices: Dict[int, Dict[str, List[int]]] = {}  # fold -> split -> [idx]
        self._loaded = False

    def load(self, max_samples: Optional[int] = None,
             fold_indices: Optional[Dict[int, Dict[str, List[int]]]] = None) -> List[DevignSample]:
        """
        加载 devign.json。

        参数:
            max_samples: 最大加载样本数（用于快速调试）
            fold_indices: 折分索引，若为 None 则自动从增强数据推断
        """
        print(f"[DevignLoader] 加载: {self.devign_json_path}")

        with open(self.devign_json_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        print(f"[DevignLoader] 原始数据: {len(raw_data)} 条")

        # 构建样本列表
        self.samples = []
        for i, item in enumerate(raw_data):
            if max_samples and i >= max_samples:
                break
            sample = DevignSample(
                idx=i,
                project=item.get("project", ""),
                commit_id=item.get("commit_id", ""),
                target=item["target"],
                func=item["func"],
            )
            self.samples.append(sample)

        # 加载折分信息
        if fold_indices:
            self._fold_indices = fold_indices
        else:
            self._load_default_folds()

        # 为每个样本标注 fold 和 split
        self._assign_fold_splits()

        # 统计
        vuln = sum(1 for s in self.samples if s.target == 1)
        benign = sum(1 for s in self.samples if s.target == 0)
        print(f"[DevignLoader] 加载完成: {len(self.samples)} 样本 "
              f"(漏洞={vuln}, 良性={benign})")
        for fold in sorted(self._fold_indices.keys()):
            splits = self._fold_indices[fold]
            print(f"  Fold {fold}: {', '.join(f'{k}={len(v)}' for k, v in splits.items())}")

        self._loaded = True
        return self.samples

    def load_enhanced(self, enhance_dir: str, model: str = "gpt4o",
                      fold: Optional[int] = None):
        """
        加载 VulnSC 增强代码（func_en）。

        参数:
            enhance_dir: 增强数据根目录
            model: 增强模型（gpt4o/deepseek/codellama/mixtral）
            fold: 指定折（None=全部）
        """
        print(f"[DevignLoader] 加载增强数据: {model}")

        # 构建样本索引
        sample_map = {s.idx: s for s in self.samples}

        folds_to_load = [fold] if fold is not None else range(4)
        loaded = 0

        for f in folds_to_load:
            for split in ["train", "test", "valid"]:
                jsonl_path = os.path.join(
                    enhance_dir, model, str(f), f"{split}.jsonl"
                )
                if not os.path.exists(jsonl_path):
                    continue
                with open(jsonl_path, "r", encoding="utf-8") as fh:
                    for line in fh:
                        item = json.loads(line)
                        idx = item["idx"]
                        if idx in sample_map:
                            sample_map[idx].func_en = item.get("func_en", "")
                            sample_map[idx].fold = f
                            sample_map[idx].split = split
                            loaded += 1

        print(f"[DevignLoader] 已增强 {loaded} 个样本 (model={model})")
        return loaded

    def get_fold(self, fold: int, split: str = "test") -> List[DevignSample]:
        """获取指定折的指定分片。"""
        if not self._loaded:
            raise RuntimeError("请先调用 load()")
        if fold not in self._fold_indices:
            raise ValueError(f"无效折号: {fold} (可用: {list(self._fold_indices.keys())})")
        if split not in self._fold_indices[fold]:
            raise ValueError(f"无效分片: {split} (可用: {list(self._fold_indices[fold].keys())})")

        indices = set(self._fold_indices[fold][split])
        return [s for s in self.samples if s.idx in indices]

    def get_all(self) -> List[DevignSample]:
        """获取所有样本。"""
        if not self._loaded:
            raise RuntimeError("请先调用 load()")
        return self.samples

    def get_stats(self) -> dict:
        """获取数据集统计信息。"""
        if not self._loaded:
            return {}
        stats = {
            "total": len(self.samples),
            "vulnerable": sum(1 for s in self.samples if s.target == 1),
            "benign": sum(1 for s in self.samples if s.target == 0),
            "folds": {},
        }
        for fold in sorted(self._fold_indices.keys()):
            splits = {}
            for split, indices in self._fold_indices[fold].items():
                fold_samples = [s for s in self.samples if s.idx in indices]
                splits[split] = {
                    "count": len(indices),
                    "vulnerable": sum(1 for s in fold_samples if s.target == 1),
                    "benign": sum(1 for s in fold_samples if s.target == 0),
                }
            stats["folds"][f"fold_{fold}"] = splits
        return stats

    def extract_fold_indices_from_enhanced(self, enhance_dir: str, model: str = "gpt4o") -> Dict[int, Dict[str, List[int]]]:
        """
        从增强数据中提取折分索引。

        这确保 HGL-Vul 与 VulnSC 使用完全相同的 4 折划分。
        """
        fold_indices = {}
        for fold in range(4):
            fold_indices[fold] = {}
            for split in ["train", "test", "valid"]:
                jsonl_path = os.path.join(enhance_dir, model, str(fold), f"{split}.jsonl")
                if not os.path.exists(jsonl_path):
                    continue
                indices = []
                with open(jsonl_path, "r", encoding="utf-8") as f:
                    for line in f:
                        indices.append(json.loads(line)["idx"])
                fold_indices[fold][split] = sorted(indices)
        return fold_indices

    def _load_default_folds(self):
        """尝试从默认路径加载折分。"""
        # 尝试从增强数据目录推断折分
        candidate_paths = [
            os.path.join(os.path.dirname(self.devign_json_path),
                         "..", "enhance", "devign", "gpt4o"),
            os.path.join(os.path.dirname(os.path.dirname(self.devign_json_path)),
                         "enhance-20260913T072240Z-1-001", "enhance", "devign", "gpt4o"),
        ]
        for path in candidate_paths:
            resolved = os.path.realpath(path) if os.path.exists(path) else path
            if os.path.exists(resolved):
                try:
                    self._fold_indices = self.extract_fold_indices_from_enhanced(
                        os.path.dirname(resolved)  # resolved=.../enhance/devign/gpt4o → dirname=.../enhance/devign
                    )
                    print(f"[DevignLoader] 从增强数据加载折分: {resolved}")
                    return
                except Exception as e:
                    print(f"[DevignLoader] 折分加载失败: {e}")

        # 如果没有增强数据，创建随机 4 折
        print("[DevignLoader] 未找到增强数据，创建随机 4 折...")
        self._create_random_folds()

    def _create_random_folds(self, seed: int = 42):
        """创建随机 4 折（不依赖增强数据时使用）。

        用局部 RNG（random.Random(seed)）而非全局 random.seed()——折分本身
        需确定性可复现（同一 fold 集合保证跨版本同批可比），但全局随机源
        必须保留系统熵，否则下游 random.sample（compare_devign 采样）会被
        固定成完全相同的批次（v14/v15/v16 三次 100% 同批即此 bug）。
        """
        indices = list(range(len(self.samples)))
        rng = random.Random(seed)
        rng.shuffle(indices)

        fold_size = len(indices) // 4
        self._fold_indices = {}
        for fold in range(4):
            test_start = fold * fold_size
            test_end = (fold + 1) * fold_size if fold < 3 else len(indices)
            test_idx = indices[test_start:test_end]
            train_idx = [i for i in indices if i not in test_idx]

            # 从 train 分出 valid（约 10%）
            valid_size = max(1, len(train_idx) // 10)
            valid_idx = train_idx[:valid_size]
            train_idx = train_idx[valid_size:]

            self._fold_indices[fold] = {
                "train": sorted(train_idx),
                "test": sorted(test_idx),
                "valid": sorted(valid_idx),
            }

    def _assign_fold_splits(self):
        """
        为每个样本标注其所属的 fold 和 split。

        每个样本只属于一个 fold 的 test 集（其余 fold 中它在 train 集）。
        这里优先按 test 归属标注，确保每个样本有唯一的 (fold, split) 映射。
        """
        sample_idx_set = {s.idx for s in self.samples}

        # Step 1: 先为每个样本找到它作为 test 的 fold
        idx_to_fold = {}  # idx -> (fold, split)
        for fold, splits in self._fold_indices.items():
            for split in ["test", "valid"]:  # test 优先，其次是 valid
                for idx in splits.get(split, []):
                    if idx in sample_idx_set and idx not in idx_to_fold:
                        idx_to_fold[idx] = (fold, split)

        # Step 2: 剩余的样本分配到 train
        for fold, splits in self._fold_indices.items():
            for idx in splits.get("train", []):
                if idx in sample_idx_set and idx not in idx_to_fold:
                    idx_to_fold[idx] = (fold, "train")

        # Step 3: 标注到 sample 对象
        for s in self.samples:
            if s.idx in idx_to_fold:
                s.fold, s.split = idx_to_fold[s.idx]


class DevignBatchProcessor:
    """
    Devign 批量处理器。

    将 Devign 样本转换为 HGL-Vul 可处理的格式：
    1. 将源代码写出为临时 .c 文件（供 Joern 构建 CPG）
    2. 记录元数据（idx, target, fold）
    """

    def __init__(self, output_dir: str = "data/devign_batch"):
        self.output_dir = output_dir
        self.samples_dir = os.path.join(output_dir, "samples")
        self.metadata_path = os.path.join(output_dir, "metadata.json")
        self.results_dir = os.path.join(output_dir, "results")
        os.makedirs(self.samples_dir, exist_ok=True)
        os.makedirs(self.results_dir, exist_ok=True)

    def prepare_samples(self, samples: List[DevignSample],
                        use_enhanced: bool = False) -> List[dict]:
        """
        将样本写出为 .c 文件，返回元数据列表。

        参数:
            samples: Devign 样本列表
            use_enhanced: 是否使用 VulnSC 增强代码（func_en）
                          控制变量：默认 False，评测原始代码
        """
        metadata = []
        for sample in samples:
            code = sample.func_en if (use_enhanced and sample.func_en) else sample.func
            file_name = f"sample_{sample.idx:06d}.c"
            file_path = os.path.join(self.samples_dir, file_name)

            with open(file_path, "w", encoding="utf-8") as f:
                f.write(code)

            metadata.append({
                "idx": sample.idx,
                "sample_id": f"sample_{sample.idx:06d}",
                "file_path": file_path,
                "file_name": file_name,
                "target": sample.target,
                "fold": sample.fold,
                "split": sample.split,
                "project": sample.project,
                "commit_id": sample.commit_id,
                "use_enhanced": use_enhanced,
                "status": "pending",
            })

        # 保存元数据
        with open(self.metadata_path, "w", encoding="utf-8") as f:
            json.dump({
                "total": len(metadata),
                "vulnerable": sum(1 for m in metadata if m["target"] == 1),
                "benign": sum(1 for m in metadata if m["target"] == 0),
                "use_enhanced": use_enhanced,
                "samples": metadata,
            }, f, indent=2, ensure_ascii=False)

        print(f"[DevignBatch] 已准备 {len(metadata)} 个样本到 {self.samples_dir}")
        return metadata

    def load_results(self) -> list:
        """加载已有的评测结果。"""
        results = []
        results_file = os.path.join(self.results_dir, "evaluation_results.json")
        if os.path.exists(results_file):
            with open(results_file, "r", encoding="utf-8") as f:
                results = json.load(f)
        return results

    def save_intermediate(self, result: dict):
        """增量保存单个结果（防止中途崩溃丢失数据）。"""
        results = self.load_results()
        results.append(result)
        results_file = os.path.join(self.results_dir, "evaluation_results.json")
        with open(results_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        # 同时保存 CSV 格式方便查看
        csv_file = os.path.join(self.results_dir, "evaluation_results.csv")
        if not os.path.exists(csv_file):
            with open(csv_file, "w", encoding="utf-8") as f:
                f.write("idx,target,prediction,fold,project,hop_count,error\n")
        with open(csv_file, "a", encoding="utf-8") as f:
            r = result
            f.write(f"{r.get('idx','')},{r.get('target',-1)},{r.get('prediction',-1)},"
                    f"{r.get('fold',-1)},{r.get('project','')},{r.get('hop_count',0)},"
                    f"{r.get('error','')}\n")