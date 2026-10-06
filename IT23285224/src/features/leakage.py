"""
Leakage Prevention and Data Audit Tools.
Verifies no data leakage across training, validation, and test partitions.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


def audit_for_leakage(
    train_df: pd.DataFrame,
    val_df: Optional[pd.DataFrame] = None,
    test_df: Optional[pd.DataFrame] = None,
    feature_cols: Optional[List[str]] = None,
) -> Dict[str, any]:
    """
    Audits partitions for:
    1. Overlapping rows (exact duplicate flow vectors across splits).
    2. Zero-variance / constant features.
    3. Infinite or NaN values.
    4. Label contamination in feature space.
    """
    results: Dict[str, any] = {
        "passed": True,
        "warnings": [],
        "errors": [],
        "constant_features": [],
        "nan_counts": {},
        "inf_counts": {},
        "train_val_overlap_count": 0,
        "train_test_overlap_count": 0,
    }

    cols = feature_cols or [c for c in train_df.columns if c != "label"]

    # 1. Check label contamination
    if "label" in cols:
        results["passed"] = False
        results["errors"].append("Target column 'label' detected in feature columns list!")

    # 2. Check for constant features on training data
    stds = train_df[cols].std(numeric_only=True)
    constant_cols = stds[stds == 0].index.tolist()
    if constant_cols:
        results["constant_features"] = constant_cols
        results["warnings"].append(f"Constant features detected in training set: {constant_cols}")

    # 3. Check for NaNs and Infs
    train_nans = train_df[cols].isna().sum().to_dict()
    non_zero_nans = {k: int(v) for k, v in train_nans.items() if v > 0}
    if non_zero_nans:
        results["nan_counts"] = non_zero_nans
        results["warnings"].append(f"NaN values found in features: {non_zero_nans}")

    inf_counts = np.isinf(train_df[cols].select_dtypes(include=[np.number])).sum().to_dict()
    non_zero_infs = {k: int(v) for k, v in inf_counts.items() if v > 0}
    if non_zero_infs:
        results["inf_counts"] = non_zero_infs
        results["warnings"].append(f"Infinite values found in features: {non_zero_infs}")

    # 4. Check for cross-partition duplicate overlap
    # We hash rows or compare subsets to verify partition isolation
    if test_df is not None:
        train_hashes = pd.util.hash_pandas_object(train_df[cols], index=False)
        test_hashes = pd.util.hash_pandas_object(test_df[cols], index=False)
        overlap = set(train_hashes).intersection(set(test_hashes))
        results["train_test_overlap_count"] = len(overlap)
        if len(overlap) > 0:
            results["warnings"].append(
                f"Detected {len(overlap)} feature vectors with identical hashes across train and test partitions."
            )

    if val_df is not None:
        train_hashes = pd.util.hash_pandas_object(train_df[cols], index=False)
        val_hashes = pd.util.hash_pandas_object(val_df[cols], index=False)
        overlap_val = set(train_hashes).intersection(set(val_hashes))
        results["train_val_overlap_count"] = len(overlap_val)
        if len(overlap_val) > 0:
            results["warnings"].append(
                f"Detected {len(overlap_val)} feature vectors with identical hashes across train and validation partitions."
            )

    return results
