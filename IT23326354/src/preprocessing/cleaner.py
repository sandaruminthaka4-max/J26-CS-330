"""
cleaner.py — Preprocessing, cleaning, and label encoding for CICIoMT2024
Project: J26-CS-330 | Component: DoS Detection via SDN Flow Analysis
"""

import logging
from typing import Dict, List, Tuple
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder

logger = logging.getLogger(__name__)


def clean_dataframe(df: pd.DataFrame, config: dict) -> Tuple[pd.DataFrame, dict]:
    """
    Perform rigorous data cleaning:
    1. Count and remove exact duplicate records.
    2. Replace infinite values with NaN.
    3. Impute missing / NaN values using specified strategy (median).
    4. Enforce non-negative constraints on flow physical metrics.
    """
    initial_rows = len(df)
    stats = {"initial_rows": initial_rows}

    # 1. Deduplication
    if config.get("preprocessing", {}).get("remove_duplicates", True):
        df = df.drop_duplicates()
        duplicates_removed = initial_rows - len(df)
        stats["duplicates_removed"] = duplicates_removed
        logger.info(f"Removed {duplicates_removed:,} duplicate rows.")
    else:
        stats["duplicates_removed"] = 0

    # 2. Infinite values handling
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    inf_counts = np.isinf(df[numeric_cols]).sum().sum()
    stats["inf_values_found"] = int(inf_counts)
    if inf_counts > 0:
        logger.info(f"Replacing {inf_counts:,} infinite values with NaN.")
        df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)

    # 3. Missing value imputation
    nan_counts = df[numeric_cols].isna().sum().sum()
    stats["nan_values_found"] = int(nan_counts)
    if nan_counts > 0:
        fill_strategy = config.get("preprocessing", {}).get("fill_strategy", "median")
        logger.info(f"Filling NaN values using numeric column {fill_strategy}...")
        for col in numeric_cols:
            if df[col].isna().sum() > 0:
                median_val = df[col].median()
                df[col] = df[col].fillna(0.0 if np.isnan(median_val) else median_val)

    # 4. Physical feasibility clipping (non-negative metrics)
    non_negative_cols = [
        "Header_Length", "Duration", "Rate", "Srate", "Drate",
        "ack_count", "syn_count", "fin_count", "rst_count",
        "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "IAT", "Number"
    ]
    for col in non_negative_cols:
        if col in df.columns:
            df[col] = df[col].clip(lower=0.0)

    stats["final_rows"] = len(df)
    return df, stats


def encode_protocol(df: pd.DataFrame) -> Tuple[pd.DataFrame, LabelEncoder]:
    """
    Ensure 'Protocol Type' is numerically encoded for model ingestion.
    """
    encoder = LabelEncoder()
    col = "Protocol Type"
    if col in df.columns:
        # Convert to string first to handle mixed types cleanly
        df[col] = encoder.fit_transform(df[col].astype(str))
        logger.info(f"Encoded '{col}' with classes: {encoder.classes_}")
    return df, encoder


def encode_labels(
    df: pd.DataFrame,
    label_col: str,
    dos_labels: List[str],
    normal_labels: List[str],
) -> pd.DataFrame:
    """
    Map diverse multi-class labels into a rigorous binary classification:
        0 -> Normal (benign)
        1 -> DoS (Denial of Service / Distributed Denial of Service)
    
    Any irrelevant or unverified labels outside the mapping are dropped safely.
    """
    df = df.copy()
    dos_set = set(dos_labels)
    normal_set = set(normal_labels)

    # Clean label strings (strip whitespace)
    df[label_col] = df[label_col].astype(str).str.strip()

    def map_label(val: str):
        if val in normal_set:
            return 0
        elif val in dos_set:
            return 1
        return -1

    df["binary_label"] = df[label_col].apply(map_label)
    
    # Check dropped labels
    unmapped = df[df["binary_label"] == -1]
    if len(unmapped) > 0:
        logger.warning(
            f"Dropping {len(unmapped):,} rows with unmapped labels: {unmapped[label_col].value_counts().to_dict()}"
        )
        df = df[df["binary_label"] != -1].copy()

    return df
