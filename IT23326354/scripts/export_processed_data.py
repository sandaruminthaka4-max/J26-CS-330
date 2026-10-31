"""
export_processed_data.py — Preprocess and save partitioned dataset to data/processed/
Project: J26-CS-330 | Component: DoS Detection via SDN Flow Analysis

Usage:
    python scripts/export_processed_data.py
"""

import json
import sys
import time
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pandas as pd
import yaml
from sklearn.model_selection import train_test_split

from src.preprocessing.loader import load_from_zip
from src.preprocessing.cleaner import clean_dataframe, encode_labels, encode_protocol
from src.features.extractor import get_feature_names


def main():
    print("=" * 65)
    print("Dataset Preprocessing & Export Pipeline")
    print("Project: J26-CS-330 | CICIoMT2024")
    print("=" * 65)

    config_path = PROJECT_ROOT / "configs" / "model_config.yaml"
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    zip_path = config["dataset"]["zip_path"]
    train_file = config["dataset"]["train_file"]
    label_col = config["dataset"]["label_column"]
    dos_labels = config["label_mapping"]["dos_labels"]
    normal_labels = config["label_mapping"]["normal_labels"]
    random_seed = config["preprocessing"]["random_seed"]

    processed_dir = PROJECT_ROOT / "data" / "processed"
    processed_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n[1] Loading dataset from ZIP ({zip_path})...")
    t0 = time.time()
    # Load dataset
    df = load_from_zip(zip_path, train_file)
    print(f"Loaded {len(df):,} raw rows in {time.time() - t0:.1f}s.")

    # We sample a representative stratified 200,000-row dataset for clean on-disk CSV export
    # to avoid creating multi-gigabyte disk files while preserving exact class ratios
    sample_size = 200000
    print(f"\n[2] Sampling {sample_size:,} rows for stratified export...")
    df = df.sample(n=sample_size, random_state=random_seed).reset_index(drop=True)

    print("\n[3] Cleaning data (deduplication, infinite values, median imputation)...")
    df, clean_stats = clean_dataframe(df, config)

    print("\n[4] Encoding Protocol Type and Labels...")
    df, protocol_encoder = encode_protocol(df)
    df = encode_labels(df, label_col, dos_labels, normal_labels)

    feature_names = get_feature_names()
    columns_to_keep = feature_names + ["binary_label"]

    df_final = df[columns_to_keep].copy()

    counts = df_final["binary_label"].value_counts()
    print(f"Class distribution:")
    print(f"  Normal (0) : {counts.get(0, 0):,} ({counts.get(0, 0)/len(df_final)*100:.2f}%)")
    print(f"  DoS    (1) : {counts.get(1, 0):,} ({counts.get(1, 0)/len(df_final)*100:.2f}%)")

    print("\n[5] Splitting into Train (70%), Validation (15%), Test (15%)...")
    train_df, temp_df = train_test_split(
        df_final,
        test_size=0.30,
        random_state=random_seed,
        stratify=df_final["binary_label"]
    )
    val_df, test_df = train_test_split(
        temp_df,
        test_size=0.50,
        random_state=random_seed,
        stratify=temp_df["binary_label"]
    )

    print(f"  Train Set : {len(train_df):,} rows")
    print(f"  Val Set   : {len(val_df):,} rows")
    print(f"  Test Set  : {len(test_df):,} rows")

    print("\n[6] Saving CSV files to data/processed/...")
    train_path = processed_dir / "train.csv"
    val_path = processed_dir / "val.csv"
    test_path = processed_dir / "test.csv"

    train_df.to_csv(train_path, index=False)
    val_df.to_csv(val_path, index=False)
    test_df.to_csv(test_path, index=False)

    summary = {
        "dataset_source": "CICIoMT2024 (train_iomt.csv)",
        "total_exported_rows": len(df_final),
        "feature_count": len(feature_names),
        "classes": {"0": "Normal (benign)", "1": "DoS (Attack)"},
        "train_rows": len(train_df),
        "val_rows": len(val_df),
        "test_rows": len(test_df),
        "files": {
            "train": str(train_path),
            "val": str(val_path),
            "test": str(test_path),
        },
        "clean_stats": clean_stats,
    }

    summary_path = processed_dir / "preprocessing_summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    print("\n" + "=" * 65)
    print("SUCCESS: Preprocessed dataset exported!")
    print(f"  Train CSV : {train_path} ({train_path.stat().st_size / 1e6:.2f} MB)")
    print(f"  Val CSV   : {val_path} ({val_path.stat().st_size / 1e6:.2f} MB)")
    print(f"  Test CSV  : {test_path} ({test_path.stat().st_size / 1e6:.2f} MB)")
    print(f"  Summary   : {summary_path}")
    print("=" * 65)


if __name__ == "__main__":
    main()
