"""
Reproducible Preprocessing & Partitioning Pipeline.
Audits raw extracted data, handles missing/infinite values, drops zero-variance features,
performs stratified train/validation splitting, and produces audit reports and figures.
"""

import json
import logging
import os
import sys
import time

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.model_selection import train_test_split

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.data.schema import NUMERICAL_FEATURE_COLUMNS, TARGET_CLASSES
from src.features.leakage import audit_for_leakage
from src.features.preprocessor import ReconFlowPreprocessor

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("PreprocessData")


def main():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    interim_dir = os.path.join(base_dir, "data", "interim")
    processed_dir = os.path.join(base_dir, "data", "processed")
    os.makedirs(processed_dir, exist_ok=True)
    figures_dir = os.path.join(base_dir, "results", "figures")
    os.makedirs(figures_dir, exist_ok=True)
    tables_dir = os.path.join(base_dir, "results", "tables")
    os.makedirs(tables_dir, exist_ok=True)

    raw_train_path = os.path.join(interim_dir, "recon_raw_train.csv")
    raw_test_path = os.path.join(interim_dir, "recon_raw_test.csv")

    logger.info("Loading raw extracted train and test sets...")
    df_train_full = pd.read_csv(raw_train_path)
    df_test_full = pd.read_csv(raw_test_path)

    logger.info(f"Loaded Raw Train: {df_train_full.shape}, Raw Test: {df_test_full.shape}")

    # Inspect class counts
    logger.info("Raw Train Class Distribution:\n" + str(df_train_full["label"].value_counts()))
    logger.info("Raw Test Class Distribution:\n" + str(df_test_full["label"].value_counts()))

    # Audit for leakage and data anomalies
    logger.info("Performing Leakage & Quality Audit...")
    audit_report = audit_for_leakage(
        train_df=df_train_full,
        test_df=df_test_full,
        feature_cols=NUMERICAL_FEATURE_COLUMNS,
    )

    audit_report_path = os.path.join(tables_dir, "data_audit_report.json")
    with open(audit_report_path, "w", encoding="utf-8") as f:
        json.dump(audit_report, f, indent=2)
    logger.info(f"Audit report saved to: {audit_report_path}")
    if audit_report["warnings"]:
        for w in audit_report["warnings"]:
            logger.warning(f"Audit Warning: {w}")

    # Fit preprocessor strictly on raw train
    logger.info("Fitting ReconFlowPreprocessor strictly on training partition...")
    preprocessor = ReconFlowPreprocessor(
        scaler_type="standard",
        drop_constant_features=True,
        feature_columns=NUMERICAL_FEATURE_COLUMNS,
    )
    preprocessor.fit(df_train_full)

    # Save fitted preprocessor
    prep_path = os.path.join(base_dir, "models", "preprocessor.joblib")
    preprocessor.save(prep_path)

    # Stratified train/val split from official training set (80% train, 20% validation)
    logger.info("Splitting official training data into Train (80%) and Validation (20%) with stratification...")
    df_train, df_val = train_test_split(
        df_train_full,
        test_size=0.20,
        random_state=42,
        stratify=df_train_full["label"],
    )

    logger.info(f"Partition shapes -> Train: {df_train.shape}, Val: {df_val.shape}, Test: {df_test_full.shape}")

    # Export sanitized partitions
    train_out = os.path.join(processed_dir, "train.csv")
    val_out = os.path.join(processed_dir, "val.csv")
    test_out = os.path.join(processed_dir, "test.csv")

    df_train.to_csv(train_out, index=False)
    df_val.to_csv(val_out, index=False)
    df_test_full.to_csv(test_out, index=False)
    logger.info(f"Exported processed partitions to {processed_dir}")

    # Record class distribution table
    dist_data = {
        "Class": TARGET_CLASSES,
        "Train_Count": [int((df_train["label"] == c).sum()) for c in TARGET_CLASSES],
        "Val_Count": [int((df_val["label"] == c).sum()) for c in TARGET_CLASSES],
        "Test_Count": [int((df_test_full["label"] == c).sum()) for c in TARGET_CLASSES],
    }
    dist_df = pd.DataFrame(dist_data)
    dist_df["Total"] = dist_df["Train_Count"] + dist_df["Val_Count"] + dist_df["Test_Count"]
    dist_df["Percentage"] = (dist_df["Total"] / dist_df["Total"].sum() * 100).round(2)
    dist_csv_path = os.path.join(tables_dir, "class_distribution.csv")
    dist_df.to_csv(dist_csv_path, index=False)
    logger.info(f"Class distribution table saved to: {dist_csv_path}")

    # Generate Class Distribution Figure
    plt.figure(figsize=(10, 5))
    sns.set_theme(style="whitegrid")
    df_counts = dist_df.melt(id_vars=["Class"], value_vars=["Train_Count", "Val_Count", "Test_Count"], var_name="Split", value_name="Samples")
    ax = sns.barplot(data=df_counts, x="Class", y="Samples", hue="Split", palette="mako")
    ax.set_yscale("log")
    plt.title("CICIoMT2024 Reconnaissance & Benign Class Distribution (Log Scale)", fontsize=13, weight="bold")
    plt.ylabel("Number of Flows (log scale)", fontsize=11)
    plt.xlabel("Target Class", fontsize=11)
    plt.tight_layout()
    fig_path = os.path.join(figures_dir, "class_distribution.png")
    plt.savefig(fig_path, dpi=300)
    plt.close()
    logger.info(f"Class distribution figure saved to: {fig_path}")

    logger.info("Preprocessing phase successfully completed.")


if __name__ == "__main__":
    main()
