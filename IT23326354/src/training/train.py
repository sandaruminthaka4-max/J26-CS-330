"""
train.py — XGBoost DoS Detection Training Pipeline
Project: J26-CS-330 | Component: DoS Detection via SDN Flow Analysis

Usage:
    python src/training/train.py --config configs/model_config.yaml

This script:
1. Loads the CICIoMT2024 dataset from the ZIP file
2. Cleans and preprocesses the data
3. Encodes labels (Normal=0, DoS=1)
4. Splits into train / validation / test sets
5. Trains baseline models (Decision Tree, Random Forest)
6. Trains and tunes the XGBoost classifier
7. Evaluates all models on the test set
8. Saves the trained model, preprocessor, and results
"""

import argparse
import json
import logging
import os
import sys
import time
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import yaml
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import xgboost as xgb

# Add project root to path so we can import src modules
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.preprocessing.loader import load_from_zip, load_csv
from src.preprocessing.cleaner import clean_dataframe, encode_labels, encode_protocol
from src.features.extractor import get_feature_names, extract_features
from src.evaluation.evaluator import (
    compute_metrics,
    plot_confusion_matrix,
    plot_roc_curve,
    measure_inference_latency,
    compare_models,
    plot_latency_histogram,
)
from src.training.baseline import (
    train_decision_tree,
    train_random_forest,
    threshold_baseline,
    evaluate_baseline,
)

warnings.filterwarnings("ignore")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("results/logs/training.log", mode="w"),
    ],
)
logger = logging.getLogger("training")


def load_config(config_path: str) -> dict:
    """Load YAML configuration file."""
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)
    logger.info(f"Loaded config from {config_path}")
    return config


def load_dataset(config: dict) -> pd.DataFrame:
    """
    Load the CICIoMT2024 training CSV from the ZIP file.
    Falls back to loading directly if CSV path is provided.
    """
    zip_path = config["dataset"]["zip_path"]
    train_file = config["dataset"]["train_file"]

    logger.info(f"Loading dataset from ZIP: {zip_path} → {train_file}")
    logger.info("This may take 2–5 minutes for the 1.7 GB CSV. Please wait...")

    start = time.time()
    df = load_from_zip(zip_path, train_file)
    elapsed = time.time() - start

    logger.info(f"Loaded {len(df):,} rows, {len(df.columns)} columns in {elapsed:.1f}s")
    logger.info(f"Memory usage: {df.memory_usage(deep=True).sum() / 1e9:.2f} GB")
    return df


def build_preprocessor(df: pd.DataFrame, config: dict) -> tuple:
    """
    Clean, encode, and split the dataset.

    Returns:
        X_train, X_val, X_test, y_train, y_val, y_test, preprocessor_dict
    """
    label_col = config["dataset"]["label_column"]
    dos_labels = config["label_mapping"]["dos_labels"]
    normal_labels = config["label_mapping"]["normal_labels"]
    random_seed = config["preprocessing"]["random_seed"]
    test_size = config["preprocessing"]["test_size"]
    val_size = config["preprocessing"]["val_size"]

    # --- Step 1: Clean ---
    logger.info("Step 1: Cleaning dataset...")
    df, clean_stats = clean_dataframe(df, config)
    logger.info(f"Clean stats: {clean_stats}")

    # --- Step 2: Encode protocol ---
    logger.info("Step 2: Encoding Protocol Type column...")
    df, protocol_encoder = encode_protocol(df)

    # --- Step 3: Encode binary labels ---
    logger.info("Step 3: Encoding binary labels (Normal=0, DoS=1)...")
    df = encode_labels(df, label_col, dos_labels, normal_labels)

    label_counts = df["binary_label"].value_counts()
    logger.info(f"Class distribution after encoding:")
    logger.info(f"  Normal (0): {label_counts.get(0, 0):,}")
    logger.info(f"  DoS    (1): {label_counts.get(1, 0):,}")

    total = len(df)
    normal_pct = label_counts.get(0, 0) / total * 100
    dos_pct = label_counts.get(1, 0) / total * 100
    logger.info(f"  Ratio: {normal_pct:.1f}% Normal / {dos_pct:.1f}% DoS")

    # Compute scale_pos_weight for XGBoost (handles class imbalance)
    n_normal = label_counts.get(0, 1)
    n_dos = label_counts.get(1, 1)
    scale_pos_weight = n_normal / n_dos
    logger.info(f"  scale_pos_weight = {scale_pos_weight:.4f}")

    # --- Step 4: Select features ---
    logger.info("Step 4: Extracting features...")
    feature_names = get_feature_names()
    X = extract_features(df, feature_names)
    y = df["binary_label"].values

    logger.info(f"Feature matrix shape: {X.shape}")

    # --- Step 5: Split ---
    logger.info("Step 5: Splitting into train / val / test sets (stratified)...")
    # First split off test set
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y,
        test_size=test_size,
        random_state=random_seed,
        stratify=y,
    )
    # Then split remainder into train / val
    val_fraction_of_temp = val_size / (1.0 - test_size)
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp,
        test_size=val_fraction_of_temp,
        random_state=random_seed,
        stratify=y_temp,
    )

    logger.info(f"  Train : {len(X_train):,} rows ({len(X_train)/total*100:.1f}%)")
    logger.info(f"  Val   : {len(X_val):,} rows ({len(X_val)/total*100:.1f}%)")
    logger.info(f"  Test  : {len(X_test):,} rows ({len(X_test)/total*100:.1f}%)")

    preprocessor_dict = {
        "protocol_encoder": protocol_encoder,
        "feature_names": feature_names,
        "scale_pos_weight": scale_pos_weight,
        "label_map": {"0": "Normal", "1": "DoS"},
        "clean_stats": clean_stats,
    }

    return X_train, X_val, X_test, y_train, y_val, y_test, preprocessor_dict


def train_xgboost(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    config: dict,
    scale_pos_weight: float,
) -> xgb.XGBClassifier:
    """
    Train the XGBoost classifier with early stopping on validation set.
    Uses the parameters from config, overriding scale_pos_weight with the
    computed value from the actual data.
    """
    params = config["model"]["params"].copy()
    params["scale_pos_weight"] = scale_pos_weight
    params["random_state"] = config["model"]["random_seed"]

    logger.info("Training XGBoost classifier...")
    logger.info(f"Parameters: {params}")

    model = xgb.XGBClassifier(
        **params,
        early_stopping_rounds=20,
        verbosity=1,
    )

    start = time.time()
    model.fit(
        X_train,
        y_train,
        eval_set=[(X_val, y_val)],
        verbose=50,
    )
    elapsed = time.time() - start

    logger.info(f"XGBoost training complete in {elapsed:.1f}s")
    logger.info(f"Best iteration: {model.best_iteration}")
    return model


def run_evaluation(
    models_dict: dict,
    X_test: np.ndarray,
    y_test: np.ndarray,
    feature_names: list,
    config: dict,
) -> dict:
    """
    Evaluate all models on the test set.
    Returns dict mapping model_name -> metrics_dict.
    """
    figures_dir = Path(config["paths"]["figures_dir"])
    tables_dir = Path(config["paths"]["tables_dir"])
    figures_dir.mkdir(parents=True, exist_ok=True)
    tables_dir.mkdir(parents=True, exist_ok=True)

    all_results = []

    for model_name, model_info in models_dict.items():
        logger.info(f"\n{'='*50}")
        logger.info(f"Evaluating: {model_name}")

        model = model_info["model"]
        is_precomputed = model_info.get("precomputed", False)

        if is_precomputed:
            # threshold baseline returns pre-computed predictions
            y_pred = model
            y_prob = None
        else:
            y_pred = model.predict(X_test)
            y_prob = None
            if hasattr(model, "predict_proba"):
                y_prob = model.predict_proba(X_test)[:, 1]

        metrics = compute_metrics(
            y_true=y_test,
            y_pred=y_pred,
            y_prob=y_prob,
            model_name=model_name,
        )

        logger.info(f"  Accuracy : {metrics['accuracy']:.4f}")
        logger.info(f"  Precision: {metrics['precision']:.4f}")
        logger.info(f"  Recall   : {metrics['recall']:.4f}")
        logger.info(f"  F1-Score : {metrics['f1']:.4f}")
        logger.info(f"  FPR      : {metrics['fpr']:.4f}")
        logger.info(f"  FNR      : {metrics['fnr']:.4f}")
        if metrics.get("roc_auc"):
            logger.info(f"  ROC-AUC  : {metrics['roc_auc']:.4f}")

        # Confusion matrix
        cm_path = str(figures_dir / f"confusion_matrix_{model_name.replace(' ', '_')}.png")
        plot_confusion_matrix(metrics["confusion_matrix"], model_name, cm_path)

        # ROC curve (only for models with probabilities)
        if y_prob is not None:
            roc_path = str(figures_dir / f"roc_curve_{model_name.replace(' ', '_')}.png")
            plot_roc_curve(y_test, y_prob, model_name, roc_path)

        # Latency benchmark (skip for precomputed)
        if not is_precomputed:
            logger.info(f"  Measuring inference latency ({model_name})...")
            # Use a sample of 1000 test rows
            sample_size = min(1000, len(X_test))
            X_sample = X_test[:sample_size]
            latency_stats = measure_inference_latency(model, X_sample, n_repeats=1000)
            metrics["latency"] = latency_stats
            logger.info(f"  Latency median: {latency_stats['median_ms']:.3f} ms")
            logger.info(f"  Latency p95   : {latency_stats['p95_ms']:.3f} ms")

            # Latency histogram
            lat_path = str(figures_dir / f"latency_{model_name.replace(' ', '_')}.png")
            plot_latency_histogram(latency_stats["all_latencies_ms"], model_name, lat_path)

        all_results.append(metrics)

    # Model comparison chart + CSV
    compare_models(
        all_results,
        save_path=str(tables_dir / "model_comparison"),
    )

    return {m["model_name"]: m for m in all_results}


def save_artifacts(
    model: xgb.XGBClassifier,
    preprocessor_dict: dict,
    config: dict,
    results: dict,
) -> None:
    """Save the trained model, preprocessor, and results."""
    model_path = Path(config["paths"]["model_file"])
    preprocessor_path = Path(config["paths"]["preprocessor_file"])
    model_path.parent.mkdir(parents=True, exist_ok=True)

    # Save model
    joblib.dump(model, model_path)
    logger.info(f"Model saved to {model_path}")

    # Save preprocessor (protocol encoder + feature names + metadata)
    joblib.dump(preprocessor_dict, preprocessor_path)
    logger.info(f"Preprocessor saved to {preprocessor_path}")

    # Save results summary
    results_path = Path(config["paths"]["tables_dir"]) / "results_summary.json"
    # Convert numpy types to Python native for JSON serialisation
    def convert(obj):
        if isinstance(obj, (np.integer,)):
            return int(obj)
        if isinstance(obj, (np.floating,)):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        return str(obj)

    serialisable_results = json.loads(json.dumps(results, default=convert))
    with open(results_path, "w") as f:
        json.dump(serialisable_results, f, indent=2)
    logger.info(f"Results saved to {results_path}")

    # Save model metadata
    metadata = {
        "model_type": "XGBoost",
        "xgboost_version": xgb.__version__,
        "feature_count": len(preprocessor_dict["feature_names"]),
        "feature_names": preprocessor_dict["feature_names"],
        "label_map": preprocessor_dict["label_map"],
        "scale_pos_weight": preprocessor_dict["scale_pos_weight"],
        "best_iteration": getattr(model, "best_iteration", None),
        "dataset": "CICIoMT2024",
        "schema_version": "1.0",
    }
    meta_path = Path("models") / "metadata.json"
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    logger.info(f"Model metadata saved to {meta_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Train XGBoost DoS detector on CICIoMT2024 dataset"
    )
    parser.add_argument(
        "--config",
        type=str,
        default="configs/model_config.yaml",
        help="Path to YAML config file",
    )
    parser.add_argument(
        "--skip-baselines",
        action="store_true",
        help="Skip baseline model training (faster, for debugging)",
    )
    parser.add_argument(
        "--sample",
        type=int,
        default=None,
        help="Use only first N rows (for testing the pipeline quickly)",
    )
    args = parser.parse_args()

    # Ensure results directories exist
    Path("results/logs").mkdir(parents=True, exist_ok=True)
    Path("results/figures").mkdir(parents=True, exist_ok=True)
    Path("results/tables").mkdir(parents=True, exist_ok=True)

    logger.info("=" * 60)
    logger.info("DoS Detection Training Pipeline — J26-CS-330")
    logger.info("=" * 60)

    # 1. Load config
    config = load_config(args.config)

    # 2. Load dataset
    df = load_dataset(config)
    if args.sample:
        logger.info(f"[DEBUG] Using sample of {args.sample:,} rows")
        df = df.sample(n=args.sample, random_state=42).reset_index(drop=True)

    # 3. Preprocess and split
    X_train, X_val, X_test, y_train, y_val, y_test, preprocessor_dict = build_preprocessor(
        df, config
    )
    feature_names = preprocessor_dict["feature_names"]
    scale_pos_weight = preprocessor_dict["scale_pos_weight"]

    # 4. Train models
    models_to_evaluate = {}

    if not args.skip_baselines:
        logger.info("\nTraining baseline: Decision Tree...")
        dt = train_decision_tree(X_train, y_train, random_seed=42)
        models_to_evaluate["Decision Tree"] = {"model": dt}

        logger.info("Training baseline: Random Forest...")
        rf = train_random_forest(X_train, y_train, random_seed=42)
        models_to_evaluate["Random Forest"] = {"model": rf}

        logger.info("Computing threshold baseline (Rate feature)...")
        # Estimate threshold from training data
        rate_idx = feature_names.index("Rate")
        normal_mask = y_train == 0
        if normal_mask.sum() > 0:
            threshold = np.percentile(X_train[normal_mask, rate_idx], 99)
        else:
            threshold = 10000
        logger.info(f"Threshold baseline using Rate > {threshold:.0f}")
        threshold_preds = threshold_baseline(X_test, feature_names, "Rate", threshold)
        models_to_evaluate["Threshold Baseline"] = {
            "model": threshold_preds,
            "precomputed": True,
        }

    # 5. Train XGBoost
    xgb_model = train_xgboost(
        X_train, y_train, X_val, y_val, config, scale_pos_weight
    )
    models_to_evaluate["XGBoost"] = {"model": xgb_model}

    # 6. Evaluate all models on test set
    logger.info("\n" + "=" * 60)
    logger.info("EVALUATION ON HELD-OUT TEST SET")
    logger.info("=" * 60)
    results = run_evaluation(models_to_evaluate, X_test, y_test, feature_names, config)

    # 7. Save artifacts
    save_artifacts(xgb_model, preprocessor_dict, config, results)

    # 8. Summary
    logger.info("\n" + "=" * 60)
    logger.info("TRAINING COMPLETE — RESULTS SUMMARY")
    logger.info("=" * 60)
    for model_name, metrics in results.items():
        logger.info(
            f"{model_name:20s} | "
            f"Acc={metrics['accuracy']:.4f} | "
            f"F1={metrics['f1']:.4f} | "
            f"FPR={metrics['fpr']:.4f} | "
            f"FNR={metrics['fnr']:.4f}"
        )

    xgb_metrics = results.get("XGBoost", {})
    logger.info("\n--- XGBoost vs Research Targets ---")
    logger.info(f"Target accuracy/F1 > 95%: Accuracy={xgb_metrics.get('accuracy', 0):.4f}, F1={xgb_metrics.get('f1', 0):.4f}")
    if "latency" in xgb_metrics:
        lat = xgb_metrics["latency"]
        logger.info(f"Target latency < 50ms  : Median={lat['median_ms']:.3f}ms, P95={lat['p95_ms']:.3f}ms")

    logger.info("\nAll results saved to results/ directory.")
    logger.info("Model saved to models/xgboost_model.joblib")
    logger.info("Preprocessor saved to models/preprocessor.joblib")


if __name__ == "__main__":
    main()
