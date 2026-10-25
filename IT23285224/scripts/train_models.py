"""
Comprehensive Model Training, Cross-Validation, Baseline Benchmarking & Evaluation Pipeline.
Trains 6 candidate algorithms, evaluates 4 baselines, profiles lightweight performance,
and exports the final champion pipeline artifact.
"""

import json
import logging
import os
import sys
import time
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.data.schema import CLASS_TO_INT_MAP, TARGET_CLASSES
from src.evaluation.metrics import compute_all_metrics, plot_confusion_matrix_heatmap
from src.evaluation.profiler import DeploymentProfiler, compute_deployment_score
from src.features.preprocessor import ReconFlowPreprocessor
from src.models.baselines import HierarchicalReconClassifier
from src.models.classifiers import get_classifier

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("TrainModels")


class CompleteInferencePipeline:
    """
    Atomic deployment artifact bundling preprocessor, feature selector indices, and champion model.
    Accepts raw unscaled dictionaries or DataFrames and outputs predictions + calibrated probabilities.
    """

    def __init__(self, preprocessor: ReconFlowPreprocessor, selected_features: List[str], model: Any):
        self.preprocessor = preprocessor
        self.selected_features = selected_features
        self.active_features = preprocessor.active_features_
        self.feature_indices = [self.active_features.index(f) for f in selected_features]
        self.model = model
        self.classes_ = model.classes_ if hasattr(model, "classes_") else np.array(range(5))

    def predict(self, X: Any) -> np.ndarray:
        X_clean = self.preprocessor.transform(X)
        X_selected = X_clean[:, self.feature_indices]
        return self.model.predict(X_selected)

    def predict_proba(self, X: Any) -> np.ndarray:
        X_clean = self.preprocessor.transform(X)
        X_selected = X_clean[:, self.feature_indices]
        if hasattr(self.model, "predict_proba"):
            return self.model.predict_proba(X_selected)
        else:
            # Fallback for models without proba
            preds = self.model.predict(X_selected)
            probas = np.zeros((len(preds), len(TARGET_CLASSES)), dtype=np.float64)
            for i, p in enumerate(preds):
                probas[i, int(p)] = 1.0
            return probas


def main():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    processed_dir = os.path.join(base_dir, "data", "processed")
    configs_dir = os.path.join(base_dir, "configs")
    models_dir = os.path.join(base_dir, "models")
    tables_dir = os.path.join(base_dir, "results", "tables")
    figures_dir = os.path.join(base_dir, "results", "figures")

    # Load data
    logger.info("Loading processed dataset partitions...")
    df_train = pd.read_csv(os.path.join(processed_dir, "train.csv"))
    df_val = pd.read_csv(os.path.join(processed_dir, "val.csv"))
    df_test = pd.read_csv(os.path.join(processed_dir, "test.csv"))

    preprocessor = ReconFlowPreprocessor.load(os.path.join(models_dir, "preprocessor.joblib"))
    active_features = preprocessor.active_features_

    with open(os.path.join(configs_dir, "selected_features.json"), "r") as f:
        selected_manifest = json.load(f)
    selected_features = selected_manifest["selected_features"]
    selected_indices = [active_features.index(f) for f in selected_features]
    logger.info(f"Loaded {len(selected_features)} selected features: {selected_features}")

    # Preprocess feature matrices
    logger.info("Transforming partitions...")
    X_train_full = preprocessor.transform(df_train)
    X_val_full = preprocessor.transform(df_val)
    X_test_full = preprocessor.transform(df_test)

    X_train_sel = X_train_full[:, selected_indices]
    X_val_sel = X_val_full[:, selected_indices]
    X_test_sel = X_test_full[:, selected_indices]

    y_train = df_train["label"].map(CLASS_TO_INT_MAP).to_numpy()
    y_val = df_val["label"].map(CLASS_TO_INT_MAP).to_numpy()
    y_test = df_test["label"].map(CLASS_TO_INT_MAP).to_numpy()

    # Define candidate models
    candidate_names = [
        "decision_tree",
        "logistic_regression",
        "linear_svm",
        "random_forest",
        "xgboost",
        "lightgbm",
    ]

    model_benchmarks = []
    trained_models = {}

    # Perform 5-Fold Stratified Cross-Validation on a representative training subset (50k samples)
    # to maintain fast, deterministic academic benchmarking while keeping all minority samples
    n_cv = min(50_000, len(y_train))
    rng = np.random.default_rng(42)
    cv_indices = []
    for cls_idx in range(len(TARGET_CLASSES)):
        mask = np.where(y_train == cls_idx)[0]
        if len(mask) < 2000:
            cv_indices.extend(mask)
        else:
            cv_indices.extend(rng.choice(mask, size=min(12_000, len(mask)), replace=False))
    cv_indices = np.array(cv_indices)

    X_cv = X_train_sel[cv_indices]
    y_cv = y_train[cv_indices]
    logger.info(f"5-Fold Cross-Validation set size: {len(X_cv)} flows.")

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    logger.info("=== PHASE 6: 5-FOLD STRATIFIED CROSS-VALIDATION ===")
    for model_name in candidate_names:
        logger.info(f"Evaluating {model_name}...")
        fold_macro_f1s = []
        fold_min_recalls = []

        for fold_idx, (tr_idx, val_idx) in enumerate(skf.split(X_cv, y_cv)):
            clf = get_classifier(model_name, random_state=42)
            clf.fit(X_cv[tr_idx], y_cv[tr_idx])
            preds = clf.predict(X_cv[val_idx])

            m = compute_all_metrics(y_cv[val_idx], preds)
            fold_macro_f1s.append(m["macro_f1"])
            fold_min_recalls.append(m["minimum_per_class_recall"])

        # Train on full training partition for profiling
        final_clf = get_classifier(model_name, random_state=42)
        t_fit_start = time.perf_counter()
        final_clf.fit(X_train_sel, y_train)
        fit_time_sec = time.perf_counter() - t_fit_start

        # Validate on holdout validation set
        val_preds = final_clf.predict(X_val_sel)
        val_probas = final_clf.predict_proba(X_val_sel) if hasattr(final_clf, "predict_proba") else None
        val_metrics = compute_all_metrics(y_val, val_preds, val_probas)

        # Profile deployment characteristics
        profiler = DeploymentProfiler(final_clf)
        size_mb = profiler.measure_model_size_mb()
        lat_metrics = profiler.benchmark_latency(X_val_sel, test_samples=500)
        res_metrics = profiler.measure_resource_utilization(X_val_sel, duration_seconds=1.5)

        # Deployment score
        dep_score = compute_deployment_score(
            macro_f1=val_metrics["macro_f1"],
            min_recall=val_metrics["minimum_per_class_recall"],
            latency_p95_ms=lat_metrics["single_latency_p95_ms"],
            model_size_mb=size_mb,
            ram_mb=res_metrics["ram_rss_mb"],
        )

        record = {
            "model": model_name,
            "cv_macro_f1_mean": round(float(np.mean(fold_macro_f1s)), 4),
            "cv_macro_f1_std": round(float(np.std(fold_macro_f1s)), 4),
            "val_accuracy": val_metrics["accuracy"],
            "val_macro_f1": val_metrics["macro_f1"],
            "val_weighted_f1": val_metrics["weighted_f1"],
            "val_min_recall": val_metrics["minimum_per_class_recall"],
            "val_benign_fpr": val_metrics["benign_fpr"],
            "fit_time_sec": round(fit_time_sec, 2),
            "model_size_mb": size_mb,
            "p50_latency_ms": lat_metrics["single_latency_p50_ms"],
            "p95_latency_ms": lat_metrics["single_latency_p95_ms"],
            "throughput_flows_sec": lat_metrics["batch_throughput_flows_sec"],
            "ram_rss_mb": res_metrics["ram_rss_mb"],
            "cpu_percent": res_metrics["sustained_cpu_percent"],
            "deployment_score": dep_score,
        }
        model_benchmarks.append(record)
        trained_models[model_name] = final_clf
        logger.info(
            f"[{model_name}] Val Macro-F1: {val_metrics['macro_f1']:.4f}, "
            f"P95 Latency: {lat_metrics['single_latency_p95_ms']:.3f}ms, "
            f"Size: {size_mb:.2f}MB, Score: {dep_score:.1f}"
        )

    # Save model benchmark table
    bench_df = pd.DataFrame(model_benchmarks).sort_values(by="deployment_score", ascending=False)
    bench_csv_path = os.path.join(tables_dir, "model_benchmark_comparison.csv")
    bench_df.to_csv(bench_csv_path, index=False)
    logger.info(f"Saved candidate models comparison to {bench_csv_path}")

    # Designate champion
    champion_name = bench_df.iloc[0]["model"]
    champion_clf = trained_models[champion_name]
    logger.info(f"CHAMPION MODEL SELECTED: '{champion_name}' with Deployment Score: {bench_df.iloc[0]['deployment_score']}")

    # === PHASE 7: BASELINE COMPARISONS ===
    logger.info("=== PHASE 7: EVALUATING BASELINES ===")
    baselines_records = []

    # Baseline A: Full-Feature Multi-Class (44 features with champion algorithm)
    logger.info("Evaluating Baseline A: Full-Feature Multi-Class...")
    clf_base_a = get_classifier(champion_name, random_state=42)
    clf_base_a.fit(X_train_full, y_train)
    preds_a = clf_base_a.predict(X_val_full)
    m_a = compute_all_metrics(y_val, preds_a)
    prof_a = DeploymentProfiler(clf_base_a)
    lat_a = prof_a.benchmark_latency(X_val_full, test_samples=500)
    baselines_records.append({
        "baseline": "Baseline A (Full-Feature 44-Features)",
        "features": 44,
        "macro_f1": m_a["macro_f1"],
        "min_recall": m_a["minimum_per_class_recall"],
        "p95_latency_ms": lat_a["single_latency_p95_ms"],
        "model_size_mb": prof_a.measure_model_size_mb(),
    })

    # Baseline B: Reduced-Feature Multi-Class (15 features with champion algorithm)
    logger.info("Evaluating Baseline B: Reduced-Feature Multi-Class...")
    baselines_records.append({
        "baseline": "Baseline B (Reduced-Feature 15-Features)",
        "features": 15,
        "macro_f1": bench_df.loc[bench_df['model'] == champion_name, 'val_macro_f1'].values[0],
        "min_recall": bench_df.loc[bench_df['model'] == champion_name, 'val_min_recall'].values[0],
        "p95_latency_ms": bench_df.loc[bench_df['model'] == champion_name, 'p95_latency_ms'].values[0],
        "model_size_mb": bench_df.loc[bench_df['model'] == champion_name, 'model_size_mb'].values[0],
    })

    # Baseline C: Binary Benign vs Reconnaissance
    logger.info("Evaluating Baseline C: Binary Benign vs. Recon...")
    y_train_bin = np.where(y_train == 0, 0, 1)
    y_val_bin = np.where(y_val == 0, 0, 1)
    clf_base_c = get_classifier(champion_name, random_state=42)
    clf_base_c.fit(X_train_sel, y_train_bin)
    preds_c = clf_base_c.predict(X_val_sel)
    m_c = compute_all_metrics(y_val_bin, preds_c, class_names=["Benign", "Reconnaissance"])
    prof_c = DeploymentProfiler(clf_base_c)
    lat_c = prof_c.benchmark_latency(X_val_sel, test_samples=500)
    baselines_records.append({
        "baseline": "Baseline C (Binary Benign vs Recon)",
        "features": 15,
        "macro_f1": m_c["macro_f1"],
        "min_recall": m_c["minimum_per_class_recall"],
        "p95_latency_ms": lat_c["single_latency_p95_ms"],
        "model_size_mb": prof_c.measure_model_size_mb(),
    })

    # Baseline D: Hierarchical Classification
    logger.info("Evaluating Baseline D: Hierarchical Two-Stage...")
    st1 = get_classifier("decision_tree", max_depth=10, random_state=42)
    st2 = get_classifier(champion_name, random_state=42)
    clf_base_d = HierarchicalReconClassifier(st1, st2)
    clf_base_d.fit(X_train_sel, y_train)
    preds_d = clf_base_d.predict(X_val_sel)
    m_d = compute_all_metrics(y_val, preds_d)
    prof_d = DeploymentProfiler(clf_base_d)
    lat_d = prof_d.benchmark_latency(X_val_sel, test_samples=500)
    baselines_records.append({
        "baseline": "Baseline D (Hierarchical Two-Stage)",
        "features": 15,
        "macro_f1": m_d["macro_f1"],
        "min_recall": m_d["minimum_per_class_recall"],
        "p95_latency_ms": lat_d["single_latency_p95_ms"],
        "model_size_mb": prof_d.measure_model_size_mb(),
    })

    baselines_df = pd.DataFrame(baselines_records)
    baselines_path = os.path.join(tables_dir, "baselines_comparison.csv")
    baselines_df.to_csv(baselines_path, index=False)
    logger.info(f"Saved Baselines comparison to {baselines_path}")

    # === FINAL TEST EVALUATION OF CHAMPION MODEL ===
    logger.info("=== FINAL EVALUATION ON UNTOUCHED TEST SET ===")
    test_preds = champion_clf.predict(X_test_sel)
    test_probas = champion_clf.predict_proba(X_test_sel) if hasattr(champion_clf, "predict_proba") else None
    test_metrics = compute_all_metrics(y_test, test_preds, test_probas)

    logger.info(f"FINAL TEST MACRO-F1: {test_metrics['macro_f1']:.4f}")
    logger.info(f"FINAL TEST ACCURACY: {test_metrics['accuracy']:.4f}")
    logger.info(f"FINAL TEST BENIGN FPR: {test_metrics['benign_fpr']:.4%}")

    # Save test metrics JSON
    final_test_path = os.path.join(tables_dir, "final_test_report.json")
    with open(final_test_path, "w", encoding="utf-8") as f:
        json.dump(test_metrics, f, indent=2)
    logger.info(f"Saved final test report to {final_test_path}")

    # Plot Confusion Matrix
    cm = np.array(test_metrics["confusion_matrix"])
    cm_fig_path = os.path.join(figures_dir, "confusion_matrix.png")
    plot_confusion_matrix_heatmap(
        cm,
        output_png_path=cm_fig_path,
        title=f"CICIoMT2024 Test Confusion Matrix ({champion_name.upper()} 15-Features)",
    )

    # Package complete deployment pipeline
    logger.info("Packaging CompleteInferencePipeline artifact...")
    pipeline = CompleteInferencePipeline(
        preprocessor=preprocessor,
        selected_features=selected_features,
        model=champion_clf,
    )
    pipeline_save_path = os.path.join(models_dir, "champion_pipeline.joblib")
    joblib.dump(pipeline, pipeline_save_path, compress=3)
    logger.info(f"Saved deployable champion pipeline to {pipeline_save_path}")

    logger.info("Training and evaluation pipeline completed successfully.")


if __name__ == "__main__":
    main()
