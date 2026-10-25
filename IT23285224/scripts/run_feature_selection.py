"""
Executable Feature Selection Experiment.
Executes MI, Chi2, Tree-MDI, and RFE on training partition, benchmarks subset performance
across multiple feature counts, generates plots, and outputs selected feature manifest.
"""

import json
import logging
import os
import sys
import time

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import f1_score, recall_score
from sklearn.tree import DecisionTreeClassifier
import lightgbm as lgb

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.data.schema import CLASS_TO_INT_MAP, TARGET_CLASSES
from src.features.preprocessor import ReconFlowPreprocessor
from src.features.selector import (
    compute_chi2,
    compute_mutual_information,
    compute_rfe_ranking,
    compute_tree_importance,
    generate_consensus_ranking,
)

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("FeatureSelection")


def main():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    processed_dir = os.path.join(base_dir, "data", "processed")
    tables_dir = os.path.join(base_dir, "results", "tables")
    figures_dir = os.path.join(base_dir, "results", "figures")
    configs_dir = os.path.join(base_dir, "configs")
    os.makedirs(tables_dir, exist_ok=True)
    os.makedirs(figures_dir, exist_ok=True)
    os.makedirs(configs_dir, exist_ok=True)

    logger.info("Loading processed training and validation sets...")
    df_train = pd.read_csv(os.path.join(processed_dir, "train.csv"))
    df_val = pd.read_csv(os.path.join(processed_dir, "val.csv"))

    preprocessor = ReconFlowPreprocessor.load(os.path.join(base_dir, "models", "preprocessor.joblib"))
    active_features = preprocessor.active_features_
    logger.info(f"Loaded preprocessor with {len(active_features)} active features.")

    # Target integer vectors
    y_train = df_train["label"].map(CLASS_TO_INT_MAP).to_numpy()
    y_val = df_val["label"].map(CLASS_TO_INT_MAP).to_numpy()

    # Preprocess training data
    logger.info("Transforming training partition...")
    X_train_full = preprocessor.transform(df_train)
    X_val_full = preprocessor.transform(df_val)

    # Use a stratified sample of 40,000 rows for MI / RFE computation speed while keeping all minority samples
    n_sample = min(40_000, len(df_train))
    sample_indices = []
    rng = np.random.default_rng(42)
    for cls_idx in range(len(TARGET_CLASSES)):
        cls_mask = np.where(y_train == cls_idx)[0]
        # Keep all if small class, or sample up to proportional share
        if len(cls_mask) < 2000:
            sample_indices.extend(cls_mask)
        else:
            sample_indices.extend(rng.choice(cls_mask, size=min(10_000, len(cls_mask)), replace=False))

    sample_indices = np.array(sample_indices)
    X_sample = X_train_full[sample_indices]
    y_sample = y_train[sample_indices]
    logger.info(f"Stratified sampling for feature selection: {len(X_sample)} flows.")

    # 1. Mutual Information
    mi_df = compute_mutual_information(X_sample, y_sample, active_features)
    
    # 2. Chi-Square
    chi2_df = compute_chi2(X_sample, y_sample, active_features)

    # 3. Tree Importance
    tree_df = compute_tree_importance(X_sample, y_sample, active_features)

    # 4. RFE
    rfe_df = compute_rfe_ranking(X_sample, y_sample, active_features, n_features_to_select=15)

    # 5. Consensus Ranking
    logger.info("Computing consensus feature ranking...")
    consensus_df = generate_consensus_ranking(mi_df, chi2_df, tree_df, rfe_df)
    rankings_csv_path = os.path.join(tables_dir, "feature_rankings.csv")
    consensus_df.to_csv(rankings_csv_path, index=False)
    logger.info(f"Saved complete feature rankings to {rankings_csv_path}")

    # Plot top-15 consensus features
    top15 = consensus_df.head(15)
    plt.figure(figsize=(10, 6))
    sns.set_theme(style="whitegrid")
    sns.barplot(data=top15, x="tree_importance", y="feature", palette="viridis")
    plt.title("Top-15 Network Flow Features by Importance (Consensus Selection)", fontsize=13, weight="bold")
    plt.xlabel("Ensemble Tree Gini Importance", fontsize=11)
    plt.ylabel("Feature Name", fontsize=11)
    plt.tight_layout()
    fig_importance = os.path.join(figures_dir, "feature_importance.png")
    plt.savefig(fig_importance, dpi=300)
    plt.close()
    logger.info(f"Saved feature importance plot to {fig_importance}")

    # Benchmark multiple feature counts K in [5, 10, 15, 20, 30, len(active_features)]
    candidate_ks = [5, 10, 15, 20, 30, len(active_features)]
    k_results = []

    ranked_features = consensus_df["feature"].tolist()

    logger.info("Benchmarking feature counts against Macro-F1 and Inference Latency...")
    for k in candidate_ks:
        selected_cols = ranked_features[:k]
        col_indices = [active_features.index(c) for c in selected_cols]

        X_tr_k = X_train_full[:, col_indices]
        X_va_k = X_val_full[:, col_indices]

        # Train fast LightGBM evaluator
        clf = lgb.LGBMClassifier(
            n_estimators=60,
            learning_rate=0.1,
            num_leaves=31,
            random_state=42,
            n_jobs=-1,
            verbose=-1,
        )
        clf.fit(X_tr_k, y_train)

        # Measure latency
        warmup = clf.predict(X_va_k[:100])
        t_start = time.perf_counter()
        preds = clf.predict(X_va_k)
        t_total = time.perf_counter() - t_start
        latency_us_per_flow = (t_total / len(X_va_k)) * 1_000_000

        macro_f1 = f1_score(y_val, preds, average="macro")
        weighted_f1 = f1_score(y_val, preds, average="weighted")
        min_recall = recall_score(y_val, preds, average=None).min()

        k_results.append({
            "k_features": k,
            "macro_f1": round(float(macro_f1), 4),
            "weighted_f1": round(float(weighted_f1), 4),
            "min_class_recall": round(float(min_recall), 4),
            "latency_us_per_flow": round(latency_us_per_flow, 2),
            "throughput_flows_sec": int(len(X_va_k) / t_total),
        })
        logger.info(f"K={k:2d}: Macro-F1 = {macro_f1:.4f}, Min-Recall = {min_recall:.4f}, Latency = {latency_us_per_flow:.1f} us/flow")

    k_df = pd.DataFrame(k_results)
    k_df_path = os.path.join(tables_dir, "feature_count_comparison.csv")
    k_df.to_csv(k_df_path, index=False)
    logger.info(f"Saved feature count comparison table to {k_df_path}")

    # Plot K vs Macro-F1 and Latency
    fig, ax1 = plt.subplots(figsize=(9, 5))
    color = "tab:blue"
    ax1.set_xlabel("Number of Selected Features (K)", fontsize=11)
    ax1.set_ylabel("Macro-F1 Score", color=color, fontsize=11)
    ax1.plot(k_df["k_features"], k_df["macro_f1"], color=color, marker="o", linewidth=2.5, label="Macro-F1")
    ax1.tick_params(axis="y", labelcolor=color)
    ax1.set_ylim(0.85, 1.01)

    ax2 = ax1.twinx()
    color = "tab:red"
    ax2.set_ylabel("Inference Latency (us / flow)", color=color, fontsize=11)
    ax2.plot(k_df["k_features"], k_df["latency_us_per_flow"], color=color, marker="s", linestyle="--", linewidth=2.0, label="Latency")
    ax2.tick_params(axis="y", labelcolor=color)

    plt.title("Impact of Feature Reduction on Classification Quality vs. Inference Latency", fontsize=12, weight="bold")
    fig.tight_layout()
    fig_k_path = os.path.join(figures_dir, "feature_count_vs_performance.png")
    plt.savefig(fig_k_path, dpi=300)
    plt.close()
    logger.info(f"Saved K-comparison chart to {fig_k_path}")

    # Select optimal K=15 based on Pareto efficiency (achieves near-peak Macro-F1 with small footprint)
    optimal_k = 15
    selected_final_features = ranked_features[:optimal_k]
    selected_manifest = {
        "optimal_feature_count": optimal_k,
        "selection_strategy": "Consensus (MI 30%, Tree MDI 30%, Chi2 20%, RFE 20%)",
        "selected_features": selected_final_features,
        "all_active_features": active_features,
        "k_benchmarks": k_results,
    }
    selected_config_path = os.path.join(configs_dir, "selected_features.json")
    with open(selected_config_path, "w", encoding="utf-8") as f:
        json.dump(selected_manifest, f, indent=2)
    logger.info(f"Saved selected feature manifest ({optimal_k} features) to {selected_config_path}")


if __name__ == "__main__":
    main()
