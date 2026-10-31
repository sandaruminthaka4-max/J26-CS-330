"""
evaluator.py — Research-grade model evaluation, metric computation, and visualization
Project: J26-CS-330 | Component: DoS Detection via SDN Flow Analysis
"""

import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import matplotlib
matplotlib.use("Agg")  # Non-interactive headless backend
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_curve,
    auc,
)

logger = logging.getLogger(__name__)


def compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: Optional[np.ndarray] = None,
    model_name: str = "Model",
) -> Dict[str, Union[float, list, str]]:
    """
    Compute comprehensive classification metrics including FPR and FNR.
    """
    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))

    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()

    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    roc_auc_val = None
    if y_prob is not None:
        try:
            fpr_arr, tpr_arr, _ = roc_curve(y_true, y_prob)
            roc_auc_val = float(auc(fpr_arr, tpr_arr))
        except Exception as e:
            logger.warning(f"Could not compute ROC-AUC: {e}")

    return {
        "model_name": model_name,
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "fpr": fpr,
        "fnr": fnr,
        "roc_auc": roc_auc_val,
        "confusion_matrix": cm.tolist(),
        "tp": int(tp),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
    }


def plot_confusion_matrix(
    cm: Union[np.ndarray, list],
    model_name: str,
    save_path: Union[str, Path],
) -> None:
    """
    Render and save a high-resolution confusion matrix heatmap.
    """
    cm = np.array(cm)
    save_path = Path(save_path)
    save_path.parent.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(6, 5))
    im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    ax.figure.colorbar(im, ax=ax)

    classes = ["Normal (0)", "DoS (1)"]
    tick_marks = np.arange(len(classes))
    ax.set_xticks(tick_marks)
    ax.set_xticklabels(classes, fontsize=10)
    ax.set_yticks(tick_marks)
    ax.set_yticklabels(classes, fontsize=10)

    # Annotate numbers
    thresh = cm.max() / 2.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(
                j, i, f"{cm[i, j]:,}",
                ha="center", va="center",
                color="white" if cm[i, j] > thresh else "black",
                fontweight="bold"
            )

    ax.set_ylabel("True Class", fontsize=11, fontweight="bold")
    ax.set_xlabel("Predicted Class", fontsize=11, fontweight="bold")
    ax.set_title(f"Confusion Matrix — {model_name}", fontsize=12, fontweight="bold", pad=12)
    plt.tight_layout()
    plt.savefig(save_path, dpi=300)
    plt.close(fig)
    logger.info(f"Saved confusion matrix plot to: {save_path}")


def plot_roc_curve(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    model_name: str,
    save_path: Union[str, Path],
) -> None:
    """
    Plot and save ROC curve.
    """
    save_path = Path(save_path)
    save_path.parent.mkdir(parents=True, exist_ok=True)

    fpr, tpr, _ = roc_curve(y_true, y_prob)
    roc_auc = auc(fpr, tpr)

    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot(fpr, tpr, color="darkorange", lw=2, label=f"ROC curve (AUC = {roc_auc:.4f})")
    ax.plot([0, 1], [0, 1], color="navy", lw=1.5, linestyle="--", label="Random Chance")
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])
    ax.set_xlabel("False Positive Rate (FPR)", fontsize=11, fontweight="bold")
    ax.set_ylabel("True Positive Rate (Recall)", fontsize=11, fontweight="bold")
    ax.set_title(f"ROC Curve — {model_name}", fontsize=12, fontweight="bold", pad=12)
    ax.legend(loc="lower right")
    ax.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(save_path, dpi=300)
    plt.close(fig)
    logger.info(f"Saved ROC curve to: {save_path}")


def measure_inference_latency(
    model: object,
    X_sample: np.ndarray,
    n_repeats: int = 1000,
) -> Dict[str, Union[float, list]]:
    """
    Measure single-row prediction inference latency (isolated from data loading).
    """
    n_samples = len(X_sample)
    if n_samples == 0:
        return {"median_ms": 0.0, "mean_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0}

    # Warm-up run
    for i in range(min(10, n_samples)):
        _ = model.predict(X_sample[i:i+1])

    latencies_ms = []
    indices = np.random.choice(n_samples, size=n_repeats, replace=True)
    for idx in indices:
        row = X_sample[idx:idx+1]
        t0 = time.perf_counter()
        _ = model.predict(row)
        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000.0)

    latencies_arr = np.array(latencies_ms)
    return {
        "median_ms": float(np.median(latencies_arr)),
        "mean_ms": float(np.mean(latencies_arr)),
        "p95_ms": float(np.percentile(latencies_arr, 95)),
        "p99_ms": float(np.percentile(latencies_arr, 99)),
        "min_ms": float(np.min(latencies_arr)),
        "max_ms": float(np.max(latencies_arr)),
        "n_repeats": n_repeats,
        "all_latencies_ms": latencies_ms,
    }


def plot_latency_histogram(
    latencies_ms: List[float],
    model_name: str,
    save_path: Union[str, Path],
) -> None:
    """
    Save histogram of inference latencies.
    """
    save_path = Path(save_path)
    save_path.parent.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.hist(latencies_ms, bins=40, color="teal", edgecolor="black", alpha=0.7)
    median_val = np.median(latencies_ms)
    ax.axvline(median_val, color="red", linestyle="dashed", linewidth=2, label=f"Median: {median_val:.2f} ms")
    ax.axvline(50.0, color="black", linestyle="dotted", linewidth=2, label="Proposal Target (50 ms)")
    ax.set_xlabel("Inference Latency (ms)", fontsize=11, fontweight="bold")
    ax.set_ylabel("Frequency", fontsize=11, fontweight="bold")
    ax.set_title(f"Inference Latency Distribution — {model_name}", fontsize=11, fontweight="bold")
    ax.legend()
    plt.tight_layout()
    plt.savefig(save_path, dpi=300)
    plt.close(fig)


def compare_models(
    results_list: List[Dict],
    save_path: Union[str, Path],
) -> pd.DataFrame:
    """
    Generate comparison table (CSV) and bar chart across tested models.
    """
    save_path = Path(save_path)
    csv_path = save_path.with_suffix(".csv")
    chart_path = save_path.with_suffix(".png")

    records = []
    for r in results_list:
        rec = {
            "Model": r["model_name"],
            "Accuracy": round(r["accuracy"] * 100, 2),
            "Precision": round(r["precision"] * 100, 2),
            "Recall": round(r["recall"] * 100, 2),
            "F1-Score": round(r["f1"] * 100, 2),
            "FPR (%)": round(r["fpr"] * 100, 2),
            "FNR (%)": round(r["fnr"] * 100, 2),
            "ROC-AUC": round(r["roc_auc"], 4) if r.get("roc_auc") else "N/A",
        }
        if "latency" in r:
            rec["Median Latency (ms)"] = round(r["latency"]["median_ms"], 3)
            rec["P95 Latency (ms)"] = round(r["latency"]["p95_ms"], 3)
        records.append(rec)

    df_comp = pd.DataFrame(records)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    df_comp.to_csv(csv_path, index=False)
    logger.info(f"Saved model comparison table to: {csv_path}")

    # Plot comparison bar chart
    fig, ax = plt.subplots(figsize=(9, 5))
    metrics = ["Accuracy", "Precision", "Recall", "F1-Score"]
    x = np.arange(len(df_comp))
    width = 0.2

    for i, m in enumerate(metrics):
        vals = [float(v) for v in df_comp[m]]
        ax.bar(x + (i - 1.5) * width, vals, width, label=m)

    ax.set_ylabel("Score (%)", fontsize=11, fontweight="bold")
    ax.set_title("Comparative Evaluation Across Models (J26-CS-330)", fontsize=12, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(df_comp["Model"], fontsize=10, fontweight="bold")
    ax.axhline(95.0, color="red", linestyle="--", alpha=0.7, label="95% Target")
    ax.set_ylim([0, 105])
    ax.legend(loc="lower right")
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(chart_path, dpi=300)
    plt.close(fig)
    logger.info(f"Saved comparison bar chart to: {chart_path}")

    return df_comp
