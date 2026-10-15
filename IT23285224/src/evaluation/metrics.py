"""
Evaluation Metrics and Statistical Analysis for Reconnaissance IDS.
Calculates Macro-F1, per-class metrics, Benign False Positive Rate, and Confusion Matrices.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    brier_score_loss,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from src.data.schema import TARGET_CLASSES

logger = logging.getLogger(__name__)


def compute_all_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: Optional[np.ndarray] = None,
    class_names: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Computes a comprehensive dictionary of academic classification metrics.
    """
    names = class_names or TARGET_CLASSES

    acc = float(accuracy_score(y_true, y_pred))
    macro_prec = float(precision_score(y_true, y_pred, average="macro", zero_division=0))
    macro_rec = float(recall_score(y_true, y_pred, average="macro", zero_division=0))
    macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))

    weighted_f1 = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))

    # Per-class scores
    per_cls_prec = precision_score(y_true, y_pred, average=None, zero_division=0)
    per_cls_rec = recall_score(y_true, y_pred, average=None, zero_division=0)
    per_cls_f1 = f1_score(y_true, y_pred, average=None, zero_division=0)

    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred, labels=list(range(len(names))))

    # False Positive Rate on Benign (Class 0)
    # FPR = FP / (FP + TN) where negative class is Benign (0)
    tn = cm[1:, 1:].sum()
    fp = cm[0, 1:].sum()  # Benign predicted as Attack
    fn = cm[1:, 0].sum()  # Attack predicted as Benign
    tp = cm[1:, 1:].sum()

    benign_fpr = float(fp / (fp + cm[0, 0])) if (fp + cm[0, 0]) > 0 else 0.0

    per_class_dict = {}
    for idx, cname in enumerate(names):
        per_class_dict[cname] = {
            "precision": round(float(per_cls_prec[idx]), 4),
            "recall": round(float(per_cls_rec[idx]), 4),
            "f1_score": round(float(per_cls_f1[idx]), 4),
            "support": int((y_true == idx).sum()),
        }

    metrics: Dict[str, Any] = {
        "accuracy": round(acc, 4),
        "macro_precision": round(macro_prec, 4),
        "macro_recall": round(macro_rec, 4),
        "macro_f1": round(macro_f1, 4),
        "weighted_f1": round(weighted_f1, 4),
        "benign_fpr": round(benign_fpr, 4),
        "minimum_per_class_recall": round(float(np.min(per_cls_rec)), 4),
        "per_class": per_class_dict,
        "confusion_matrix": cm.tolist(),
    }

    # Probability calibration check
    if y_proba is not None and y_proba.shape[1] == len(names):
        # Multi-class Brier score
        brier_scores = []
        for idx in range(len(names)):
            y_bin = (y_true == idx).astype(int)
            brier_scores.append(brier_score_loss(y_bin, y_proba[:, idx]))
        metrics["mean_brier_score"] = round(float(np.mean(brier_scores)), 4)

    return metrics


def plot_confusion_matrix_heatmap(
    cm: np.ndarray,
    output_png_path: str,
    class_names: Optional[List[str]] = None,
    normalize: bool = True,
    title: str = "Reconnaissance Attack Confusion Matrix",
) -> None:
    """Generate and save publication-quality confusion matrix heatmap."""
    names = class_names or TARGET_CLASSES
    plt.figure(figsize=(8, 6.5))
    sns.set_theme(style="white")

    if normalize:
        cm_norm = cm.astype("float") / cm.sum(axis=1)[:, np.newaxis]
        cm_norm = np.nan_to_num(cm_norm)
        ax = sns.heatmap(
            cm_norm,
            annot=True,
            fmt=".2%",
            cmap="Blues",
            xticklabels=names,
            yticklabels=names,
            cbar=True,
        )
    else:
        ax = sns.heatmap(
            cm,
            annot=True,
            fmt="d",
            cmap="Blues",
            xticklabels=names,
            yticklabels=names,
            cbar=True,
        )

    plt.title(title, fontsize=12, weight="bold", pad=12)
    plt.ylabel("True Flow Class", fontsize=11)
    plt.xlabel("Predicted Flow Class", fontsize=11)
    plt.xticks(rotation=30, ha="right")
    plt.yticks(rotation=0)
    plt.tight_layout()

    os.makedirs(os.path.dirname(output_png_path), exist_ok=True)
    plt.savefig(output_png_path, dpi=300)
    plt.close()
    logger.info(f"Saved confusion matrix figure to {output_png_path}")
