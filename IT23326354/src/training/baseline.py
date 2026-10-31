"""
baseline.py — Benchmark baseline models for comparison against XGBoost
Project: J26-CS-330 | Component: DoS Detection via SDN Flow Analysis
"""

import logging
from typing import Dict, List, Union
import numpy as np
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

logger = logging.getLogger(__name__)


def train_decision_tree(
    X_train: np.ndarray,
    y_train: np.ndarray,
    random_seed: int = 42,
    max_depth: int = 10,
) -> DecisionTreeClassifier:
    """
    Train a standard Decision Tree baseline.
    """
    logger.info(f"Training Decision Tree baseline (max_depth={max_depth})...")
    clf = DecisionTreeClassifier(max_depth=max_depth, random_state=random_seed)
    clf.fit(X_train, y_train)
    return clf


def train_random_forest(
    X_train: np.ndarray,
    y_train: np.ndarray,
    random_seed: int = 42,
    n_estimators: int = 100,
    max_depth: int = 12,
) -> RandomForestClassifier:
    """
    Train an ensemble Random Forest baseline.
    """
    logger.info(f"Training Random Forest baseline (n_estimators={n_estimators}, max_depth={max_depth})...")
    clf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        random_state=random_seed,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)
    return clf


def threshold_baseline(
    X: np.ndarray,
    feature_names: List[str],
    threshold_feature: str = "Rate",
    threshold: float = 10000.0,
) -> np.ndarray:
    """
    Traditional rule-based / threshold baseline:
    If flow Rate exceeds fixed threshold -> classify as DoS (1), else Normal (0).
    """
    if threshold_feature not in feature_names:
        logger.warning(f"Feature '{threshold_feature}' not found. Defaulting to all zeros.")
        return np.zeros(len(X), dtype=int)
    
    idx = feature_names.index(threshold_feature)
    vals = X[:, idx]
    preds = (vals > threshold).astype(int)
    return preds


def evaluate_baseline(
    model_or_preds: Union[object, np.ndarray],
    X_test: np.ndarray,
    y_test: np.ndarray,
    model_name: str,
) -> Dict[str, float]:
    """
    Evaluate baseline predictions or model object on test set.
    """
    if isinstance(model_or_preds, np.ndarray):
        y_pred = model_or_preds
        y_prob = None
    else:
        y_pred = model_or_preds.predict(X_test)
        y_prob = model_or_preds.predict_proba(X_test)[:, 1] if hasattr(model_or_preds, "predict_proba") else None

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    roc_auc = float(roc_auc_score(y_test, y_prob)) if y_prob is not None else None

    logger.info(f"[{model_name}] Acc: {acc:.4f} | Prec: {prec:.4f} | Rec: {rec:.4f} | F1: {f1:.4f}")
    return {
        "model_name": model_name,
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "roc_auc": roc_auc,
    }
