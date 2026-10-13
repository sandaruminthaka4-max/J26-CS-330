"""
Baseline Implementations:
- Baseline A: Full-Feature Multi-Class Classification (44 active features)
- Baseline B: Reduced-Feature Multi-Class Classification (15 selected features)
- Baseline C: Binary Benign vs. Reconnaissance Classification
- Baseline D: Hierarchical Two-Stage Classification (Stage 1: Binary, Stage 2: Recon Subtypes)
"""

import copy
import logging
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.metrics import f1_score

from src.data.schema import CANONICAL_TO_BINARY_MAP, TARGET_CLASSES

logger = logging.getLogger(__name__)


class HierarchicalReconClassifier(BaseEstimator, ClassifierMixin):
    """
    Two-Stage Hierarchical Classifier:
    - Stage 1: Distinguishes Benign (class 0) from Reconnaissance (classes 1, 2, 3, 4).
    - Stage 2: Distinguishes among the 4 reconnaissance attack vectors:
               Ping Sweep (1), Port Scan (2), OS Scan (3), Vulnerability Scan (4).
    """

    def __init__(self, stage1_estimator: Any, stage2_estimator: Any):
        self.stage1_estimator = stage1_estimator
        self.stage2_estimator = stage2_estimator
        self.stage1_model_: Optional[Any] = None
        self.stage2_model_: Optional[Any] = None
        self.classes_ = np.array([0, 1, 2, 3, 4])

    def fit(self, X: np.ndarray, y: np.ndarray) -> "HierarchicalReconClassifier":
        # Stage 1: Binary labels (0 = Benign, 1 = Any Recon)
        y_binary = np.where(y == 0, 0, 1)
        logger.info("Training Stage 1 (Binary Benign vs Recon)...")
        self.stage1_model_ = copy.deepcopy(self.stage1_estimator)
        self.stage1_model_.fit(X, y_binary)

        # Stage 2: Filter to Recon flows only (y > 0)
        recon_mask = y > 0
        if np.any(recon_mask):
            X_recon = X[recon_mask]
            # Map classes 1..4 to 0..3 for stage 2
            y_recon = y[recon_mask] - 1
            logger.info(f"Training Stage 2 (4 Recon Subtypes on {len(X_recon)} samples)...")
            self.stage2_model_ = copy.deepcopy(self.stage2_estimator)
            self.stage2_model_.fit(X_recon, y_recon)
        else:
            raise ValueError("No reconnaissance samples found to train Stage 2.")

        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        # P(Benign) from Stage 1
        p_stage1 = self.stage1_model_.predict_proba(X)  # shape (N, 2): [P(Benign), P(Recon)]
        p_benign = p_stage1[:, 0]
        p_recon = p_stage1[:, 1]

        # Stage 2 conditional probabilities P(Subtype | Recon)
        p_subtypes = self.stage2_model_.predict_proba(X)  # shape (N, 4)

        # Joint probabilities:
        # P(class 0) = P(Benign)
        # P(class k) = P(Recon) * P(Subtype k | Recon)
        p_full = np.zeros((len(X), 5), dtype=np.float64)
        p_full[:, 0] = p_benign
        for k in range(4):
            p_full[:, k + 1] = p_recon * p_subtypes[:, k]

        # Normalize rows to sum to 1.0
        row_sums = p_full.sum(axis=1, keepdims=True)
        row_sums[row_sums == 0] = 1.0
        p_full = p_full / row_sums
        return p_full

    def predict(self, X: np.ndarray) -> np.ndarray:
        probas = self.predict_proba(X)
        return np.argmax(probas, axis=1)
