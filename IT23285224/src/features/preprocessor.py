"""
Robust, Leakage-Free Preprocessor for Network Flow Features.
Ensures zero data leakage by computing all imputation statistics, infinite clamping bounds,
and scaling parameters strictly on training partitions.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import RobustScaler, StandardScaler

from src.data.schema import NUMERICAL_FEATURE_COLUMNS

logger = logging.getLogger(__name__)


class ReconFlowPreprocessor(BaseEstimator, TransformerMixin):
    """
    Scikit-Learn compatible transformer for CICIoMT2024 network flows.
    Handles:
    - Infinite values (replaces with feature-specific 99.9th percentile or max finite bound)
    - Missing / NaN values (median imputation)
    - Constant feature removal
    - Feature scaling (StandardScaler or RobustScaler)
    - Feature order consistency
    """

    def __init__(
        self,
        scaler_type: str = "standard",  # 'standard', 'robust', or 'none'
        drop_constant_features: bool = True,
        feature_columns: Optional[List[str]] = None,
    ):
        self.scaler_type = scaler_type
        self.drop_constant_features = drop_constant_features
        self.feature_columns = feature_columns or list(NUMERICAL_FEATURE_COLUMNS)

        # Fitted attributes
        self.is_fitted: bool = False
        self.constant_columns_: List[str] = []
        self.active_features_: List[str] = []
        self.medians_: Dict[str, float] = {}
        self.finite_maxes_: Dict[str, float] = {}
        self.finite_mins_: Dict[str, float] = {}
        self.scaler_: Optional[Union[StandardScaler, RobustScaler]] = None

    def fit(self, X: Union[pd.DataFrame, np.ndarray], y: Optional[Any] = None) -> "ReconFlowPreprocessor":
        if isinstance(X, np.ndarray):
            df = pd.DataFrame(X, columns=self.feature_columns[: X.shape[1]])
        else:
            df = X.copy()

        # Ensure numeric conversion
        numeric_cols = [c for c in self.feature_columns if c in df.columns]

        self.constant_columns_ = []
        self.medians_ = {}
        self.finite_maxes_ = {}
        self.finite_mins_ = {}

        cleaned_data: Dict[str, np.ndarray] = {}

        for col in numeric_cols:
            series = pd.to_numeric(df[col], errors="coerce").to_numpy(dtype=np.float64)

            # Determine finite bounds
            finite_mask = np.isfinite(series)
            if np.any(finite_mask):
                f_min = float(np.min(series[finite_mask]))
                f_max = float(np.max(series[finite_mask]))
                med = float(np.median(series[finite_mask]))
            else:
                f_min = 0.0
                f_max = 0.0
                med = 0.0

            self.finite_mins_[col] = f_min
            self.finite_maxes_[col] = f_max
            self.medians_[col] = med

            # Temporarily clean to test variance
            clean_series = np.where(np.isposinf(series), f_max, series)
            clean_series = np.where(np.isneginf(clean_series), f_min, clean_series)
            clean_series = np.where(np.isnan(clean_series), med, clean_series)

            # Check zero variance
            if self.drop_constant_features and np.std(clean_series) < 1e-12:
                self.constant_columns_.append(col)
            else:
                cleaned_data[col] = clean_series

        self.active_features_ = [c for c in numeric_cols if c not in self.constant_columns_]
        logger.info(
            f"Preprocessor fit: {len(numeric_cols)} input features, "
            f"dropped {len(self.constant_columns_)} constant features, "
            f"{len(self.active_features_)} active features retained."
        )

        # Fit scaler on active features
        if self.scaler_type in ("standard", "robust") and self.active_features_:
            clean_matrix = np.column_stack([cleaned_data[col] for col in self.active_features_])
            if self.scaler_type == "standard":
                self.scaler_ = StandardScaler()
            else:
                self.scaler_ = RobustScaler()
            self.scaler_.fit(clean_matrix)
        else:
            self.scaler_ = None

        self.is_fitted = True
        return self

    def transform(self, X: Union[pd.DataFrame, np.ndarray, Dict[str, Any]]) -> np.ndarray:
        if not self.is_fitted:
            raise RuntimeError("ReconFlowPreprocessor must be fitted before calling transform().")

        if isinstance(X, dict):
            # Single instance dict
            df = pd.DataFrame([X])
        elif isinstance(X, np.ndarray):
            df = pd.DataFrame(X, columns=self.feature_columns[: X.shape[1]])
        else:
            df = X.copy()

        cleaned_cols = []
        for col in self.active_features_:
            if col in df.columns:
                series = pd.to_numeric(df[col], errors="coerce").to_numpy(dtype=np.float64)
            else:
                # Missing column in payload: impute median
                series = np.full(len(df), self.medians_.get(col, 0.0), dtype=np.float64)

            # Replace +inf with finite max, -inf with finite min, NaN with median
            series = np.where(np.isposinf(series), self.finite_maxes_.get(col, 0.0), series)
            series = np.where(np.isneginf(series), self.finite_mins_.get(col, 0.0), series)
            series = np.where(np.isnan(series), self.medians_.get(col, 0.0), series)
            cleaned_cols.append(series)

        if not cleaned_cols:
            return np.empty((len(df), 0), dtype=np.float64)

        matrix = np.column_stack(cleaned_cols)

        if self.scaler_ is not None:
            matrix = self.scaler_.transform(matrix)

        return matrix

    def save(self, filepath: str) -> None:
        """Persist fitted preprocessor object."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(self, filepath)
        logger.info(f"Preprocessor saved to {filepath}")

    @classmethod
    def load(cls, filepath: str) -> "ReconFlowPreprocessor":
        """Load persisted preprocessor object."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Preprocessor file not found at {filepath}")
        return joblib.load(filepath)
