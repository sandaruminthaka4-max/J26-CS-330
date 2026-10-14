"""
Deployable Complete Inference Pipeline Object.
Encapsulates Preprocessor, Selected Feature Column Subsetting, and Model Predictor.
"""

from typing import Any, Dict, List
import numpy as np
import pandas as pd

from src.data.schema import TARGET_CLASSES
from src.features.preprocessor import ReconFlowPreprocessor


class CompleteInferencePipeline:
    """
    Production inference container bundling preprocessor, selected feature indices, and trained classifier.
    """

    def __init__(self, preprocessor: ReconFlowPreprocessor, selected_features: List[str], model: Any):
        self.preprocessor = preprocessor
        self.selected_features = selected_features
        self.active_features = preprocessor.active_features_
        self.feature_indices = [self.active_features.index(f) for f in selected_features]
        self.model = model
        self.classes_ = model.classes_ if hasattr(model, "classes_") else np.array(range(len(TARGET_CLASSES)))

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
            preds = self.model.predict(X_selected)
            probas = np.zeros((len(preds), len(TARGET_CLASSES)), dtype=np.float64)
            for i, p in enumerate(preds):
                probas[i, int(p)] = 1.0
            return probas
