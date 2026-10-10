"""
Classifier Implementations and Factory for Multi-Class Reconnaissance Detection.
Wraps Decision Tree, Logistic Regression, Linear SVM, Random Forest, XGBoost, and LightGBM.
"""

import logging
from typing import Any, Dict, Optional, Union

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeClassifier
import lightgbm as lgb
import xgboost as xgb

logger = logging.getLogger(__name__)


def get_classifier(
    model_name: str,
    random_state: int = 42,
    class_weight: Optional[Union[str, Dict]] = "balanced",
    calibrate_svm: bool = True,
    **kwargs,
) -> Any:
    """
    Factory function returning instantiated, configured classifier instances.
    """
    name = model_name.lower().replace("-", "_").replace(" ", "_")

    if name in ("decision_tree", "dt"):
        return DecisionTreeClassifier(
            criterion="gini",
            max_depth=kwargs.get("max_depth", 15),
            min_samples_split=kwargs.get("min_samples_split", 10),
            min_samples_leaf=kwargs.get("min_samples_leaf", 5),
            class_weight=class_weight,
            random_state=random_state,
        )

    elif name in ("logistic_regression", "lr"):
        return LogisticRegression(
            penalty="l2",
            C=kwargs.get("C", 1.0),
            max_iter=kwargs.get("max_iter", 1000),
            class_weight=class_weight,
            random_state=random_state,
            solver="lbfgs",
            n_jobs=-1,
        )

    elif name in ("linear_svm", "svm", "linear_svc"):
        base_svm = LinearSVC(
            C=kwargs.get("C", 1.0),
            max_iter=kwargs.get("max_iter", 2000),
            class_weight=class_weight,
            random_state=random_state,
            dual="auto",
        )
        if calibrate_svm:
            # Wrap LinearSVC with Platt scaling to output well-calibrated probabilities
            return CalibratedClassifierCV(estimator=base_svm, cv=3, method="sigmoid")
        return base_svm

    elif name in ("random_forest", "rf"):
        return RandomForestClassifier(
            n_estimators=kwargs.get("n_estimators", 100),
            max_depth=kwargs.get("max_depth", 16),
            min_samples_split=kwargs.get("min_samples_split", 10),
            min_samples_leaf=kwargs.get("min_samples_leaf", 4),
            class_weight=class_weight,
            random_state=random_state,
            n_jobs=-1,
        )

    elif name in ("xgboost", "xgb"):
        # XGBoost multi:softprob for calibrated probabilities
        return xgb.XGBClassifier(
            n_estimators=kwargs.get("n_estimators", 100),
            max_depth=kwargs.get("max_depth", 8),
            learning_rate=kwargs.get("learning_rate", 0.1),
            subsample=kwargs.get("subsample", 0.8),
            colsample_bytree=kwargs.get("colsample_bytree", 0.8),
            random_state=random_state,
            tree_method="hist",
            eval_metric="mlogloss",
            n_jobs=-1,
        )

    elif name in ("lightgbm", "lgbm"):
        return lgb.LGBMClassifier(
            n_estimators=kwargs.get("n_estimators", 100),
            max_depth=kwargs.get("max_depth", 10),
            num_leaves=kwargs.get("num_leaves", 31),
            learning_rate=kwargs.get("learning_rate", 0.1),
            class_weight=class_weight,
            random_state=random_state,
            n_jobs=-1,
            verbose=-1,
        )

    else:
        raise ValueError(
            f"Unsupported model: '{model_name}'. Choose from: "
            "['decision_tree', 'logistic_regression', 'linear_svm', 'random_forest', 'xgboost', 'lightgbm']"
        )
