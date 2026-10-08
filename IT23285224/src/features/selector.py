"""
Feature Selection and Ranking Engine for Reconnaissance Attack Detection.
Implements Mutual Information, Chi-Square, Tree Importance, and RFE within training partitions.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.feature_selection import RFE, chi2, mutual_info_classif
from sklearn.metrics import f1_score
from sklearn.preprocessing import MinMaxScaler
from sklearn.tree import DecisionTreeClassifier

logger = logging.getLogger(__name__)


def compute_mutual_information(
    X: np.ndarray,
    y: np.ndarray,
    feature_names: List[str],
    random_state: int = 42,
) -> pd.DataFrame:
    """Compute Mutual Information scores between features and target labels."""
    logger.info("Computing Mutual Information scores...")
    mi_scores = mutual_info_classif(X, y, random_state=random_state)
    df = pd.DataFrame({"feature": feature_names, "mi_score": mi_scores})
    df = df.sort_values(by="mi_score", ascending=False).reset_index(drop=True)
    return df


def compute_chi2(
    X: np.ndarray,
    y: np.ndarray,
    feature_names: List[str],
) -> pd.DataFrame:
    """Compute Chi-Square statistics using non-negative MinMax scaling."""
    logger.info("Computing Chi-Square statistics on non-negative scaled inputs...")
    scaler = MinMaxScaler()
    X_pos = scaler.fit_transform(X)
    chi2_scores, p_values = chi2(X_pos, y)
    df = pd.DataFrame({
        "feature": feature_names,
        "chi2_score": chi2_scores,
        "p_value": p_values,
    })
    df = df.sort_values(by="chi2_score", ascending=False).reset_index(drop=True)
    return df


def compute_tree_importance(
    X: np.ndarray,
    y: np.ndarray,
    feature_names: List[str],
    random_state: int = 42,
) -> pd.DataFrame:
    """Compute Gini / MDI importance using an ensemble of randomized trees."""
    logger.info("Computing Tree Importance scores via ExtraTreesClassifier...")
    clf = ExtraTreesClassifier(
        n_estimators=100,
        max_depth=15,
        random_state=random_state,
        n_jobs=-1,
    )
    clf.fit(X, y)
    df = pd.DataFrame({"feature": feature_names, "tree_importance": clf.feature_importances_})
    df = df.sort_values(by="tree_importance", ascending=False).reset_index(drop=True)
    return df


def compute_rfe_ranking(
    X: np.ndarray,
    y: np.ndarray,
    feature_names: List[str],
    n_features_to_select: int = 15,
    random_state: int = 42,
) -> pd.DataFrame:
    """Compute feature rankings via Recursive Feature Elimination (RFE)."""
    logger.info(f"Computing RFE ranking targeting {n_features_to_select} features...")
    estimator = DecisionTreeClassifier(max_depth=12, random_state=random_state)
    rfe = RFE(estimator=estimator, n_features_to_select=n_features_to_select, step=2)
    rfe.fit(X, y)
    df = pd.DataFrame({
        "feature": feature_names,
        "rfe_ranking": rfe.ranking_,
        "rfe_selected": rfe.support_,
    })
    df = df.sort_values(by="rfe_ranking").reset_index(drop=True)
    return df


def generate_consensus_ranking(
    mi_df: pd.DataFrame,
    chi2_df: pd.DataFrame,
    tree_df: pd.DataFrame,
    rfe_df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Combines ranks from the 4 feature selection paradigms into a normalized consensus rank.
    """
    merged = mi_df.merge(chi2_df, on="feature").merge(tree_df, on="feature").merge(rfe_df, on="feature")

    # Lower rank number = better
    merged["rank_mi"] = merged["mi_score"].rank(ascending=False)
    merged["rank_chi2"] = merged["chi2_score"].rank(ascending=False)
    merged["rank_tree"] = merged["tree_importance"].rank(ascending=False)
    merged["rank_rfe"] = merged["rfe_ranking"].rank(ascending=True)

    merged["consensus_score"] = (
        0.30 * merged["rank_mi"]
        + 0.20 * merged["rank_chi2"]
        + 0.30 * merged["rank_tree"]
        + 0.20 * merged["rank_rfe"]
    )
    consensus_df = merged.sort_values(by="consensus_score", ascending=True).reset_index(drop=True)
    consensus_df["consensus_rank"] = range(1, len(consensus_df) + 1)
    return consensus_df
