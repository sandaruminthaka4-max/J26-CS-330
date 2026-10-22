"""
Unit Tests for Preprocessor, Infinite Clamping, and Leakage Prevention.
"""

import numpy as np
import pandas as pd
import pytest
from src.features.leakage import audit_for_leakage
from src.features.preprocessor import ReconFlowPreprocessor


def test_preprocessor_handles_nans_and_infs():
    cols = ["f1", "f2", "f3"]
    train_df = pd.DataFrame({
        "f1": [1.0, 2.0, np.nan, 4.0, 5.0],
        "f2": [10.0, np.inf, 30.0, -np.inf, 50.0],
        "f3": [7.0, 7.0, 7.0, 7.0, 7.0],  # Constant feature
    })

    prep = ReconFlowPreprocessor(
        scaler_type="standard",
        drop_constant_features=True,
        feature_columns=cols,
    )
    prep.fit(train_df)

    assert "f3" in prep.constant_columns_
    assert "f1" in prep.active_features_
    assert "f2" in prep.active_features_
    assert len(prep.active_features_) == 2

    # Transform test instance with extreme values
    test_df = pd.DataFrame({
        "f1": [np.nan, 10.0],
        "f2": [np.inf, -np.inf],
        "f3": [999.0, 999.0],
    })

    transformed = prep.transform(test_df)
    assert transformed.shape == (2, 2)
    assert not np.any(np.isnan(transformed))
    assert not np.any(np.isinf(transformed))


def test_leakage_audit_detects_overlap_and_label():
    df1 = pd.DataFrame({"f1": [1, 2, 3], "label": ["Benign", "Port Scan", "Benign"]})
    df2 = pd.DataFrame({"f1": [3, 4, 5], "label": ["Benign", "OS Scan", "Benign"]})

    # Should detect overlap of row with f1=3
    audit = audit_for_leakage(train_df=df1, test_df=df2, feature_cols=["f1"])
    assert audit["train_test_overlap_count"] == 1

    # Should flag error if target label included in features
    audit_bad = audit_for_leakage(train_df=df1, feature_cols=["f1", "label"])
    assert not audit_bad["passed"]
    assert any("label" in err.lower() for err in audit_bad["errors"])
