"""
test_features.py — Unit tests for feature extraction and OpenFlow mapping
Project: J26-CS-330 | Component: DoS Detection via SDN Flow Analysis
"""

import json
import numpy as np
import pandas as pd
import pytest
from src.features.extractor import (
    extract_features,
    features_from_api_input,
    get_feature_names,
    openflow_to_features,
    validate_feature_order,
)


def test_schema_feature_count():
    names = get_feature_names()
    assert len(names) == 45
    assert "Duration" in names
    assert "Rate" in names
    assert "Protocol Type" in names


def test_extract_features_enforces_order():
    feature_names = ["Duration", "Rate", "TCP"]
    df = pd.DataFrame({
        "TCP": [1.0],
        "Duration": [2.5],
        "Rate": [100.0],
    })
    X = extract_features(df, feature_names)
    assert X.shape == (1, 3)
    # Check exact order: Duration, Rate, TCP
    assert X[0, 0] == 2.5
    assert X[0, 1] == 100.0
    assert X[0, 2] == 1.0


def test_validate_feature_order_missing_raises():
    feature_names = ["Duration", "NonExistentFeature"]
    df = pd.DataFrame({"Duration": [1.0]})
    with pytest.raises(ValueError):
        validate_feature_order(df, feature_names)


def test_features_from_api_input():
    names = ["Duration", "Rate", "Protocol Type"]
    data = {"Duration": 3.0, "Rate": 5000.0}
    arr = features_from_api_input(data, names)
    assert arr.shape == (1, 3)
    assert arr[0, 0] == 3.0
    assert arr[0, 1] == 5000.0
    assert arr[0, 2] == 0.0  # missing defaults to 0


def test_openflow_to_features_bridge():
    feature_names = get_feature_names()
    flow_stats = {
        "packet_count": 1000,
        "byte_count": 64000,
        "duration_sec": 2,
        "duration_nsec": 0,
        "ip_proto": 6,  # TCP
        "tcp_flags": 0x02,  # SYN flag
    }
    mapped = openflow_to_features(flow_stats, feature_names)
    assert mapped["Duration"] == 2.0
    assert mapped["Rate"] == 500.0
    assert mapped["TCP"] == 1.0
    assert mapped["syn_flag_number"] == 1.0
    assert mapped["syn_count"] == 1.0
