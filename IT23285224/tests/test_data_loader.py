"""
Unit Tests for Dataset Schema, Label Mapping, and Manifest Generator.
"""

import os
import pytest
from src.data.schema import (
    CLASS_TO_INT_MAP,
    INT_TO_CLASS_MAP,
    NUMERICAL_FEATURE_COLUMNS,
    RAW_FEATURE_COLUMNS,
    RAW_TO_CANONICAL_LABEL_MAP,
    TARGET_CLASSES,
)


def test_schema_column_counts():
    assert len(RAW_FEATURE_COLUMNS) == 46
    assert len(NUMERICAL_FEATURE_COLUMNS) == 45
    assert "label" not in NUMERICAL_FEATURE_COLUMNS
    assert "label" in RAW_FEATURE_COLUMNS


def test_target_classes():
    assert len(TARGET_CLASSES) == 5
    expected_classes = ["Benign", "Ping Sweep", "Port Scan", "OS Scan", "Vulnerability Scan"]
    assert TARGET_CLASSES == expected_classes


def test_label_mappings():
    assert RAW_TO_CANONICAL_LABEL_MAP["benign"] == "Benign"
    assert RAW_TO_CANONICAL_LABEL_MAP["Ping Sweep"] == "Ping Sweep"
    assert RAW_TO_CANONICAL_LABEL_MAP["Port Scan"] == "Port Scan"
    assert RAW_TO_CANONICAL_LABEL_MAP["OS Scan"] == "OS Scan"
    assert RAW_TO_CANONICAL_LABEL_MAP["Recon VulScan"] == "Vulnerability Scan"

    for cls_name in TARGET_CLASSES:
        idx = CLASS_TO_INT_MAP[cls_name]
        assert INT_TO_CLASS_MAP[idx] == cls_name
