"""
test_preprocessing.py — Unit tests for dataset cleaning and label mapping
Project: J26-CS-330 | Component: DoS Detection via SDN Flow Analysis
"""

import numpy as np
import pandas as pd
import pytest
from src.preprocessing.cleaner import clean_dataframe, encode_labels, encode_protocol


def test_clean_removes_duplicates():
    df = pd.DataFrame({
        "Duration": [1.0, 1.0, 2.0],
        "Rate": [10.0, 10.0, 20.0],
        "Protocol Type": [6, 6, 17],
    })
    cleaned_df, stats = clean_dataframe(df, {"preprocessing": {"remove_duplicates": True}})
    assert len(cleaned_df) == 2
    assert stats["duplicates_removed"] == 1


def test_clean_handles_inf_and_nan():
    df = pd.DataFrame({
        "Duration": [1.0, np.inf, 3.0],
        "Rate": [10.0, np.nan, 30.0],
    })
    cleaned_df, stats = clean_dataframe(df, {"preprocessing": {"fill_strategy": "median", "remove_duplicates": False}})
    assert not np.isinf(cleaned_df.values).any()
    assert not np.isnan(cleaned_df.values).any()
    assert stats["inf_values_found"] == 1
    assert stats["nan_values_found"] >= 1


def test_clean_clips_negative_values():
    df = pd.DataFrame({
        "Duration": [-5.0, 10.0],
        "Rate": [-100.0, 50.0],
    })
    cleaned_df, _ = clean_dataframe(df, {"preprocessing": {"remove_duplicates": False}})
    assert (cleaned_df["Duration"] >= 0).all()
    assert (cleaned_df["Rate"] >= 0).all()


def test_encode_labels_binary():
    df = pd.DataFrame({
        "label": ["benign", "DDoS UDP", "DoS TCP", "Unknown_Threat"],
        "Rate": [10.0, 50000.0, 30000.0, 5.0],
    })
    dos_labels = ["DDoS UDP", "DoS TCP"]
    normal_labels = ["benign"]

    encoded_df = encode_labels(df, "label", dos_labels, normal_labels)
    # The unknown threat should be dropped
    assert len(encoded_df) == 3
    assert set(encoded_df["binary_label"].unique()) == {0, 1}
    assert (encoded_df[encoded_df["label"] == "benign"]["binary_label"] == 0).all()
    assert (encoded_df[encoded_df["label"] == "DDoS UDP"]["binary_label"] == 1).all()


def test_encode_protocol():
    df = pd.DataFrame({
        "Protocol Type": ["TCP", "UDP", "TCP", "ICMP"],
    })
    df_encoded, encoder = encode_protocol(df)
    assert np.issubdtype(df_encoded["Protocol Type"].dtype, np.integer)
    assert len(encoder.classes_) == 3
