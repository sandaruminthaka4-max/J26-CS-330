"""
test_model.py — Unit and integration tests for model loading and latency
Project: J26-CS-330 | Component: DoS Detection via SDN Flow Analysis
"""

import json
from pathlib import Path
import joblib
import numpy as np
import pytest

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "models" / "xgboost_model.joblib"
PREPROCESSOR_PATH = BASE_DIR / "models" / "preprocessor.joblib"
SCHEMA_PATH = BASE_DIR / "configs" / "feature_schema.json"


def test_schema_file_exists():
    assert SCHEMA_PATH.exists(), f"Schema file missing at {SCHEMA_PATH}"
    with open(SCHEMA_PATH, "r") as f:
        data = json.load(f)
    assert "feature_names" in data
    assert len(data["feature_names"]) == 45


@pytest.mark.skipif(not MODEL_PATH.exists(), reason="Trained model artifact not yet generated.")
def test_model_loading_and_inference():
    model = joblib.load(MODEL_PATH)
    assert model is not None

    # Synthesize a single sample row matching 45 features
    sample_row = np.zeros((1, 45), dtype=np.float32)
    preds = model.predict(sample_row)
    assert len(preds) == 1
    assert preds[0] in [0, 1]


@pytest.mark.skipif(not MODEL_PATH.exists(), reason="Trained model artifact not yet generated.")
def test_model_inference_latency_target():
    """
    Ensure single-row model inference latency satisfies target (< 50 ms).
    """
    import time
    model = joblib.load(MODEL_PATH)
    sample_row = np.zeros((1, 45), dtype=np.float32)

    # Warm-up
    for _ in range(10):
        _ = model.predict(sample_row)

    latencies = []
    for _ in range(100):
        t0 = time.perf_counter()
        _ = model.predict(sample_row)
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000.0)

    median_lat = float(np.median(latencies))
    # Target in proposal: < 50ms
    assert median_lat < 50.0, f"Median latency {median_lat:.3f} ms exceeds 50 ms target!"
