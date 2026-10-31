"""
test_api.py — Functional test suite for the FastAPI detection service
Project: J26-CS-330 | Component: DoS Detection via SDN Flow Analysis
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "model_loaded" in data
    assert "feature_count" in data
    assert data["feature_count"] == 45


def test_predict_validation_error():
    # Sending invalid data type for Duration (string that can't be parsed)
    payload = {"Duration": "not-a-number"}
    response = client.post("/predict", json=payload)
    assert response.status_code == 422


def test_predict_empty_payload_uses_defaults():
    # An empty payload should gracefully fill all 45 features with 0.0 defaults
    payload = {}
    response = client.post("/predict", json=payload)
    # If model is loaded -> 200, else if degraded mode -> 503
    assert response.status_code in [200, 503]
    if response.status_code == 200:
        data = response.json()
        assert "prediction" in data
        assert "is_dos" in data
        assert "confidence" in data
        assert "inference_latency_ms" in data
        assert 0.0 <= data["confidence"] <= 1.0


def test_predict_normal_traffic_format():
    # Synthetic normal low-rate flow
    payload = {
        "Duration": 10.0,
        "Rate": 5.0,
        "Protocol Type": 6.0,
        "TCP": 1.0,
        "Number": 50.0,
        "Tot sum": 3200.0,
    }
    response = client.post("/predict", json=payload)
    assert response.status_code in [200, 503]
    if response.status_code == 200:
        data = response.json()
        assert data["prediction"] in ["Normal", "DoS"]
        assert isinstance(data["is_dos"], bool)


def test_predict_dos_traffic_format():
    # Synthetic high-rate flood traffic
    payload = {
        "Duration": 1.0,
        "Rate": 550000.0,
        "Protocol Type": 17.0,
        "UDP": 1.0,
        "Number": 550000.0,
        "Tot sum": 35200000.0,
    }
    response = client.post("/predict", json=payload)
    assert response.status_code in [200, 503]
    if response.status_code == 200:
        data = response.json()
        assert data["prediction"] in ["Normal", "DoS"]
        assert isinstance(data["is_dos"], bool)
