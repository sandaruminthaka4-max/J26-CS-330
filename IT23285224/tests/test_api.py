"""
End-to-End API Tests for Reconnaissance Intrusion Detection Service.
"""

import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.api.routes import runtime_state


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_health_endpoint(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "model_loaded" in data


def test_model_info_endpoint(client):
    res = client.get("/model/info")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ACTIVE"
    assert data["selected_feature_count"] == 15
    assert len(data["selected_features"]) == 15
    assert len(data["target_classes"]) == 5


def test_features_endpoint(client):
    res = client.get("/features")
    assert res.status_code == 200
    data = res.json()
    assert "selected_features" in data
    assert len(data["selected_features"]) == 15


def test_predict_single_flow(client):
    payload = {
        "flow_id": "TEST-FLOW-999",
        "source_ip": "192.168.1.100",
        "destination_ip": "192.168.1.20",
        "is_critical_asset": True,
        "Header_Length": 54.0,
        "syn_flag_number": 1.0,
        "Rate": 500.0,
        "Duration": 0.05,
        "Max": 60.0,
        "Min": 60.0,
        "Tot size": 60.0,
        "Magnitue": 10.95,
        "Srate": 500.0,
        "IAT": 0.002,
    }
    res = client.post("/predict", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "prediction" in data
    assert "confidence" in data
    assert "severity" in data
    assert data["flow_id"] == "TEST-FLOW-999"
    assert data["prediction"] in ["Benign", "Ping Sweep", "Port Scan", "OS Scan", "Vulnerability Scan"]


def test_predict_batch_flows(client):
    flows = [
        {"flow_id": "BATCH-1", "syn_flag_number": 0.0, "Rate": 10.0, "Duration": 1.0},
        {"flow_id": "BATCH-2", "syn_flag_number": 1.0, "Rate": 900.0, "Duration": 0.01},
    ]
    res = client.post("/predict/batch", json={"flows": flows})
    assert res.status_code == 200
    data = res.json()
    assert data["count"] == 2
    assert len(data["predictions"]) == 2
    assert "processing_time_ms" in data


def test_alerts_endpoint(client):
    res = client.get("/alerts?limit=5")
    assert res.status_code == 200
    data = res.json()
    assert "alerts" in data
    assert "count" in data


def test_metrics_endpoint(client):
    res = client.get("/metrics")
    assert res.status_code == 200
    data = res.json()
    assert "ram_rss_mb" in data
    assert "cpu_percent" in data
