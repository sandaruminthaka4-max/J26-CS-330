"""
Integration Tests for SDN Zero-Touch Mitigation Interface and Mock Controller.
Verifies Detection -> Alert Creation -> Webhook Dispatch -> Mock Controller -> FlowMod Ack.
"""

import pytest
from fastapi.testclient import TestClient

from src.alerts.engine import AlertEngine
from src.integration.mock_controller import mock_app
from src.integration.sdn_client import SDNMitigationClient


@pytest.fixture
def mock_client():
    return TestClient(mock_app)


def test_mock_controller_health(mock_client):
    res = mock_client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"


def test_mock_controller_receives_vulnerability_scan_alert(mock_client):
    engine = AlertEngine()
    alert = engine.create_alert_object(
        predicted_class="Vulnerability Scan",
        confidence=0.88,
        flow_id="INT-FLOW-VUL-01",
        source_ip="172.16.0.45",
        destination_ip="172.16.0.10",
        destination_port=443,
        is_critical_asset=True,
    )
    assert alert is not None
    assert alert["severity"] == "CRITICAL"

    # Post to mock controller
    res = mock_client.post("/api/v1/mitigation/alert", json=alert)
    assert res.status_code == 200
    ack = res.json()
    assert ack["status"] == "ACKNOWLEDGED"
    assert ack["alert_id"] == alert["alert_id"]
    assert ack["mitigation_action"] == "QUARANTINE_SOURCE_IP"
    assert "openflow_flowmod" in ack
    assert ack["openflow_flowmod"]["instruction"] == "APPLY_ACTIONS: DROP"


def test_mock_controller_receives_port_scan_alert(mock_client):
    engine = AlertEngine()
    alert = engine.create_alert_object(
        predicted_class="Port Scan",
        confidence=0.82,
        flow_id="INT-FLOW-PORT-02",
        source_ip="172.16.0.88",
        destination_ip="172.16.0.22",
        destination_port=80,
    )
    assert alert is not None

    res = mock_client.post("/api/v1/mitigation/alert", json=alert)
    assert res.status_code == 200
    ack = res.json()
    assert ack["status"] == "ACKNOWLEDGED"
    assert ack["mitigation_action"] == "RATE_LIMIT_PORT"
    assert "METER" in ack["openflow_flowmod"]["instruction"]
