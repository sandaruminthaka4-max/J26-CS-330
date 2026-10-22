"""
Unit Tests for Confidence-Aware Severity Mapping and Alert Engine.
"""

import pytest
from src.alerts.engine import AlertEngine, AlertStatus, SeverityLevel


def test_severity_rule_engine():
    engine = AlertEngine(confidence_threshold=0.70, high_confidence_threshold=0.85)

    # Benign should produce INFO
    assert engine.compute_severity("Benign", 0.99) == SeverityLevel.INFO

    # Ping Sweep
    assert engine.compute_severity("Ping Sweep", 0.60) == SeverityLevel.LOW
    assert engine.compute_severity("Ping Sweep", 0.90) == SeverityLevel.MEDIUM

    # Port Scan
    assert engine.compute_severity("Port Scan", 0.65) == SeverityLevel.LOW
    assert engine.compute_severity("Port Scan", 0.75) == SeverityLevel.MEDIUM
    assert engine.compute_severity("Port Scan", 0.90) == SeverityLevel.HIGH

    # Vulnerability Scan
    assert engine.compute_severity("Vulnerability Scan", 0.65) == SeverityLevel.HIGH
    assert engine.compute_severity("Vulnerability Scan", 0.85) == SeverityLevel.CRITICAL


def test_clinical_asset_escalation():
    engine = AlertEngine()

    # Normal asset vs critical asset escalation
    sev_normal = engine.compute_severity("Port Scan", 0.75, is_critical_asset=False)
    sev_critical = engine.compute_severity("Port Scan", 0.75, is_critical_asset=True)

    assert sev_normal == SeverityLevel.MEDIUM
    assert sev_critical == SeverityLevel.HIGH  # Escalated by 1 level


def test_alert_object_creation():
    engine = AlertEngine()

    # Benign returns None
    assert engine.create_alert_object("Benign", 0.95) is None

    # Port Scan returns structured alert
    alert = engine.create_alert_object(
        predicted_class="Port Scan",
        confidence=0.92,
        flow_id="FLOW-TEST-123",
        source_ip="10.0.0.99",
        destination_ip="10.0.0.2",
    )
    assert alert is not None
    assert alert["prediction"] == "Port Scan"
    assert alert["attack_type"] == "Reconnaissance"
    assert alert["severity"] in ("HIGH", "CRITICAL")
    assert alert["flow_id"] == "FLOW-TEST-123"
    assert alert["status"] == AlertStatus.MITIGATION_ELIGIBLE.value
