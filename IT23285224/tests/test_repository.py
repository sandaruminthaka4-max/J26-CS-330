"""
Unit Tests for SQLite Alert Repository Operations.
"""

import os
import tempfile
import pytest
from src.alerts.repository import SQLiteAlertRepository


def test_sqlite_repository_crud():
    db_path = tempfile.mktemp(suffix=".db")

    try:
        repo = SQLiteAlertRepository(db_path=db_path)

        # Save an alert
        alert = {
            "alert_id": "ALT-TEST-001",
            "timestamp": "2026-10-17T08:00:00Z",
            "flow_id": "FLOW-001",
            "prediction": "Port Scan",
            "attack_type": "Reconnaissance",
            "recon_subtype": "Port Scan",
            "confidence": 0.94,
            "severity": "HIGH",
            "status": "CONFIRMED",
            "source_ip": "192.168.1.100",
            "destination_ip": "192.168.1.20",
            "destination_port": 80,
            "is_critical_asset": True,
            "model_version": "v1.0.0",
            "delivery_status": "PENDING",
            "mitigation_action": "NONE",
        }
        res_id = repo.save_alert(alert)
        assert res_id == "ALT-TEST-001"

        # Fetch by ID
        fetched = repo.get_alert_by_id("ALT-TEST-001")
        assert fetched is not None
        assert fetched["prediction"] == "Port Scan"
        assert fetched["confidence"] == 0.94
        assert fetched["severity"] == "HIGH"

        # List with filter
        alerts_list = repo.list_alerts(limit=10, severity="HIGH")
        assert len(alerts_list) == 1

        # Update status
        repo.update_delivery_status("ALT-TEST-001", "DELIVERED", "QUARANTINE_SOURCE_IP")
        updated = repo.get_alert_by_id("ALT-TEST-001")
        assert updated["delivery_status"] == "DELIVERED"
        assert updated["mitigation_action"] == "QUARANTINE_SOURCE_IP"

    finally:
        if os.path.exists(db_path):
            os.remove(db_path)
