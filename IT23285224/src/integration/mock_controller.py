"""
Mock SDN Zero-Touch Mitigation Controller Service.
Simulates Ryu / OpenFlow mitigation reception, automated rule synthesis, and flow quarantine.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

mock_app = FastAPI(
    title="Mock SDN Zero-Touch Mitigation Controller",
    version="1.0.0",
    description="Simulates reception of reconnaissance alerts and automated OpenFlow FlowMod generation.",
)

# In-memory store of received alerts and installed OpenFlow flow rules
received_alerts: List[Dict[str, Any]] = []
installed_rules: List[Dict[str, Any]] = []


class MitigationAlertPayload(BaseModel):
    alert_id: str
    timestamp: str
    flow_id: str
    prediction: str
    attack_type: str = "Reconnaissance"
    recon_subtype: str
    confidence: float
    severity: str
    status: str
    source_ip: Optional[str] = "unknown"
    destination_ip: Optional[str] = "unknown"
    destination_port: Optional[int] = None
    is_critical_asset: Optional[bool] = False
    model_version: Optional[str] = "v1.0.0"


@mock_app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "Mock SDN Zero-Touch Mitigation Controller",
        "received_alerts_count": len(received_alerts),
        "installed_flowmods_count": len(installed_rules),
    }


@mock_app.post("/api/v1/mitigation/alert")
def receive_alert(payload: MitigationAlertPayload):
    """
    Receives an alert from the Reconnaissance IDS, decides on proportionate mitigation,
    and returns simulated OpenFlow rule confirmation.
    """
    alert_data = payload.model_dump()
    alert_data["received_at"] = datetime.now(timezone.utc).isoformat()
    received_alerts.append(alert_data)

    # Mitigation policy decision based on subtype and severity
    rule_id = f"OF-RULE-{uuid.uuid4().hex[:8].upper()}"
    src_ip = payload.source_ip
    sev = payload.severity.upper()
    subtype = payload.recon_subtype

    if sev == "CRITICAL" or subtype == "Vulnerability Scan":
        action = "QUARANTINE_SOURCE_IP"
        openflow_mod = {
            "rule_id": rule_id,
            "match": {"ipv4_src": src_ip, "eth_type": 0x0800},
            "instruction": "APPLY_ACTIONS: DROP",
            "priority": 60000,
            "idle_timeout": 300,
            "hard_timeout": 600,
        }
    elif sev == "HIGH" or subtype in ("Port Scan", "OS Scan"):
        action = "RATE_LIMIT_PORT"
        openflow_mod = {
            "rule_id": rule_id,
            "match": {"ipv4_src": src_ip, "tcp_dst": payload.destination_port or 0},
            "instruction": "METER: 50kbps, LOG_PACKETS",
            "priority": 40000,
            "idle_timeout": 120,
            "hard_timeout": 300,
        }
    else:
        action = "MIRROR_TO_HONEYPOT_AND_LOG"
        openflow_mod = {
            "rule_id": rule_id,
            "match": {"ipv4_src": src_ip},
            "instruction": "OUTPUT: PORT_MIRROR_INSPECTION",
            "priority": 20000,
            "idle_timeout": 60,
            "hard_timeout": 120,
        }

    installed_rules.append(openflow_mod)

    return {
        "status": "ACKNOWLEDGED",
        "alert_id": payload.alert_id,
        "mitigation_action": action,
        "openflow_flowmod": openflow_mod,
        "controller_timestamp": datetime.now(timezone.utc).isoformat(),
    }


@mock_app.get("/api/v1/mitigation/rules")
def get_installed_rules():
    return {"count": len(installed_rules), "rules": installed_rules}


@mock_app.get("/api/v1/mitigation/alerts")
def get_received_alerts():
    return {"count": len(received_alerts), "alerts": received_alerts}
