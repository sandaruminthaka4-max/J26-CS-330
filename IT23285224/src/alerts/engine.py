"""
Confidence-Aware Severity Mapping & Alert Decision Engine.
Evaluates model confidence, reconnaissance subtype, and IoMT target criticality
to assign calibrated severity and determine mitigation eligibility.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class SeverityLevel(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, Enum):
    BENIGN = "BENIGN"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    PENDING_REVIEW = "PENDING_REVIEW"
    CONFIRMED = "CONFIRMED"
    MITIGATION_ELIGIBLE = "MITIGATION_ELIGIBLE"


class AlertEngine:
    """
    Evaluates raw predictions, confidence levels, and clinical context to generate structured alerts.
    """

    def __init__(
        self,
        confidence_threshold: float = 0.70,
        high_confidence_threshold: float = 0.85,
    ):
        self.confidence_threshold = confidence_threshold
        self.high_confidence_threshold = high_confidence_threshold

    def compute_severity(
        self,
        predicted_class: str,
        confidence: float,
        is_critical_asset: bool = False,
    ) -> SeverityLevel:
        """
        Determines severity based on attack subtype, probability confidence, and device asset criticality.
        """
        if predicted_class == "Benign":
            return SeverityLevel.INFO

        severity = SeverityLevel.LOW

        if predicted_class == "Ping Sweep":
            if confidence >= self.high_confidence_threshold:
                severity = SeverityLevel.MEDIUM
            else:
                severity = SeverityLevel.LOW

        elif predicted_class in ("Port Scan", "OS Scan"):
            if confidence >= self.high_confidence_threshold:
                severity = SeverityLevel.HIGH
            elif confidence >= self.confidence_threshold:
                severity = SeverityLevel.MEDIUM
            else:
                severity = SeverityLevel.LOW

        elif predicted_class == "Vulnerability Scan":
            if confidence >= self.confidence_threshold:
                severity = SeverityLevel.CRITICAL
            else:
                severity = SeverityLevel.HIGH

        # Escalate by 1 level if targeting a critical clinical device (e.g. infusion pump)
        if is_critical_asset and predicted_class != "Benign":
            escalation_map = {
                SeverityLevel.LOW: SeverityLevel.MEDIUM,
                SeverityLevel.MEDIUM: SeverityLevel.HIGH,
                SeverityLevel.HIGH: SeverityLevel.CRITICAL,
                SeverityLevel.CRITICAL: SeverityLevel.CRITICAL,
            }
            severity = escalation_map.get(severity, severity)

        return severity

    def create_alert_object(
        self,
        predicted_class: str,
        confidence: float,
        flow_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        destination_port: Optional[int] = None,
        is_critical_asset: bool = False,
        model_version: str = "v1.0.0",
        raw_features: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Generates a complete, structured JSON alert dictionary if the classification represents an attack.
        """
        if predicted_class == "Benign":
            return None

        severity = self.compute_severity(predicted_class, confidence, is_critical_asset)

        # Determine alert status
        if confidence < self.confidence_threshold:
            status = AlertStatus.LOW_CONFIDENCE
        elif severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL):
            status = AlertStatus.MITIGATION_ELIGIBLE
        else:
            status = AlertStatus.CONFIRMED

        alert_id = f"ALT-{uuid.uuid4().hex[:10].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat()

        return {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "flow_id": flow_id or f"flow-{uuid.uuid4().hex[:8]}",
            "prediction": predicted_class,
            "attack_type": "Reconnaissance",
            "recon_subtype": predicted_class,
            "confidence": round(float(confidence), 4),
            "severity": severity.value,
            "status": status.value,
            "source_ip": source_ip or "unknown",
            "destination_ip": destination_ip or "unknown",
            "destination_port": destination_port,
            "is_critical_asset": is_critical_asset,
            "model_version": model_version,
            "delivery_status": "PENDING",
            "mitigation_action": "NONE",
        }
