import ipaddress
import math
from datetime import datetime
from copy import deepcopy

ALIASES = {
    "dos": "dos",
    "dos_flooding": "dos",
    "reconnaissance": "reconnaissance",
    "mitm": "mitm",
}

REQUIRED = (
    "alert_id", "attack_type", "source_ip", "target_ip",
    "severity", "affected_service", "detector_id", "timestamp",
)


def validate_alert(data, services):
    if not isinstance(data, dict):
        raise ValueError("Send a JSON object")

    for field in REQUIRED:
        value = data.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} must be a nonempty string")
        if len(value) > 256:
            raise ValueError(f"{field} is too long")

    alert = {field: data[field].strip() for field in REQUIRED}

    attack = ALIASES.get(alert["attack_type"].lower())
    if attack is None:
        raise ValueError("Unsupported attack_type")
    alert["attack_type"] = attack

    for field in ("source_ip", "target_ip"):
        try:
            alert[field] = str(ipaddress.IPv4Address(alert[field]))
        except ipaddress.AddressValueError:
            raise ValueError(f"{field} must be a valid IPv4 address")

    alert["severity"] = alert["severity"].lower()
    if alert["severity"] not in {"low", "medium", "high"}:
        raise ValueError("severity must be low, medium, or high")

    try:
        timestamp = datetime.fromisoformat(
            alert["timestamp"].replace("Z", "+00:00")
        )
    except ValueError:
        raise ValueError("timestamp must be ISO 8601")
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    alert["timestamp"] = timestamp.isoformat()

    if "confidence" in data:
        confidence = data["confidence"]
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not math.isfinite(confidence)
            or not 0 <= confidence <= 1
        ):
            raise ValueError("confidence must be a number from 0 to 1")
        alert["confidence"] = float(confidence)

    service = services.get(alert["affected_service"])
    if service is None:
        raise ValueError("affected_service is not registered")
    if service["criticality"] not in {"critical", "noncritical"}:
        raise ValueError("Invalid service criticality configuration")
    if alert["target_ip"] != service["target_ip"]:
        raise ValueError("target_ip does not match the configured service")

    return alert, deepcopy(service)
