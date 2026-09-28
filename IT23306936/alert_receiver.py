import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from flask import Flask, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

LOG_FILE = Path(__file__).resolve().parent / "logs" / "alerts.jsonl"
LOG_FILE.parent.mkdir(exist_ok=True)

ATTACK_TYPES = {"dos", "reconnaissance", "mitm"}


@app.get("/health")
def health():
    return {"status": "ok", "component": "alert_receiver"}


@app.post("/alert")
def receive_alert():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return {"error": "Send a JSON object"}, 400

    attack_type = data.get("attack_type")
    if not isinstance(attack_type, str):
        return {"error": "attack_type must be a string"}, 400

    attack_type = attack_type.strip().lower()
    if attack_type not in ATTACK_TYPES:
        return {"error": "Use dos, reconnaissance, or mitm"}, 400

    try:
        source_ip = str(ipaddress.IPv4Address(data.get("source_ip")))
    except (ValueError, TypeError):
        return {"error": "source_ip must be a valid IPv4 address"}, 400

    alert = {
        "alert_id": str(uuid4()),
        "received_at": datetime.now(timezone.utc).isoformat(),
        "attack_type": attack_type,
        "source_ip": source_ip,
        "status": "received",
    }

    alert["action"] = "none"

    from mitigation_policy import choose_action

    devices = {
        "10.0.0.1": "critical",
        "10.0.0.3": "noncritical",
    }
    criticality = devices.get(source_ip)

    if criticality is None:
        policy = {
            "action": "review",
            "reason": "Device is not registered",
        }
    else:
        policy = choose_action(attack_type, criticality)

    alert["criticality"] = criticality
    alert["recommended_action"] = policy["action"]
    alert["policy_reason"] = policy["reason"]

    if policy["action"] == "rate_limit":
        import subprocess

        rule = (
            "cookie=0x23,priority=110,hard_timeout=60,"
            "ip,nw_src=10.0.0.1,nw_dst=10.0.0.2,"
            "udp,tp_dst=5201,actions=meter:1,normal"
        )

        try:
            subprocess.run(
                ["sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13",
                 "add-flow", "s1", rule],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
            alert["action"] = "rate_limit"
            alert["status"] = "rule_installed"
            alert["rate_limit_kbps"] = 1000
            alert["duration_seconds"] = 60
            alert["scope"] = "UDP to 10.0.0.2 port 5201"
        except (subprocess.CalledProcessError,
                subprocess.TimeoutExpired, OSError) as error:
            alert["status"] = "enforcement_failed"
            alert["error"] = (
                getattr(error, "stderr", None) or str(error)
            ).strip()
            app.logger.exception("Rate-limit installation failed")

    if policy["action"] == "review":
        alert["status"] = "review_required"

    if policy["action"] == "block" and source_ip == "10.0.0.3":
        import subprocess

        rule = (
            "cookie=0x22,priority=100,hard_timeout=60,"
            "ip,nw_src=10.0.0.3,actions=drop"
        )

        try:
            subprocess.run(
                ["sudo", "-n", "ovs-ofctl", "add-flow", "s1", rule],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
            alert["action"] = "block"
            alert["status"] = "rule_installed"
            alert["duration_seconds"] = 60
        except (subprocess.CalledProcessError,
                subprocess.TimeoutExpired, OSError) as error:
            alert["status"] = "enforcement_failed"
            alert["error"] = str(error)
            app.logger.exception("Blocking rule installation failed")

    with LOG_FILE.open("a", encoding="utf-8") as log:
        log.write(json.dumps(alert) + "\n")

    print("ALERT RECEIVED:", json.dumps(alert), flush=True)
    return alert, 201


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=False)
