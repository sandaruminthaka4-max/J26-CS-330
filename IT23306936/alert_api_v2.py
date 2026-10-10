import json
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from flask import Flask, request
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge
from alert_validation_v2 import validate_alert

BASE = Path(__file__).resolve().parent

_MAX_SEEN_IDS = 10_000  # FIFO eviction bound to prevent unbounded growth


def create_app(log_file=None, context_provider=None):
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
    services = json.loads(
        (BASE / "configs/services_v2.json").read_text()
    )
    path = (
        Path(log_file) if log_file is not None
        else BASE / "logs/alerts_v2.jsonl"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = Lock()
    seen_ids: set[str] = set()
    seen_order: deque[str] = deque()
    in_flight_ids: set[str] = set()

    def record(event):
        with lock:
            with path.open("a", encoding="utf-8") as output:
                output.write(json.dumps(event) + "\n")

    def reject(reason, status):
        record({
            "event": "alert_rejected",
            "received_at": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "http_status": status,
        })
        return {"status": "rejected", "error": reason}, status

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "component": "alert_api_v2",
            "enforcement_enabled": False,
        }

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(error):
        return reject("Request exceeds 16 KiB", 413)

    @app.post("/alert")
    def receive_alert():
        if not request.is_json:
            return reject("Content-Type must be application/json", 415)

        try:
            data = request.get_json()
        except BadRequest:
            return reject("Malformed JSON", 400)

        # Duplicate alert_id guard (FR1 extension).
        #
        # Architecture and Semantics:
        #   - Thread-safe, session-scoped, in-memory duplicate filter with FIFO eviction (bound: 10,000).
        #   - Transient in-memory storage: The cache DOES NOT survive service restart and
        #     permits reuse of alert_id after FIFO eviction.
        #   - DO NOT describe as durable idempotency: It does NOT provide persistent, database-backed,
        #     or distributed idempotency across server instances, restarts, or cache evictions.
        #   - Concurrent duplicate requests: In-flight tracking (in_flight_ids under lock) rejects
        #     simultaneous concurrent submissions of the same alert_id with HTTP 409 Conflict.
        #   - Failed processing & retry behavior: An alert_id whose submission failed (e.g. 400
        #     validation error, 415 content type, 413 payload too large) is removed from in_flight_ids
        #     and NOT added to seen_ids. The client is explicitly permitted to retry with a
        #     corrected payload using the same alert_id.
        raw_id = data.get("alert_id", "") if isinstance(data, dict) else ""
        if raw_id:
            with lock:
                if raw_id in seen_ids:
                    dup_event = {
                        "event": "alert_duplicate",
                        "received_at": datetime.now(timezone.utc).isoformat(),
                        "alert_id": raw_id,
                        "reason": "Duplicate alert_id rejected (previously accepted)",
                    }
                    with path.open("a", encoding="utf-8") as f:
                        f.write(json.dumps(dup_event) + "\n")
                    return {"status": "duplicate",
                            "error": "alert_id already accepted in this session",
                            "alert_id": raw_id}, 409
                if raw_id in in_flight_ids:
                    dup_event = {
                        "event": "alert_duplicate_inflight",
                        "received_at": datetime.now(timezone.utc).isoformat(),
                        "alert_id": raw_id,
                        "reason": "Concurrent duplicate alert_id currently in processing",
                    }
                    with path.open("a", encoding="utf-8") as f:
                        f.write(json.dumps(dup_event) + "\n")
                    return {"status": "duplicate",
                            "error": "alert_id currently in processing",
                            "alert_id": raw_id}, 409
                in_flight_ids.add(raw_id)

        try:
            alert, service = validate_alert(data, services)
        except ValueError as error:
            if raw_id:
                with lock:
                    in_flight_ids.discard(raw_id)
            return reject(str(error), 400)

        from copy import deepcopy
        from mitigation_policy_v2 import choose_action

        try:
            context = (
                context_provider(deepcopy(alert), deepcopy(service))
                if context_provider is not None else {}
            )
            if not isinstance(context, dict):
                raise ValueError("Context provider must return a dictionary")
            context = deepcopy(context)
            context["protected_services"] = [
                deepcopy(item) for item in services.values()
                if item["criticality"] == "critical"
            ]
            recommendation = choose_action(alert, service, context)
        except Exception:
            app.logger.exception("Context collection or policy failed")
            recommendation = {
                "action": "review",
                "reason": "Context collection or policy failed",
                "enforcement_enabled": False,
            }

        event = {
            "recommendation": recommendation,
            "event": "alert_accepted",
            "received_at": datetime.now(timezone.utc).isoformat(),
            "alert": alert,
            "service_context": service,
            "status": "validated",
            "action": "none",
            "enforcement_enabled": False,
        }
        record(event)

        # Register alert_id only after successful acceptance.
        # Clear in-flight tracking and record into seen_ids under lock.
        if raw_id:
            with lock:
                in_flight_ids.discard(raw_id)
                if raw_id not in seen_ids:
                    if len(seen_ids) >= _MAX_SEEN_IDS:
                        oldest = seen_order.popleft()
                        seen_ids.discard(oldest)
                    seen_ids.add(raw_id)
                    seen_order.append(raw_id)

        return event, 201

    return app


if __name__ == "__main__":
    create_app().run(
        host="127.0.0.1", port=5001,
        debug=False, threaded=False,
    )
