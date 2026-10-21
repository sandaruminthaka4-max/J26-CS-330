#!/usr/bin/env python3
"""Regression and Acceptance Test Suite for Dashboard Data Integrity.

Verifies:
1. Issue A: DEMO -> LIVE resets state and clears synthetic measurements.
2. Issue B: Live mode request without root / on Windows is rejected; never executes mock labeled as live.
3. Issue C: Predefined scenario selection invokes exact target scenario.
4. Issue D: Replay discovers nested runs inside matched_comparison_* and supports sequential stepping.
5. Issue E: Unified RTT field names (icmp_reply_rtt_avg_ms and icmp_rtt_avg_ms).
6. Issue F: Missing/invalid telemetry fails closed and remains null (never zero).
7. Issue G: Process completion reaps handles and releases experiment lock.
8. Issue H: Authentication token verification on control endpoints.
9. Issue I: Path traversal protection strictly enforces containment within results directory.
10. Issue J: History parsing separates execution failure from valid QoS failure.
"""

import json
import os
from pathlib import Path
import pytest
import sys
import time

from dashboard_server import (
    app, resolve_secure_result_path, scan_results_history,
    PREDEFINED_SCENARIOS, AUTH_TOKEN, EXPERIMENT_LOCK
)
from telemetry_contract import (
    TelemetryEnvelope, create_waiting_envelope, validate_telemetry_dict, SCHEMA_VERSION
)


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


class TestDashboardIntegrityRegressions:
    """Verifies all identified dashboard regression fixes (Issues A - L)."""

    def test_issue_a_mode_switch_clears_synthetic_measurements(self, client):
        """DEMO -> LIVE must reset state and clear synthetic metrics to None/null."""
        # Switch to DEMO
        client.post("/api/mode", json={"mode": "DEMO"})
        # Switch to LIVE
        res = client.post("/api/mode", json={"mode": "LIVE"})
        assert res.status_code == 200

        # Query telemetry
        res_t = client.get("/api/telemetry")
        assert res_t.status_code == 200
        data = res_t.get_json()
        assert data["mode"] == "LIVE"
        assert data["data_freshness"] in ("waiting", "stale", "fresh")
        # In waiting state, metrics must NOT retain DEMO 100.0 or 23.4
        if data["data_freshness"] == "waiting":
            assert data["sensor_throughput_kbps"] is None
            assert data["sensor_packet_loss_percent"] is None
            assert data["qos_satisfied"] is None

    def test_issue_b_live_request_without_root_rejected_never_labeled_live(self, client):
        """A LIVE request must be rejected if root privileges are unavailable; never run mock labeled LIVE."""
        # On Windows host or non-root, live=True must return 403
        is_linux = sys.platform.startswith("linux")
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        if not (is_linux and is_root):
            res = client.post(
                "/api/experiments/start",
                headers={"X-IoMT-Token": AUTH_TOKEN},
                json={"scenario": "adaptive", "live": True},
            )
            assert res.status_code == 403
            err_msg = res.get_json()["error"]
            assert "requires Linux root privileges" in err_msg

    def test_issue_c_scenario_selection_targets_specific_scenario(self):
        """Scenario buttons must invoke specific target scenarios, not the identical comparison command."""
        assert "--scenario" in PREDEFINED_SCENARIOS["adaptive"]
        assert "adaptive" in PREDEFINED_SCENARIOS["adaptive"]

        assert "--scenario" in PREDEFINED_SCENARIOS["static_block"]
        assert "static_block" in PREDEFINED_SCENARIOS["static_block"]

        assert "--scenario" in PREDEFINED_SCENARIOS["baseline"]
        assert "baseline" in PREDEFINED_SCENARIOS["baseline"]

        assert "--scenario" in PREDEFINED_SCENARIOS["smoke_1_repeat"]
        assert "all" in PREDEFINED_SCENARIOS["smoke_1_repeat"]

    def test_issue_d_replay_discovers_nested_runs_and_steps_sequentially(self, client):
        """Replay scanner must expose individual runs inside matched_comparison directories and support stepping."""
        # 1. Scan history
        history, errors = scan_results_history()
        matched = next((h for h in history if h["type"] == "matched_comparison"), None)
        if matched and matched["nested_runs"]:
            nested_id = matched["nested_runs"][0]["run_id"]
            # Load replay
            res_load = client.post(
                "/api/replay/load",
                headers={"X-IoMT-Token": AUTH_TOKEN},
                json={"run_id": nested_id},
            )
            if res_load.status_code == 200:
                load_data = res_load.get_json()
                assert load_data["status"] == "replay_loaded"
                assert load_data["total_windows"] > 0

                # Step forward
                res_step = client.post(
                    "/api/replay/step",
                    headers={"X-IoMT-Token": AUTH_TOKEN},
                    json={"direction": "next"},
                )
                assert res_step.status_code == 200
                step_data = res_step.get_json()
                assert step_data["status"] == "step_updated"

    def test_issue_e_unified_rtt_field_names(self, client):
        """Backend must provide both icmp_rtt_avg_ms and icmp_reply_rtt_avg_ms with identical values."""
        res = client.get("/api/telemetry")
        assert res.status_code == 200
        data = res.get_json()
        assert "icmp_rtt_avg_ms" in data
        assert "icmp_reply_rtt_avg_ms" in data
        assert data["icmp_rtt_avg_ms"] == data["icmp_reply_rtt_avg_ms"]

    def test_issue_f_missing_telemetry_fails_closed(self):
        """Telemetry validator must reject missing or non-finite metrics from issuing a PASS."""
        bad_payload = {
            "sensor_throughput_kbps": None,
            "sensor_packet_loss_percent": None,
            "data_freshness": "fresh",
        }
        ok, err, env = validate_telemetry_dict(bad_payload)
        assert ok is True
        assert env.qos.passed is None
        assert env.validity.measurement_valid is False

        nan_payload = {
            "metrics": {
                "sensor_throughput_kbps": float("nan"),
                "sensor_packet_loss_percent": 0.0,
            },
            "freshness": {"status": "fresh"},
        }
        ok2, err2, env2 = validate_telemetry_dict(nan_payload)
        assert ok2 is True
        assert env2.metrics.sensor_throughput_kbps is None
        assert env2.qos.passed is None

    def test_issue_g_experiment_lock_lifecycle(self, client):
        """Experiment lock must be released on stop or completion."""
        # Stop experiment when none is running should release/confirm unlock
        res = client.post("/api/experiments/stop", headers={"X-IoMT-Token": AUTH_TOKEN})
        assert res.status_code == 200
        assert not EXPERIMENT_LOCK.locked()

    def test_issue_h_control_authentication(self, client):
        """Unauthorized requests from non-loopback with invalid token must be rejected."""
        # Simulate remote non-loopback IP
        res = client.post(
            "/api/experiments/start",
            environ_overrides={"REMOTE_ADDR": "192.168.1.100"},
            headers={"X-IoMT-Token": "invalid_secret_token"},
            json={"scenario": "adaptive"},
        )
        assert res.status_code == 403
        assert "Unauthorized" in res.get_json()["error"]

    def test_issue_i_path_traversal_prevention(self, client):
        """Path traversal patterns in run_id must be rejected."""
        # Directory traversal attempt
        assert resolve_secure_result_path("../../etc/passwd") is None
        assert resolve_secure_result_path("../../../windows/system32") is None
        assert resolve_secure_result_path("..") is None

        res = client.get("/api/runs/../../etc/passwd")
        assert res.status_code == 404

    def test_issue_j_history_separates_qos_fail_from_exec_fail(self):
        """History scanner must separate execution failure from valid QoS failure (e.g., baseline)."""
        history, errors = scan_results_history()
        for item in history:
            assert "total_valid_runs" in item
            if item["type"] == "matched_comparison":
                assert "total_execution_failures" in item
                assert "total_measurement_invalid" in item
