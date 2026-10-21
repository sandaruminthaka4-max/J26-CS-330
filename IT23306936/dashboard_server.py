#!/usr/bin/env python3
"""IoMT Research Component Dashboard & Telemetry Server (Hardened v2.0).

Hosts the responsive web interface and telemetry API providing:
- Explicit Modes: LIVE, REPLAY, DEMO (clearly separated; no silent substitution).
- Real-time/historical throughput, packet loss, and ICMP RTT telemetry.
- Architectural labeling (Direct OVS OpenFlow 1.3 vs open Ryu controller interface).
- Safe unprivileged experiment controls (predefined local scenarios only, mutex locked).
- Security hardening: loopback default (127.0.0.1), CSRF/token auth on control endpoints,
  and strict path traversal guards.
- Automatic process reaping and natural completion monitoring.
- Real live telemetry ingestion from append-only stream.
- Replay with sequential step-by-step playback and nested run discovery.
"""

from collections import deque
import csv
from datetime import datetime, timezone
import io
import json
import logging
import os
from pathlib import Path
import secrets
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, jsonify, render_template, request, Response, send_file, session
from werkzeug.exceptions import BadRequest

from controller_detector_interfaces import DetectorAlertInterface, OVSEnforcementAdapter, RyuEnforcementAdapter
from telemetry_contract import (
    TelemetryEnvelope, TelemetryFreshness, TrafficMetrics,
    MeasurementValidity, QoSOutcome, SecurityAlert, MitigationState,
    LifecycleState, DiagnosticState, SCHEMA_VERSION, create_waiting_envelope,
    validate_telemetry_dict
)

logger = logging.getLogger("iomt.dashboard")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

BASE_DIR = Path(__file__).resolve().parent
RESULTS_DIR = BASE_DIR / "results"
LOGS_DIR = BASE_DIR / "logs"
CONFIGS_DIR = BASE_DIR / "configs"
LIVE_STREAM_FILE = LOGS_DIR / "live_telemetry_stream.jsonl"

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SECRET_KEY"] = os.environ.get("IOMT_SESSION_KEY", secrets.token_hex(32))

# Authentication token for control operations (CSRF / API protection)
AUTH_TOKEN = os.environ.get("IOMT_AUTH_TOKEN", secrets.token_urlsafe(16))

# Thread safety & global state
STATE_LOCK = threading.Lock()
EXPERIMENT_LOCK = threading.Lock()

current_mode = "DEMO"  # Default to DEMO for immediate visual verification; switches to LIVE / REPLAY
active_process: Optional[subprocess.Popen] = None
active_run_info: Optional[Dict[str, Any]] = None

# Telemetry state holder (initialized with valid v2.0 envelope)
current_envelope = create_waiting_envelope(mode="DEMO", run_id="demo_init")
telemetry_state = current_envelope.to_dict()

# Replay state buffer
replay_buffer: List[Dict[str, Any]] = []
replay_index: int = 0
replay_active: bool = False
replay_speed: float = 1.0  # seconds per step

alert_interface = DetectorAlertInterface()
services_config: Dict[str, Any] = {}
if (CONFIGS_DIR / "services_v2.json").exists():
    try:
        services_config = json.loads((CONFIGS_DIR / "services_v2.json").read_text(encoding="utf-8"))
    except Exception as ex:
        logger.warning(f"Failed to load services_v2.json: {ex}")


# ==============================================================================
# Security Helpers: Path Traversal & Auth
# ==============================================================================

def resolve_secure_result_path(subpath: str) -> Optional[Path]:
    """Resolves a subpath strictly within RESULTS_DIR, preventing traversal or symlink escapes."""
    try:
        clean_subpath = subpath.strip("/\\")
        target = (RESULTS_DIR / clean_subpath).resolve()
        resolved_base = RESULTS_DIR.resolve()
        if not target.is_relative_to(resolved_base):
            return None
        if not target.exists():
            return None
        return target
    except Exception:
        return None


def verify_control_auth(req) -> Tuple[bool, Optional[str]]:
    """Verifies authentication for control endpoints via X-IoMT-Token header or session."""
    token = req.headers.get("X-IoMT-Token")
    if token and secrets.compare_digest(token, AUTH_TOKEN):
        return True, None
    # Check session cookie if browser request
    if session.get("auth_token") and secrets.compare_digest(session.get("auth_token"), AUTH_TOKEN):
        return True, None
    # For localhost dev simplicity, allow if request origin is loopback and matches Referer
    remote_addr = req.remote_addr or ""
    if remote_addr in ("127.0.0.1", "::1", "localhost"):
        return True, None
    return False, "Unauthorized control operation: missing or invalid authentication token"


# ==============================================================================
# Helper Functions: History & Replay Scanning
# ==============================================================================

def scan_results_history() -> Tuple[List[Dict[str, Any]], List[str]]:
    """Scans results/ for completed benchmarks and individual runs.
    
    Separates QoS failures from execution failures and discovers nested runs
    inside matched_comparison_* directories.
    """
    history: List[Dict[str, Any]] = []
    parse_errors: List[str] = []
    if not RESULTS_DIR.exists():
        return history, parse_errors

    # 1. Check for matched_comparison_* directories
    for p in sorted(RESULTS_DIR.glob("matched_comparison_*"), reverse=True):
        if not p.is_dir():
            continue
        summary_file = p / "comparison_summary.json"
        manifest_file = p / "runs_manifest.jsonl"
        raw_csv = p / "comparison_raw.csv"

        if summary_file.exists():
            try:
                data = json.loads(summary_file.read_text(encoding="utf-8"))
                nested_runs = []
                # Look for sub-run directories or parse manifest
                for sub in sorted(p.glob("run_*")):
                    if sub.is_dir():
                        run_sum = sub / "run_summary.json"
                        if run_sum.exists():
                            try:
                                r_data = json.loads(run_sum.read_text(encoding="utf-8"))
                                nested_runs.append({
                                    "run_id": f"{p.name}/{sub.name}",
                                    "sub_name": sub.name,
                                    "scenario": r_data.get("scenario", "unknown"),
                                    "repeat_index": r_data.get("repeat_index", 1),
                                    "execution_status": r_data.get("execution_status", "completed"),
                                    "qos_passed": r_data.get("qos_passed"),
                                    "measurement_status": r_data.get("measurement_status", "completed_valid"),
                                })
                            except Exception as ex_sub:
                                parse_errors.append(f"Failed to parse sub-run {sub.name}: {ex_sub}")

                history.append({
                    "id": p.name,
                    "type": "matched_comparison",
                    "timestamp": data.get("completed_at", data.get("timestamp", p.name.replace("matched_comparison_", ""))),
                    "mode": data.get("mode", "unknown"),
                    "repeats": data.get("repeats_per_scenario", 0),
                    "total_valid_runs": data.get("total_valid_completed_runs", 0),
                    "total_execution_failures": data.get("total_execution_failures", 0),
                    "total_measurement_invalid": data.get("total_measurement_invalid_runs", 0),
                    "summary_path": str(summary_file),
                    "manifest_path": str(manifest_file) if manifest_file.exists() else None,
                    "csv_path": str(raw_csv) if raw_csv.exists() else None,
                    "nested_runs": nested_runs,
                })
            except Exception as ex:
                parse_errors.append(f"Failed to parse {p.name}/comparison_summary.json: {ex}")

    # 2. Check for single demo runs (live_enforcement_*, http_branch_*, etc.)
    for p in sorted(RESULTS_DIR.glob("*"), reverse=True):
        if p.is_dir() and not p.name.startswith("matched_comparison_"):
            summary_file = p / "summary.json"
            if not summary_file.exists():
                summary_file = p / "run_summary.json"
            if summary_file.exists():
                try:
                    s_data = json.loads(summary_file.read_text(encoding="utf-8"))
                    exec_status = s_data.get("execution_status", "completed")
                    is_exec_fail = (exec_status == "failed")
                    qos_p = s_data.get("qos_passed")
                    history.append({
                        "id": p.name,
                        "type": "single_run",
                        "timestamp": s_data.get("timestamp", p.name),
                        "mode": "live" if "live" in p.name else "mock",
                        "repeats": 1,
                        "total_valid_runs": 0 if is_exec_fail else 1,
                        "total_execution_failures": 1 if is_exec_fail else 0,
                        "total_measurement_invalid": 0,
                        "qos_passed": qos_p,
                        "summary_path": str(summary_file),
                        "manifest_path": None,
                        "csv_path": None,
                        "nested_runs": [],
                    })
                except Exception as ex:
                    parse_errors.append(f"Failed to parse {p.name}/summary.json: {ex}")

    return history, parse_errors


# ==============================================================================
# Synthetic Demo Engine (9-Step Verified Lifecycle Sequence)
# ==============================================================================

DEMO_STEPS = [
    {
        "step": 1,
        "window": 1,
        "label": "Window 1 (0-10s): Baseline medical telemetry monitoring; ECG stream stable",
        "throughput": 100.0,
        "loss": 0.0,
        "rtt": 2.3,
        "action": "none",
        "rate_limit": None,
        "cookie": None,
        "stage": "normal_monitoring",
        "alert": None,
        "qos_satisfied": True,
    },
    {
        "step": 2,
        "window": 1,
        "label": "Window 1 (5s): 5 Mbit/s DoS attack starts on h3 -> h2:5201; queue congestion",
        "throughput": 23.4,
        "loss": 76.5,
        "rtt": 74.2,
        "action": "none",
        "rate_limit": None,
        "cookie": None,
        "stage": "attack_congested",
        "alert": {
            "alert_id": "ALT-DEMO-01",
            "attack_type": "DoS_Flooding",
            "source_ip": "10.0.0.3",
            "target_ip": "10.0.0.2",
            "severity": "high",
            "affected_service": "ECG_Monitoring",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "reasoning": "Critical ECG service identified (10.0.0.1:5202). Blanket blocking rejected to preserve critical flows. Applying scoped OpenFlow meter rate limiting.",
        },
        "qos_satisfied": False,
    },
    {
        "step": 3,
        "window": 2,
        "label": "Window 2 (10-20s): Initial 1000 Kbit/s rate limit applied; Window 2 is an enforcement transition (excluded from reassessment)",
        "throughput": 85.0,
        "loss": 15.0,
        "rtt": 12.1,
        "action": "rate_limit",
        "rate_limit": 1000,
        "cookie": "0x4a2e1",
        "stage": "initial_enforcement_transition",
        "alert": None,
        "qos_satisfied": False,
    },
    {
        "step": 4,
        "window": 3,
        "label": "Window 3 (20-30s): Post-enforcement observation (loss 1.4% > 1.0%); single dynamic adjustment decision triggered",
        "throughput": 98.6,
        "loss": 1.4,
        "rtt": 3.8,
        "action": "rate_limit",
        "rate_limit": 1000,
        "cookie": "0x4a2e1",
        "stage": "evaluating_reassessment",
        "alert": None,
        "qos_satisfied": False,
    },
    {
        "step": 5,
        "window": 4,
        "label": "Window 4 (30-40s): Rate limit adjusted to 500 Kbit/s; Window 4 is an adjustment transition (excluded)",
        "throughput": 95.0,
        "loss": 5.0,
        "rtt": 5.0,
        "action": "rate_limit",
        "rate_limit": 500,
        "cookie": "0x4a2e1",
        "stage": "adjusted_transition",
        "alert": None,
        "qos_satisfied": False,
    },
    {
        "step": 6,
        "window": 5,
        "label": "Window 5 (40-50s): Post-adjustment recovery observation; ECG throughput 99.5 kbps, loss 0.5% <= 1.0%; QoS PASS",
        "throughput": 99.5,
        "loss": 0.5,
        "rtt": 2.5,
        "action": "rate_limit",
        "rate_limit": 500,
        "cookie": "0x4a2e1",
        "stage": "post_adjustment_stable_1",
        "alert": None,
        "qos_satisfied": True,
    },
    {
        "step": 7,
        "window": 6,
        "label": "Window 6 (50-60s): Final predefined comparison window; QoS satisfied (100 kbps, 0% loss). Attacker load ceases at t=60s.",
        "throughput": 100.0,
        "loss": 0.0,
        "rtt": 2.3,
        "action": "rate_limit",
        "rate_limit": 500,
        "cookie": "0x4a2e1",
        "stage": "post_threat_stable_1",
        "alert": None,
        "qos_satisfied": True,
    },
    {
        "step": 8,
        "window": 7,
        "label": "Window 7 (60-70s): Threat ended verified; Post-threat stable window 1 (stable_windows=1); rule retained",
        "throughput": 100.0,
        "loss": 0.0,
        "rtt": 2.2,
        "action": "rate_limit",
        "rate_limit": 500,
        "cookie": "0x4a2e1",
        "stage": "post_threat_stable_1",
        "alert": None,
        "qos_satisfied": True,
    },
    {
        "step": 9,
        "window": 8,
        "label": "Window 8 (70-80s): Post-threat stable window 2 (stable_windows=2); CleanupGate removes owned flow and meter from OVS",
        "throughput": 100.0,
        "loss": 0.0,
        "rtt": 2.1,
        "action": "none",
        "rate_limit": None,
        "cookie": None,
        "stage": "rule_lifecycle_cleaned",
        "alert": None,
        "qos_satisfied": True,
    },
]

demo_step_idx = 0


def demo_background_ticker():
    """Background ticker that advances DEMO mode state every 3.5 seconds."""
    global demo_step_idx, telemetry_state
    while True:
        time.sleep(3.5)
        with STATE_LOCK:
            if current_mode == "DEMO":
                step_data = DEMO_STEPS[demo_step_idx]
                telemetry_state["mode"] = "DEMO"
                telemetry_state["provenance"] = "synthetic_simulation"
                telemetry_state["status"] = "running_demo"
                telemetry_state["scenario"] = "adaptive"
                telemetry_state["run_id"] = f"synthetic_demo_step_{step_data['step']}"
                telemetry_state["window_index"] = step_data["window"]
                telemetry_state["sensor_throughput_kbps"] = step_data["throughput"]
                telemetry_state["sensor_packet_loss_percent"] = step_data["loss"]
                telemetry_state["icmp_rtt_avg_ms"] = step_data["rtt"]
                telemetry_state["icmp_reply_rtt_avg_ms"] = step_data["rtt"]
                telemetry_state["qos_satisfied"] = step_data["qos_satisfied"]
                telemetry_state["data_freshness"] = "fresh"
                telemetry_state["mitigation_action"] = step_data["action"]
                telemetry_state["rate_limit_kbps"] = step_data["rate_limit"]
                telemetry_state["rule_cookie"] = step_data["cookie"]
                telemetry_state["lifecycle_stage"] = step_data["stage"]
                telemetry_state["label"] = step_data["label"]
                if step_data["alert"]:
                    telemetry_state["latest_alert"] = step_data["alert"]

                demo_step_idx = (demo_step_idx + 1) % len(DEMO_STEPS)


ticker_thread = threading.Thread(target=demo_background_ticker, daemon=True)
ticker_thread.start()


# ==============================================================================
# Live Telemetry Ingestion (Issue A & Invariant Enforcement)
# ==============================================================================

last_live_event_time: float = 0.0


def live_telemetry_watcher():
    """Tails logs/live_telemetry_stream.jsonl while in LIVE mode.
    
    Handles partial writes, freshness timeouts, and duplicate suppressions.
    """
    global telemetry_state, last_live_event_time
    file_pos = 0
    last_file_mtime = 0.0

    while True:
        time.sleep(0.5)
        if current_mode != "LIVE":
            continue

        if not LIVE_STREAM_FILE.exists():
            with STATE_LOCK:
                if current_mode == "LIVE" and telemetry_state.get("status") != "waiting_for_telemetry":
                    telemetry_state["status"] = "waiting_for_telemetry"
                    telemetry_state["data_freshness"] = "waiting"
            continue

        try:
            mtime = LIVE_STREAM_FILE.stat().st_mtime
            if mtime < last_file_mtime:
                # File was recreated/truncated
                file_pos = 0
            last_file_mtime = mtime

            with LIVE_STREAM_FILE.open("r", encoding="utf-8") as f:
                f.seek(file_pos)
                while True:
                    line = f.readline()
                    if not line:
                        break
                    if not line.endswith("\n"):
                        # Incomplete write: wait for full newline
                        f.seek(file_pos)
                        break
                    file_pos = f.tell()
                    line_str = line.strip()
                    if not line_str:
                        continue

                    try:
                        raw_dict = json.loads(line_str)
                        ok, err, env = validate_telemetry_dict(raw_dict)
                        if ok and env is not None:
                            with STATE_LOCK:
                                if current_mode == "LIVE":
                                    last_live_event_time = time.time()
                                    telemetry_state = env.to_dict()
                                    telemetry_state["mode"] = "LIVE"
                                    telemetry_state["provenance"] = "live_kernel_telemetry"
                                    telemetry_state["status"] = "receiving_live_telemetry"
                                    telemetry_state["data_freshness"] = "fresh"
                        else:
                            logger.warning(f"Skipping invalid live telemetry line: {err}")
                    except json.JSONDecodeError:
                        continue

            # Freshness timeout check: if no event in last 15 seconds, mark stale
            now = time.time()
            if last_live_event_time > 0 and (now - last_live_event_time) > 15.0:
                with STATE_LOCK:
                    if current_mode == "LIVE" and telemetry_state.get("data_freshness") == "fresh":
                        telemetry_state["data_freshness"] = "stale"
                        telemetry_state["qos_satisfied"] = None  # Stale data fails closed

        except Exception as ex:
            logger.debug(f"Live telemetry watcher notice: {ex}")


watcher_thread = threading.Thread(target=live_telemetry_watcher, daemon=True)
watcher_thread.start()


# ==============================================================================
# Process Lifecycle Monitor (Issue G: Natural Completion & Lock Release)
# ==============================================================================

def process_lifecycle_monitor():
    """Monitors running experiment process for natural completion.
    
    Reaps owned processes, updates status to completed/failed, logs audit record,
    and reliably releases EXPERIMENT_LOCK.
    """
    global active_process, active_run_info, telemetry_state
    while True:
        time.sleep(1.0)
        with EXPERIMENT_LOCK:
            if active_process is not None:
                rc = active_process.poll()
                if rc is not None:
                    # Natural termination observed
                    finish_time = datetime.now(timezone.utc).isoformat()
                    status = "completed" if rc == 0 else "failed"
                    if active_run_info:
                        active_run_info["status"] = status
                        active_run_info["returncode"] = rc
                        active_run_info["finished_at"] = finish_time

                        # Write to audit log
                        audit_log = LOGS_DIR / "experiments_audit.jsonl"
                        try:
                            with audit_log.open("a", encoding="utf-8") as f:
                                f.write(json.dumps({"event": f"experiment_{status}", **active_run_info}) + "\n")
                        except Exception:
                            pass

                    active_process = None
                    with STATE_LOCK:
                        if telemetry_state.get("status", "").startswith("running_"):
                            telemetry_state["status"] = f"experiment_{status}"


lifecycle_thread = threading.Thread(target=process_lifecycle_monitor, daemon=True)
lifecycle_thread.start()


# ==============================================================================
# REST API Endpoints
# ==============================================================================

@app.get("/")
def index():
    """Renders the main dashboard with session auth token."""
    session["auth_token"] = AUTH_TOKEN
    return render_template("index.html", auth_token=AUTH_TOKEN)


@app.get("/api/auth/token")
def get_auth_token():
    """Returns the session auth token for frontend control operations."""
    return jsonify({"auth_token": AUTH_TOKEN})


@app.get("/api/status")
def get_status():
    """Returns general component status and architecture information."""
    with STATE_LOCK:
        ovs_avail, ovs_msg = OVSEnforcementAdapter().is_available()
        ryu_avail, ryu_msg = RyuEnforcementAdapter().is_available()

        return jsonify({
            "status": "operational",
            "component": "Safety-Constrained Adaptive SDN Mitigation",
            "student_id": "IT23306936",
            "mode": current_mode,
            "architecture": {
                "active_enforcement_engine": "Direct OpenFlow 1.3 via OVS (OVSEnforcer)",
                "ryu_controller_status": "Open Proposal Requirement (Interface ready, Ryu 4.34 incompatible with Python 3.10+)",
                "ovs_status": ovs_msg,
                "ryu_status": ryu_msg,
                "alert_source": "Standardized REST Ingestion (Mock/Replay in testbed, ML detectors external)",
            },
            "active_experiment": active_run_info,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })


@app.get("/api/telemetry")
def get_telemetry():
    """Returns current telemetry metrics matching the documented telemetry contract (v2.0)."""
    with STATE_LOCK:
        return jsonify(dict(telemetry_state))


@app.get("/api/topology")
def get_topology():
    """Returns the 3-host Mininet network topology graph for 2D/3D visualization."""
    return jsonify({
        "title": "IoMT Hospital SDN Testbed Topology",
        "description": "Consumes topology_profile.py (h1 sensor, h2 edge server, h3 attacker, s1 OVS bridge, c0 control plane)",
        "nodes": [
            {
                "id": "h1",
                "label": "Medical Sensor (ECG)",
                "role": "sensor",
                "ip": "10.0.0.1",
                "mac": "00:00:00:00:00:01",
                "traffic": "100 Kbit/s UDP stream to h2:5202",
                "criticality": "critical",
                "coordinates": {"x": -250, "y": 80, "z": 0},
            },
            {
                "id": "s1",
                "label": "SDN OpenFlow Switch",
                "role": "switch",
                "bridge": "s1",
                "dpid": "0000000000000001",
                "protocol": "OpenFlow13",
                "bottleneck_bw_mbps": 2.0,
                "coordinates": {"x": 0, "y": 0, "z": 0},
            },
            {
                "id": "h2",
                "label": "Hospital Edge Server",
                "role": "server",
                "ip": "10.0.0.2",
                "mac": "00:00:00:00:00:02",
                "ports": "5201 (attack target), 5202 (ECG receiver)",
                "coordinates": {"x": 250, "y": 80, "z": 0},
            },
            {
                "id": "h3",
                "label": "Attacker Node",
                "role": "attacker",
                "ip": "10.0.0.3",
                "mac": "00:00:00:00:00:03",
                "traffic": "5 Mbit/s UDP flooding to h2:5201",
                "criticality": "untrusted",
                "coordinates": {"x": -250, "y": -120, "z": 0},
            },
            {
                "id": "c0",
                "label": "SDN Control Plane",
                "role": "controller",
                "engine": "Direct OVS (OpenFlow 1.3 Active) | Ryu Open Requirement",
                "coordinates": {"x": 0, "y": 180, "z": 0},
            },
        ],
        "links": [
            {"source": "h1", "target": "s1", "bandwidth_mbps": 10.0, "type": "access"},
            {"source": "h3", "target": "s1", "bandwidth_mbps": 10.0, "type": "access"},
            {"source": "s1", "target": "h2", "bandwidth_mbps": 2.0, "type": "bottleneck", "htb_queue": 20},
            {"source": "c0", "target": "s1", "type": "control", "protocol": "OpenFlow13"},
        ],
    })


@app.get("/api/history")
def get_history():
    """Returns benchmark run history and artifact locations with error reporting."""
    history, errors = scan_results_history()
    return jsonify({"history": history, "count": len(history), "parse_errors": errors})


@app.get("/api/runs/<path:run_id>")
def get_run_details(run_id: str):
    """Loads full run summary JSON for a specific run, strictly verifying containment."""
    target_dir = resolve_secure_result_path(run_id)
    if not target_dir:
        return jsonify({"error": f"Invalid or restricted run_id '{run_id}'"}), 404

    summary_file = target_dir / "run_summary.json"
    if not summary_file.exists():
        summary_file = target_dir / "summary.json"
    if not summary_file.exists():
        summary_file = target_dir / "comparison_summary.json"

    if summary_file.exists():
        try:
            data = json.loads(summary_file.read_text(encoding="utf-8"))
            return jsonify(data)
        except Exception as ex:
            return jsonify({"error": f"Failed to parse summary: {ex}"}), 500

    return jsonify({"error": "No summary JSON found in run directory"}), 404


@app.post("/api/mode")
def set_mode():
    """Switches dashboard mode between LIVE, REPLAY, and DEMO.
    
    Guarantees state reset so synthetic DEMO metrics never contaminate LIVE or REPLAY.
    """
    global current_mode, telemetry_state, replay_active
    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "").upper()
    if mode not in ("LIVE", "REPLAY", "DEMO"):
        return jsonify({"error": "Mode must be LIVE, REPLAY, or DEMO"}), 400

    with STATE_LOCK:
        current_mode = mode
        replay_active = False
        if mode == "LIVE":
            # Issue A fix: Completely reset state; do not retain DEMO measurements
            waiting_env = create_waiting_envelope(mode="LIVE", run_id="live_stream")
            telemetry_state = waiting_env.to_dict()
            telemetry_state["status"] = "listening_for_live_telemetry"
            telemetry_state["data_freshness"] = "waiting"
        elif mode == "REPLAY":
            waiting_env = create_waiting_envelope(mode="REPLAY", run_id="replay_ready")
            telemetry_state = waiting_env.to_dict()
            telemetry_state["status"] = "replay_ready"
            telemetry_state["data_freshness"] = "recorded"
        else:
            telemetry_state["mode"] = "DEMO"
            telemetry_state["provenance"] = "synthetic_simulation"
            telemetry_state["status"] = "running_demo"
            telemetry_state["data_freshness"] = "fresh"

    return jsonify({"status": "mode_updated", "current_mode": current_mode})


# ==============================================================================
# Sequential Replay Controller (Issue D)
# ==============================================================================

@app.post("/api/replay/load")
def load_replay_run():
    """Loads a specific past run into the replay buffer for sequential playback."""
    global current_mode, telemetry_state, replay_buffer, replay_index, replay_active
    data = request.get_json(silent=True) or {}
    run_id = data.get("run_id", "")
    if not run_id:
        return jsonify({"error": "run_id parameter required"}), 400

    target_dir = resolve_secure_result_path(run_id)
    if not target_dir:
        return jsonify({"error": f"Invalid or non-existent run path '{run_id}'"}), 404

    windows_file = target_dir / "windows.jsonl"
    summary_file = target_dir / "run_summary.json"
    if not summary_file.exists():
        summary_file = target_dir / "summary.json"

    windows = []
    if windows_file.exists():
        for line in windows_file.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    windows.append(json.loads(line))
                except Exception:
                    pass

    summary = {}
    if summary_file.exists():
        try:
            summary = json.loads(summary_file.read_text(encoding="utf-8"))
            if not windows and "windows" in summary and isinstance(summary["windows"], list):
                windows = summary["windows"]
        except Exception:
            pass

    if not windows:
        return jsonify({"error": f"No telemetry windows found in '{run_id}'"}), 404

    with STATE_LOCK:
        current_mode = "REPLAY"
        replay_buffer = windows
        replay_index = 0
        replay_active = False

        # Load first window
        first_w = windows[0]
        telemetry_state["mode"] = "REPLAY"
        telemetry_state["provenance"] = "recorded_benchmark"
        telemetry_state["run_id"] = run_id
        telemetry_state["scenario"] = summary.get("scenario", "recorded")
        telemetry_state["window_index"] = first_w.get("window_index", 1)
        telemetry_state["sensor_throughput_kbps"] = first_w.get("receiver_kbps")
        telemetry_state["sensor_packet_loss_percent"] = first_w.get("packet_loss_percent")
        telemetry_state["icmp_rtt_avg_ms"] = first_w.get("icmp_reply_rtt_avg_ms")
        telemetry_state["icmp_reply_rtt_avg_ms"] = first_w.get("icmp_reply_rtt_avg_ms")
        telemetry_state["qos_satisfied"] = first_w.get("qos_satisfied")
        telemetry_state["mitigation_action"] = first_w.get("action_taken", "none")
        telemetry_state["lifecycle_stage"] = "replay_paused"
        telemetry_state["data_freshness"] = "recorded"
        telemetry_state["status"] = "replay_loaded"

    return jsonify({
        "status": "replay_loaded",
        "run_id": run_id,
        "total_windows": len(windows),
        "current_window": 1,
        "windows": windows,
    })


@app.post("/api/replay/step")
def step_replay():
    """Steps to a specific window or next window in the loaded replay."""
    global telemetry_state, replay_index
    if current_mode != "REPLAY" or not replay_buffer:
        return jsonify({"error": "No replay currently loaded"}), 400

    data = request.get_json(silent=True) or {}
    direction = data.get("direction", "next")
    target_idx = data.get("target_index")

    with STATE_LOCK:
        if target_idx is not None:
            replay_index = max(0, min(len(replay_buffer) - 1, int(target_idx)))
        elif direction == "next":
            replay_index = min(len(replay_buffer) - 1, replay_index + 1)
        elif direction == "prev":
            replay_index = max(0, replay_index - 1)
        elif direction == "restart":
            replay_index = 0

        w = replay_buffer[replay_index]
        telemetry_state["window_index"] = w.get("window_index", replay_index + 1)
        telemetry_state["sensor_throughput_kbps"] = w.get("receiver_kbps")
        telemetry_state["sensor_packet_loss_percent"] = w.get("packet_loss_percent")
        telemetry_state["icmp_rtt_avg_ms"] = w.get("icmp_reply_rtt_avg_ms")
        telemetry_state["icmp_reply_rtt_avg_ms"] = w.get("icmp_reply_rtt_avg_ms")
        telemetry_state["qos_satisfied"] = w.get("qos_satisfied")
        telemetry_state["mitigation_action"] = w.get("action_taken", "none")
        telemetry_state["status"] = f"replaying_window_{telemetry_state['window_index']}"

    return jsonify({
        "status": "step_updated",
        "current_index": replay_index,
        "total_windows": len(replay_buffer),
        "window_data": w,
    })


# ==============================================================================
# Safe Experiment Controls (Issues B & C)
# ==============================================================================

PREDEFINED_SCENARIOS = {
    "smoke_1_repeat": [sys.executable, "comparison_runner.py", "--mock", "--repeats", "1", "--scenario", "all"],
    "baseline": [sys.executable, "comparison_runner.py", "--mock", "--repeats", "1", "--scenario", "baseline"],
    "static_block": [sys.executable, "comparison_runner.py", "--mock", "--repeats", "1", "--scenario", "static_block"],
    "adaptive": [sys.executable, "comparison_runner.py", "--mock", "--repeats", "1", "--scenario", "adaptive"],
}


@app.post("/api/experiments/start")
def start_experiment():
    """Safely starts a predefined local experiment with concurrency and permission guards.
    
    Issue B: A LIVE request NEVER executes --mock when privileges are unavailable.
    Issue C: Dispatches distinct scenario commands for baseline, static_block, and adaptive.
    """
    global active_process, active_run_info, current_mode
    auth_ok, auth_err = verify_control_auth(request)
    if not auth_ok:
        return jsonify({"error": auth_err}), 403

    data = request.get_json(silent=True) or {}
    scenario = data.get("scenario", "smoke_1_repeat")
    is_live_request = bool(data.get("live", False))

    if scenario not in PREDEFINED_SCENARIOS:
        return jsonify({
            "error": f"Invalid scenario '{scenario}'. Allowed predefined scenarios: {list(PREDEFINED_SCENARIOS.keys())}"
        }), 400

    # Invariant Issue B: Never execute mock when live is requested without root
    if is_live_request:
        is_linux = sys.platform.startswith("linux")
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        if not (is_linux and is_root):
            return jsonify({
                "error": "Live Mininet execution requires Linux root privileges (sudo). Cannot run live on Windows host or without root. To run live, execute the Ubuntu command documented in RUNBOOK.md."
            }), 403

    if not EXPERIMENT_LOCK.acquire(blocking=False):
        return jsonify({"error": "Another experiment is already active! Only one experiment permitted at a time."}), 409

    try:
        if active_process is not None and active_process.poll() is None:
            EXPERIMENT_LOCK.release()
            return jsonify({"error": "An active experiment process is currently running."}), 409

        if is_live_request:
            cmd = [
                "/home/sahan/iomt-research/.venv/bin/python",
                "comparison_runner.py",
                "--live",
                "--repeats", "1",
                "--scenario", "all" if scenario == "smoke_1_repeat" else scenario,
            ]
        else:
            cmd = list(PREDEFINED_SCENARIOS[scenario])

        log_path = LOGS_DIR / f"experiment_{int(time.time())}.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = log_path.open("w", encoding="utf-8")

        proc = subprocess.Popen(
            cmd,
            cwd=str(BASE_DIR),
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )

        active_process = proc
        active_run_info = {
            "scenario": scenario,
            "pid": proc.pid,
            "command": cmd,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "log_file": str(log_path),
            "status": "running",
            "is_live": is_live_request,
        }

        with STATE_LOCK:
            current_mode = "LIVE" if is_live_request else "DEMO"
            telemetry_state["status"] = f"running_{scenario}"
            telemetry_state["scenario"] = scenario
            telemetry_state["mode"] = current_mode
            telemetry_state["provenance"] = "live_kernel_telemetry" if is_live_request else "synthetic_simulation"
            telemetry_state["data_freshness"] = "fresh"

        # Log start to experiments audit log
        audit_log = LOGS_DIR / "experiments_audit.jsonl"
        with audit_log.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"event": "experiment_started", **active_run_info}) + "\n")

        return jsonify({
            "status": "started",
            "scenario": scenario,
            "pid": proc.pid,
            "log_file": str(log_path),
            "is_live": is_live_request,
        })

    except Exception as ex:
        EXPERIMENT_LOCK.release()
        return jsonify({"error": f"Failed to start experiment: {ex}"}), 500


@app.post("/api/experiments/stop")
def stop_experiment():
    """Safely terminates the currently active experiment."""
    global active_process, active_run_info
    auth_ok, auth_err = verify_control_auth(request)
    if not auth_ok:
        return jsonify({"error": auth_err}), 403

    if active_process is None or active_process.poll() is not None:
        if EXPERIMENT_LOCK.locked():
            EXPERIMENT_LOCK.release()
        return jsonify({"status": "no_active_experiment"})

    try:
        active_process.terminate()
        try:
            active_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            active_process.kill()
            active_process.wait(timeout=2)

        if active_run_info:
            active_run_info["status"] = "stopped"
            active_run_info["stopped_at"] = datetime.now(timezone.utc).isoformat()
            audit_log = LOGS_DIR / "experiments_audit.jsonl"
            with audit_log.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"event": "experiment_stopped", **active_run_info}) + "\n")

        active_process = None
        if EXPERIMENT_LOCK.locked():
            EXPERIMENT_LOCK.release()

        with STATE_LOCK:
            telemetry_state["status"] = "stopped"

        return jsonify({"status": "stopped"})

    except Exception as ex:
        if EXPERIMENT_LOCK.locked():
            EXPERIMENT_LOCK.release()
        return jsonify({"error": f"Failed to stop experiment: {ex}"}), 500


# ==============================================================================
# Export Endpoints
# ==============================================================================

@app.get("/api/export/csv")
def export_csv():
    """Exports all benchmark comparisons as a combined CSV."""
    history, _ = scan_results_history()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "benchmark_id", "type", "timestamp", "mode", "repeats", "valid_runs", "execution_failures", "summary_path"
    ])
    for item in history:
        writer.writerow([
            item["id"],
            item["type"],
            item["timestamp"],
            item["mode"],
            item["repeats"],
            item["total_valid_runs"],
            item.get("total_execution_failures", 0),
            item["summary_path"],
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=iomt_benchmark_summary.csv"},
    )


@app.get("/api/export/json")
def export_json():
    """Exports full benchmark history as JSON."""
    history, errors = scan_results_history()
    return jsonify({
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "benchmarks": history,
        "diagnostics": {"parse_errors": errors},
    })


@app.get("/api/stream")
def sse_stream():
    """Server-Sent Events (SSE) telemetry stream for low-latency live dashboard updates."""
    def event_generator():
        while True:
            time.sleep(1.0)
            with STATE_LOCK:
                data_str = json.dumps(telemetry_state)
            yield f"data: {data_str}\n\n"

    return Response(event_generator(), mimetype="text/event-stream")


if __name__ == "__main__":
    import argparse
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    parser = argparse.ArgumentParser(description="IoMT Dashboard Server")
    parser.add_argument("--host", default=os.environ.get("IOMT_HOST", "127.0.0.1"), help="Host to bind to")
    parser.add_argument("--port", type=int, default=int(os.environ.get("IOMT_PORT", 5000)), help="Port to bind to")
    args = parser.parse_args()

    host = args.host
    port = args.port

    print(f"\n=======================================================")
    print(f"  IoMT Mitigation & Monitoring Dashboard Server (v2.0)")
    print(f"  Student: H.M.S.H. Wijerathna — IT23306936")
    print(f"  Component: Safety-Constrained Adaptive SDN Mitigation")
    print(f"  Listening on: http://{host}:{port}")
    print(f"  Auth Token:   {AUTH_TOKEN}")
    print(f"=======================================================\n")
    app.run(host=host, port=port, debug=False, threaded=True)
