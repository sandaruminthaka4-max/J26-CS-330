#!/usr/bin/env python3
"""Two-Host Pilot Live Periodic Adjustment Branch Evaluation.

Evaluates dynamic mitigation reassessment driven strictly by live measured receiver QoS on Mininet.
Uses a two-host pilot topology (h1 sensor + load sender, h2 edge receiver) with dummy alerts
and Flask test client.

Scope & Boundary Limitations:
- TWO-HOST PILOT ONLY: Evaluates receiver QoS reassessment on a 2-host topology (h1, h2, s1).
  Does NOT use the finalized three-host (h3 attacker) topology profile.
- PILOT INSTRUMENTATION: Uses dummy alert submission via Flask test-client; does NOT claim
  real anomaly detector integration, HTTP service validation, or Ryu controller integration.
- EMPIRICAL EVALUATION & LOAD UNCONFOUNDING:
  * Initial DoS rate limit receives an explicit experimental override to 1800 Kbit/s (copied plan;
    original API recommendation is strictly preserved).
  * Load generator (5 Mbit/s) is configured to run for 70s to remain active throughout all evaluated
    windows (sensor runs for 60s). Actual process start/end times are recorded.
  * Any window overlapping or following load cessation is marked confounded/invalid; recovery is
    never attributed to mitigation.
  * Verdicts cleanly separate:
    - adjustment command executed (bool)
    - complete post-adjustment window evaluated (bool)
    - final measured QoS passed or failed (bool)
    Verdict is reported as "not_exercised_measured_qos_passed", "exercised_and_qos_recovered",
    "exercised_but_qos_unrecovered", or "inconclusive". "exercised" alone never implies recovery.
    If no eligible final window exists, reports "inconclusive".
- COLLISION GUARD:
  * Refuses live startup if OVS bridge 's1' already exists.
  * OVS inspection errors are treated as fatal errors, never proof of bridge absence.
- LOG & ARTIFACT PRESERVATION:
  * Preserves separate sensor and load client JSON stdout/stderr, receiver stream logs,
    server logs, OVS flow/meter evidence after initial enforcement and adjustment,
    and guaranteed summary.json on success and failure.

Usage:
    Live testbed (Ubuntu VM with root):
        sudo PYTHONPATH=/usr/lib/python3/dist-packages /home/sahan/iomt-research/.venv/bin/python periodic_adjustment_live_demo.py --live
    Offline mock verification:
        python3 periodic_adjustment_live_demo.py --mock
"""

import argparse
import copy
import json
import os
import subprocess
import sys
import threading
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
RESULTS_DIR = BASE / "results"

from alert_api_v2 import create_app
from context_store_v2 import ContextStore
from live_qos_bridge_v2 import LiveQoSBridge
from ovs_enforcement_v2 import OVSEnforcer
from receiver_callback_monitor import ReceiverStreamMonitor


def run_live_adjustment_demo(live=False, mock=False, mock_scenario="normal"):
    if not live and not mock:
        raise ValueError("Must specify either --live or --mock explicitly")
    if live and mock:
        raise ValueError("Cannot specify both --live and --mock")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = RESULTS_DIR / f"periodic_adjustment_live_{timestamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    mode_label = "live_mininet_ovs" if live else f"mock_offline_{mock_scenario}"
    print("=== Two-Host Pilot Live Periodic Adjustment Branch Evaluation ===")
    print(f"Mode:             {mode_label}")
    print(f"Output Directory: {out_dir}")

    services = json.loads((BASE / "configs/services_v2.json").read_text())
    current_sim_time = [10000.0]
    clock_fn = (lambda: current_sim_time[0]) if mock else time.monotonic
    store = ContextStore(clock=clock_fn)
    app = create_app(out_dir / "api_events.jsonl", store.provide)
    client = app.test_client()
    enforcer = OVSEnforcer(services)

    action_state = {
        "stage": "pending",
        "completed_at": None,
        "original_api_recommendation": None,
        "initial_override_plan": None,
        "adjusted_enforcement_plan": None,
        "adjustment_command_executed": False,
        "post_adjustment_window_evaluated": False,
        "final_measured_qos_passed": None,
        "branch_verdict": "inconclusive",
        "verdict_details": {},
    }

    timing_holder = {
        "sensor_launch_mono": None,
        "sensor_launch_unix": None,
        "sensor_ended_mono": None,
        "sensor_ended_unix": None,
        "load_started_mono": None,
        "load_started_unix": None,
        "load_ended_mono": None,
        "load_ended_unix": None,
    }

    results = []
    processes = []
    open_file_handles = []
    net = None
    stop_signal = threading.Event()
    callback_error = [None]
    load_client = None

    summary_data = {
        "timestamp": timestamp,
        "mode": mode_label,
        "test_name": "two_host_pilot_periodic_adjustment_live_evaluation",
        "status": "in_progress",
        "error": None,
        "traceback": None,
        "scope_description": (
            "Two-host pilot evaluating dynamic mitigation reassessment driven strictly by live measured receiver QoS. "
            "Evaluates whether degraded empirical QoS triggers rate-limit adjustment from 1800 to 500 Kbit/s. "
            "Pilot run with dummy alerts and Flask client; does not claim final h3 topology or Ryu integration."
        ),
        "branch_verdict": "inconclusive",
        "adjustment_command_executed": False,
        "post_adjustment_window_evaluated": False,
        "final_measured_qos_passed": None,
        "verdict_details": {},
        "process_observations": {},
        "actual_sender_rates": {
            "sensor_sent_kbps": None,
            "load_sent_kbps": None,
        },
        "preserved_raw_logs": {
            "sensor_client_json": str(out_dir / "sensor_client.json"),
            "sensor_client_stderr": str(out_dir / "sensor_client_stderr.txt"),
            "load_client_json": str(out_dir / "load.json"),
            "load_client_stderr": str(out_dir / "load_stderr.txt"),
            "receiver_jsonl": str(out_dir / "receiver.jsonl"),
            "receiver_stderr": str(out_dir / "receiver_stderr.txt"),
            "load_server_stdout": str(out_dir / "load_server_stdout.txt"),
            "load_server_stderr": str(out_dir / "load_server_stderr.txt"),
            "api_events": str(out_dir / "api_events.jsonl"),
            "window_decisions": str(out_dir / "window_decisions.jsonl"),
            "summary_json": str(out_dir / "summary.json"),
        },
        "total_windows_observed": 0,
        "windows": [],
        "cleanup_outcome": {},
    }

    try:
        if live:
            # 1. Collision guard: inspect s1 existence. Treat inspection errors as errors, never proof of absence.
            try:
                check_s1 = subprocess.run(
                    ["ovs-vsctl", "br-exists", "s1"],
                    capture_output=True,
                    text=True,
                )
            except FileNotFoundError as ex:
                raise RuntimeError(
                    f"OVS inspection error: 'ovs-vsctl' not found on system ({ex}). "
                    "Cannot assume bridge 's1' is absent."
                )
            except Exception as ex:
                raise RuntimeError(
                    f"OVS inspection error checking 's1' existence ({ex}). "
                    "Cannot assume bridge 's1' is absent."
                )

            if check_s1.returncode == 0:
                raise RuntimeError(
                    "Collision guard: OVS bridge 's1' already exists on system. "
                    "Refusing live startup to protect existing testbed/bridge resources. "
                    "Do NOT delete existing bridges or execute global Mininet cleanup; "
                    "verify and clean testbed resources explicitly."
                )
            elif check_s1.returncode != 2:
                raise RuntimeError(
                    f"OVS inspection error checking 's1' existence (exit code {check_s1.returncode}): "
                    f"{check_s1.stderr.strip() or check_s1.stdout.strip()}. "
                    "Cannot assume bridge is absent."
                )

            sys.path.append("/usr/lib/python3/dist-packages")
            try:
                from mininet.net import Mininet
                from mininet.node import OVSBridge
                from mininet.link import TCLink
            except ImportError as e:
                raise RuntimeError(
                    f"Mininet import failed: {e}. "
                    "Ensure Mininet is installed at /usr/lib/python3/dist-packages."
                )

            print("Starting Mininet topology (h1, h2, s1)...")
            net = Mininet(controller=None, switch=OVSBridge, link=TCLink)
            h1 = net.addHost("h1", ip="10.0.0.1/8")
            h2 = net.addHost("h2", ip="10.0.0.2/8")
            s1 = net.addSwitch("s1")
            net.addLink(h1, s1)
            net.addLink(h2, s1, bw=2, max_queue_size=20, use_htb=True)
            net.start()

            if net.pingAll() != 0:
                raise RuntimeError("Initial Mininet connectivity check failed")

            # 2. Prepare file handles for servers and clients
            raw_receiver = (out_dir / "receiver.jsonl").open("w")
            receiver_err = (out_dir / "receiver_stderr.txt").open("w")
            load_server_out = (out_dir / "load_server_stdout.txt").open("w")
            load_server_err = (out_dir / "load_server_stderr.txt").open("w")
            sensor_client_out = (out_dir / "sensor_client.json").open("w")
            sensor_client_err = (out_dir / "sensor_client_stderr.txt").open("w")
            load_client_out = (out_dir / "load.json").open("w")
            load_client_err = (out_dir / "load_stderr.txt").open("w")

            open_file_handles.extend([
                raw_receiver, receiver_err,
                load_server_out, load_server_err,
                sensor_client_out, sensor_client_err,
                load_client_out, load_client_err,
            ])

            # Start receiver servers on h2
            sensor_server = h2.popen(
                ["iperf3", "-s", "-1", "-p", "5202", "--json-stream", "--forceflush", "-i", "2"],
                stdout=subprocess.PIPE,
                stderr=receiver_err,
                text=True,
            )
            load_server = h2.popen(
                ["iperf3", "-s", "-1", "-p", "5201"],
                stdout=load_server_out,
                stderr=load_server_err,
            )
            processes.extend((sensor_server, load_server))

            # Check server readiness
            time.sleep(1)
            if sensor_server.poll() is not None:
                raise RuntimeError(
                    f"Sensor server (iperf3 -s -p 5202) exited immediately with code {sensor_server.poll()}"
                )
            if load_server.poll() is not None:
                raise RuntimeError(
                    f"Load server (iperf3 -s -p 5201) exited immediately with code {load_server.poll()}"
                )

            # 3. Initialize monitor with initialized load_client = None
            monitor = ReceiverStreamMonitor(sensor_server, raw_receiver)
            bridge_holder = {}

            def on_window(window):
                try:
                    bridge = bridge_holder.get("bridge")
                    if bridge is None:
                        return

                    now_mono = time.monotonic()
                    w_abs_start = bridge.client_launch + window["window_start_seconds"]
                    w_abs_end = bridge.client_launch + window["window_end_seconds"]

                    # Confounding check: check whether load generator is running
                    load_poll = load_client.poll() if load_client is not None else -1
                    load_is_running = (load_client is not None and load_poll is None)
                    if load_client is not None and load_poll is not None and timing_holder["load_ended_mono"] is None:
                        timing_holder["load_ended_mono"] = now_mono
                        timing_holder["load_ended_unix"] = time.time()

                    is_confounded = False
                    confounding_reason = None
                    if timing_holder["load_started_mono"] is not None and w_abs_start < timing_holder["load_started_mono"]:
                        is_confounded = True
                        confounding_reason = "window_started_before_load_generator_startup"
                    elif timing_holder["load_ended_mono"] is not None and w_abs_end >= timing_holder["load_ended_mono"]:
                        is_confounded = True
                        confounding_reason = "window_overlaps_or_follows_load_generator_cessation"
                    elif not load_is_running:
                        is_confounded = True
                        confounding_reason = "load_generator_not_active_during_window"

                    if load_is_running:
                        store.publish_flow("ECG_Monitoring", {
                            "source_ip": "10.0.0.1",
                            "target_ip": "10.0.0.2",
                            "protocol": "udp",
                            "dst_port": 5201,
                        })

                    pub = bridge.publish(window)
                    fresh = pub["published"]

                    alert = {
                        "alert_id": f"ADJUST-LIVE-{len(results) + 1}",
                        "attack_type": "DoS_Flooding",
                        "source_ip": "10.0.0.1",
                        "target_ip": "10.0.0.2",
                        "severity": "high",
                        "affected_service": "ECG_Monitoring",
                        "detector_id": "DUMMY_TESTBED",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                    resp = client.post("/alert", json=alert)
                    api_resp = resp.json
                    raw_rec = api_resp["recommendation"]

                    step = {
                        "window_index": len(results) + 1,
                        "window": window,
                        "publication": pub,
                        "load_active_during_window": load_is_running and not is_confounded,
                        "window_confounded_by_load_cessation": is_confounded,
                        "confounding_reason": confounding_reason,
                        "evaluation_valid": not is_confounded,
                        "api_response": api_resp,
                    }

                    if is_confounded:
                        step["confounding_warning"] = (
                            f"Window overlaps or follows load cessation ({confounding_reason}). "
                            "Recovery CANNOT be attributed to mitigation."
                        )
                        print(f"  Window {len(results)+1}: CONVOLUTED/INVALID ({confounding_reason}).")
                        if action_state["stage"] == "observing_adjusted":
                            action_state["branch_verdict"] = "inconclusive"
                            action_state["verdict_details"]["reason"] = (
                                f"post_adjustment_window_confounded_by_load_cessation_{confounding_reason}"
                            )

                    elif fresh and action_state["stage"] == "pending":
                        if raw_rec["action"] == "rate_limit":
                            # Requirement 7: Preserve original API recommendation; copy plan for experimental override
                            action_state["original_api_recommendation"] = copy.deepcopy(raw_rec)
                            override_plan = copy.deepcopy(raw_rec)
                            override_plan["rate_limit_kbps"] = 1800
                            override_plan["duration_seconds"] = 300
                            override_plan["experimental_override"] = {
                                "original_rate_limit_kbps": raw_rec.get("rate_limit_kbps"),
                                "override_rate_limit_kbps": 1800,
                                "rationale": "Experimental override to test whether empirical loss triggers adjustment on 2 Mbps link",
                            }
                            action_state["initial_override_plan"] = copy.deepcopy(override_plan)

                            # Enforce override plan
                            step["enforcement"] = enforcer.apply(override_plan)
                            action_state["completed_at"] = time.monotonic()
                            action_state["stage"] = "observing_initial"

                            # Capture OVS flow and meter evidence
                            step["ovs_evidence_initial"] = {
                                "flow_dump": enforcer.run(["dump-flows", "s1"]).stdout,
                                "meter_stats": enforcer.run(["meter-stats", "s1"]).stdout,
                                "cookie": f"0x{enforcer.cookie:x}",
                                "meter_id": enforcer.meter_id,
                            }
                            print(f"  Window {len(results)+1}: Initial override (1800 kbps) enforced. OVS evidence captured.")

                    elif fresh and action_state["stage"] in ("observing_initial", "observing_adjusted"):
                        if w_abs_start < action_state["completed_at"]:
                            step["observation_status"] = "Transition window excluded"
                            print(f"  Window {len(results)+1}: Transition window excluded from reassessment.")
                        else:
                            empirical_decision = window["qos_review"]["decision"]
                            is_degraded = (empirical_decision == "review_required")

                            if action_state["stage"] == "observing_initial":
                                if is_degraded:
                                    # Measured QoS degraded under 1800 kbps: execute adjustment to 500 kbps
                                    stronger_plan = copy.deepcopy(action_state["initial_override_plan"])
                                    stronger_plan["rate_limit_kbps"] = 500
                                    stronger_plan["duration_seconds"] = 300
                                    stronger_plan["adjustment_trigger"] = {
                                        "observed_throughput_kbps": window["receiver_kbps"],
                                        "observed_loss_percent": window["packet_loss_percent"],
                                        "trigger_reason": "empirical_degradation_under_1800kbps",
                                    }
                                    action_state["adjusted_enforcement_plan"] = copy.deepcopy(stronger_plan)

                                    enforcer.cleanup()
                                    step["reassessment"] = {
                                        "adjustment_command_executed": True,
                                        "measured_throughput_kbps": window["receiver_kbps"],
                                        "measured_loss_percent": window["packet_loss_percent"],
                                        "enforcement": enforcer.apply(stronger_plan),
                                    }
                                    action_state["completed_at"] = time.monotonic()
                                    action_state["stage"] = "observing_adjusted"
                                    action_state["adjustment_command_executed"] = True

                                    # Capture OVS flow and meter evidence post-adjustment
                                    step["ovs_evidence_adjusted"] = {
                                        "flow_dump": enforcer.run(["dump-flows", "s1"]).stdout,
                                        "meter_stats": enforcer.run(["meter-stats", "s1"]).stdout,
                                        "cookie": f"0x{enforcer.cookie:x}",
                                        "meter_id": enforcer.meter_id,
                                    }
                                    print(
                                        f"  Window {len(results)+1}: ADJUSTMENT EXECUTED based on empirical QoS "
                                        f"({window['receiver_kbps']} kbps, {window['packet_loss_percent']}% loss). "
                                        f"Meter adjusted to 500 kbps."
                                    )
                                else:
                                    # Measured QoS passed under 1800 kbps: do NOT adjust
                                    step["reassessment"] = {
                                        "adjustment_command_executed": False,
                                        "measured_throughput_kbps": window["receiver_kbps"],
                                        "measured_loss_percent": window["packet_loss_percent"],
                                        "reason": "Empirical QoS satisfied under initial limit",
                                    }
                                    action_state["adjustment_command_executed"] = False
                                    action_state["post_adjustment_window_evaluated"] = False
                                    action_state["final_measured_qos_passed"] = True
                                    action_state["branch_verdict"] = "not_exercised_measured_qos_passed"
                                    action_state["verdict_details"] = {
                                        "reason": "measured_qos_satisfied_under_initial_limit",
                                    }
                                    action_state["stage"] = "finished"
                                    print(
                                        f"  Window {len(results)+1}: Measured QoS satisfied under initial limit "
                                        f"({window['receiver_kbps']} kbps, {window['packet_loss_percent']}% loss). "
                                        f"Adjustment NOT EXERCISED."
                                    )
                            else:
                                # Post-adjustment observation window
                                action_state["post_adjustment_window_evaluated"] = True
                                action_state["final_measured_qos_passed"] = (empirical_decision == "no_change_recommended")
                                action_state["stage"] = "finished"

                                if action_state["final_measured_qos_passed"]:
                                    action_state["branch_verdict"] = "exercised_and_qos_recovered"
                                else:
                                    action_state["branch_verdict"] = "exercised_but_qos_unrecovered"

                                action_state["verdict_details"] = {
                                    "measured_throughput_kbps": window["receiver_kbps"],
                                    "measured_loss_percent": window["packet_loss_percent"],
                                    "qos_decision": empirical_decision,
                                }
                                step["post_adjustment_verdict"] = action_state["branch_verdict"]
                                print(
                                    f"  Window {len(results)+1}: Post-adjustment window evaluated. "
                                    f"Verdict: {action_state['branch_verdict']} "
                                    f"({window['receiver_kbps']} kbps, {window['packet_loss_percent']}% loss)."
                                )

                    step["controller_stage"] = action_state["stage"]
                    results.append(step)
                    with (out_dir / "window_decisions.jsonl").open("a") as log:
                        log.write(json.dumps(step) + "\n")

                except Exception as ex:
                    callback_error[0] = ex
                    stop_signal.set()
                    raise

            monitor.on_window = on_window
            monitor.start()

            # 4. Start 5 Mbit/s load client on h1 (70 seconds so it outlasts the 60s sensor stream)
            print("Starting 5 Mbit/s UDP load generator on h1 (70s duration)...")
            timing_holder["load_started_mono"] = time.monotonic()
            timing_holder["load_started_unix"] = time.time()
            load_client = h1.popen(
                ["iperf3", "-c", "10.0.0.2", "-p", "5201", "-u", "-b", "5M", "-l", "1000",
                 "-t", "70", "--pacing-timer", "1000", "--connect-timeout", "5000", "-J"],
                stdout=load_client_out,
                stderr=load_client_err,
            )
            processes.append(load_client)

            # Wait briefly to confirm load generator startup
            time.sleep(1)
            if load_client.poll() is not None:
                raise RuntimeError(
                    f"Load client exited prematurely during startup with code {load_client.poll()}"
                )

            # Requirement 3: Capture sensor launch timing IMMEDIATELY before client popen
            timing_holder["sensor_launch_mono"] = time.monotonic()
            timing_holder["sensor_launch_unix"] = time.time()
            bridge_holder["bridge"] = LiveQoSBridge(store, "ECG_Monitoring", timing_holder["sensor_launch_mono"])

            # Start sensor client on h1 (UDP 100K for 60s)
            print("Starting 100 Kbit/s UDP sensor stream on h1 (60s duration)...")
            sensor_client = h1.popen(
                ["iperf3", "-c", "10.0.0.2", "-p", "5202", "-u", "-b", "100K", "-l", "1000",
                 "-t", "60", "--pacing-timer", "1000", "--connect-timeout", "5000", "-J"],
                stdout=sensor_client_out,
                stderr=sensor_client_err,
            )
            processes.append(sensor_client)

            # Confirm receiver startup via receiver.jsonl event stream
            deadline = time.monotonic() + 5
            receiver_started = False
            raw_path = out_dir / "receiver.jsonl"
            while time.monotonic() < deadline:
                if callback_error[0] is not None:
                    raise RuntimeError(f"on_window callback failure during startup: {callback_error[0]}") from callback_error[0]
                if sensor_client.poll() is not None:
                    raise RuntimeError("Sensor client exited prematurely during startup")
                if raw_path.exists():
                    for line in raw_path.read_text().splitlines():
                        try:
                            event = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if event.get("event") == "error":
                            raise RuntimeError(f"Receiver startup error event: {event.get('data')}")
                        if event.get("event") == "start":
                            receiver_started = True
                if receiver_started:
                    break
                time.sleep(0.05)
            if not receiver_started:
                raise RuntimeError("Receiver startup was not confirmed within deadline")
            print("Telemetry streams established. Observing periodic windows...")

            # 5. Wait for sensor completion first (60s + margin), periodically checking callback failures
            deadline_sensor = time.monotonic() + 75
            while time.monotonic() < deadline_sensor:
                if callback_error[0] is not None:
                    raise RuntimeError(f"on_window callback failure: {callback_error[0]}") from callback_error[0]
                if sensor_client.poll() is not None:
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError("Sensor client timed out after 75 seconds")
            sensor_rc = sensor_client.returncode
            timing_holder["sensor_ended_mono"] = time.monotonic()
            timing_holder["sensor_ended_unix"] = time.time()

            # Now wait for load client completion (70s + margin)
            deadline_load = time.monotonic() + 25
            while time.monotonic() < deadline_load:
                if callback_error[0] is not None:
                    raise RuntimeError(f"on_window callback failure: {callback_error[0]}") from callback_error[0]
                if load_client.poll() is not None:
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError("Load client timed out after 25 seconds")
            load_rc = load_client.returncode
            if timing_holder["load_ended_mono"] is None:
                timing_holder["load_ended_mono"] = time.monotonic()
                timing_holder["load_ended_unix"] = time.time()

            # Wait for servers
            sensor_server_rc = sensor_server.wait(timeout=10)
            load_server_rc = load_server.wait(timeout=10)

            # Stop monitor thread BEFORE closing handles
            monitor.finish()
            if monitor.thread.is_alive():
                monitor.thread.join(timeout=3)

            # Propagate callback errors if any occurred in background thread
            if callback_error[0] is not None:
                raise RuntimeError(f"on_window callback failure: {callback_error[0]}") from callback_error[0]

            # 6. Verify process exit codes and stream errors
            if sensor_rc != 0:
                s_err = (out_dir / "sensor_client_stderr.txt").read_text()
                raise RuntimeError(f"Sensor client failed with exit code {sensor_rc}. Stderr: {s_err}")
            if load_rc != 0:
                l_err = (out_dir / "load_stderr.txt").read_text()
                raise RuntimeError(f"Load client failed with exit code {load_rc}. Stderr: {l_err}")
            if sensor_server_rc != 0:
                s_srv_err = (out_dir / "receiver_stderr.txt").read_text()
                raise RuntimeError(f"Sensor server failed with exit code {sensor_server_rc}. Stderr: {s_srv_err}")
            if load_server_rc != 0:
                l_srv_err = (out_dir / "load_server_stderr.txt").read_text()
                raise RuntimeError(f"Load server failed with exit code {load_server_rc}. Stderr: {l_srv_err}")
            if monitor.error is not None:
                raise RuntimeError(f"Receiver monitor reported stream error: {monitor.error}")

            # 7. Parse client JSON outputs for actual sender rates and errors
            sensor_json_path = out_dir / "sensor_client.json"
            load_json_path = out_dir / "load.json"

            if not sensor_json_path.exists() or sensor_json_path.stat().st_size == 0:
                raise RuntimeError(f"Sensor client JSON output missing or empty: {sensor_json_path}")
            s_json = json.loads(sensor_json_path.read_text())
            if "error" in s_json:
                raise RuntimeError(f"Sensor client reported iperf error: {s_json['error']}")
            summary_data["actual_sender_rates"]["sensor_sent_kbps"] = round(
                s_json["end"]["sum_sent"]["bits_per_second"] / 1000, 3
            )

            if not load_json_path.exists() or load_json_path.stat().st_size == 0:
                raise RuntimeError(f"Load client JSON output missing or empty: {load_json_path}")
            l_json = json.loads(load_json_path.read_text())
            if "error" in l_json:
                raise RuntimeError(f"Load client reported iperf error: {l_json['error']}")
            summary_data["actual_sender_rates"]["load_sent_kbps"] = round(
                l_json["end"]["sum_sent"]["bits_per_second"] / 1000, 3
            )

            # Record process observations
            sensor_dur = timing_holder["sensor_ended_mono"] - timing_holder["sensor_launch_mono"]
            load_dur = timing_holder["load_ended_mono"] - timing_holder["load_started_mono"]
            summary_data["process_observations"] = {
                "sensor_client": {
                    "configured_duration_seconds": 60,
                    "actual_duration_seconds": round(sensor_dur, 3),
                    "launch_mono": timing_holder["sensor_launch_mono"],
                    "launch_unix": timing_holder["sensor_launch_unix"],
                    "ended_mono": timing_holder["sensor_ended_mono"],
                    "ended_unix": timing_holder["sensor_ended_unix"],
                    "exit_code": sensor_rc,
                },
                "load_client": {
                    "configured_duration_seconds": 70,
                    "actual_duration_seconds": round(load_dur, 3),
                    "started_mono": timing_holder["load_started_mono"],
                    "started_unix": timing_holder["load_started_unix"],
                    "ended_mono": timing_holder["load_ended_mono"],
                    "ended_unix": timing_holder["load_ended_unix"],
                    "exit_code": load_rc,
                },
                "sensor_server": {"exit_code": sensor_server_rc},
                "load_server": {"exit_code": load_server_rc},
            }

            # Safety check: if load ended before sensor stream ended, verify no post-adjustment window overlapped
            if timing_holder["load_ended_mono"] < timing_holder["sensor_ended_mono"]:
                print("  WARNING: Load generator exited before sensor stream completed!")
                if action_state["stage"] == "observing_adjusted" and not action_state["post_adjustment_window_evaluated"]:
                    action_state["branch_verdict"] = "inconclusive"
                    action_state["verdict_details"]["reason"] = "load_exited_early_before_post_adjustment_window"

        else:
            # Mock mode: illustrates decision logic and separate verdicts offline without Mininet
            print(f"Running in mock mode ({mock_scenario})...")
            from controlled_lifecycle_test import MockOVS
            enforcer.run = MockOVS().run

            # Write mock client and server files
            (out_dir / "sensor_client.json").write_text(json.dumps({
                "end": {"sum_sent": {"bits_per_second": 100000.0}},
            }, indent=2))
            (out_dir / "sensor_client_stderr.txt").write_text("")
            (out_dir / "load.json").write_text(json.dumps({
                "end": {"sum_sent": {"bits_per_second": 5000000.0}},
            }, indent=2))
            (out_dir / "load_stderr.txt").write_text("")
            (out_dir / "receiver.jsonl").write_text(json.dumps({"event": "start"}) + "\n")
            (out_dir / "receiver_stderr.txt").write_text("")
            (out_dir / "load_server_stdout.txt").write_text("")
            (out_dir / "load_server_stderr.txt").write_text("")

            summary_data["actual_sender_rates"]["sensor_sent_kbps"] = 100.0
            summary_data["actual_sender_rates"]["load_sent_kbps"] = 5000.0

            base_sim = current_sim_time[0]
            timing_holder["load_started_mono"] = base_sim
            timing_holder["load_started_unix"] = time.time()
            timing_holder["sensor_launch_mono"] = base_sim + 1.0
            timing_holder["sensor_launch_unix"] = time.time() + 1.0

            # Mock scenarios
            if mock_scenario == "qos_passed":
                # Initial measured QoS satisfied -> adjustment not exercised
                mock_windows = [
                    {"w_start": 0.0, "w_end": 10.0, "kbps": 20.0, "loss": 80.0, "qos": "review_required"},
                    {"w_start": 10.0, "w_end": 20.0, "kbps": 85.0, "loss": 15.0, "qos": "review_required"},
                    {"w_start": 20.0, "w_end": 30.0, "kbps": 99.0, "loss": 0.0, "qos": "no_change_recommended"},
                ]
                load_end_sim = base_sim + 70.0
            elif mock_scenario == "no_post_window":
                # Adjustment executed, but test ends before post-adjustment window -> inconclusive
                mock_windows = [
                    {"w_start": 0.0, "w_end": 10.0, "kbps": 20.0, "loss": 80.0, "qos": "review_required"},
                    {"w_start": 10.0, "w_end": 20.0, "kbps": 85.0, "loss": 15.0, "qos": "review_required"},
                    {"w_start": 20.0, "w_end": 30.0, "kbps": 95.0, "loss": 5.0, "qos": "review_required"},
                ]
                load_end_sim = base_sim + 70.0
            elif mock_scenario == "early_load_cessation":
                # Load exits at 35s; Window 5 (40-50s) overlaps cessation -> confounded / inconclusive
                mock_windows = [
                    {"w_start": 0.0, "w_end": 10.0, "kbps": 20.0, "loss": 80.0, "qos": "review_required"},
                    {"w_start": 10.0, "w_end": 20.0, "kbps": 85.0, "loss": 15.0, "qos": "review_required"},
                    {"w_start": 20.0, "w_end": 30.0, "kbps": 95.0, "loss": 5.0, "qos": "review_required"},
                    {"w_start": 30.0, "w_end": 40.0, "kbps": 99.0, "loss": 1.0, "qos": "review_required"},
                    {"w_start": 40.0, "w_end": 50.0, "kbps": 100.0, "loss": 0.0, "qos": "no_change_recommended"},
                ]
                load_end_sim = base_sim + 35.0  # Stopped early!
            else:
                # Normal scenario: adjustment executed and recovered
                mock_windows = [
                    {"w_start": 0.0, "w_end": 10.0, "kbps": 20.0, "loss": 80.0, "qos": "review_required"},
                    {"w_start": 10.0, "w_end": 20.0, "kbps": 85.0, "loss": 15.0, "qos": "review_required"},
                    {"w_start": 20.0, "w_end": 30.0, "kbps": 95.0, "loss": 5.0, "qos": "review_required"},
                    {"w_start": 30.0, "w_end": 40.0, "kbps": 99.0, "loss": 1.0, "qos": "review_required"},
                    {"w_start": 40.0, "w_end": 50.0, "kbps": 100.0, "loss": 0.0, "qos": "no_change_recommended"},
                ]
                load_end_sim = base_sim + 70.0

            timing_holder["load_ended_mono"] = load_end_sim
            timing_holder["load_ended_unix"] = time.time() + (load_end_sim - base_sim)
            timing_holder["sensor_ended_mono"] = base_sim + 61.0
            timing_holder["sensor_ended_unix"] = time.time() + 61.0

            summary_data["process_observations"] = {
                "sensor_client": {
                    "configured_duration_seconds": 60,
                    "actual_duration_seconds": 60.0,
                    "launch_mono": timing_holder["sensor_launch_mono"],
                    "ended_mono": timing_holder["sensor_ended_mono"],
                    "exit_code": 0,
                },
                "load_client": {
                    "configured_duration_seconds": 70,
                    "actual_duration_seconds": round(load_end_sim - base_sim, 3),
                    "started_mono": timing_holder["load_started_mono"],
                    "ended_mono": timing_holder["load_ended_mono"],
                    "exit_code": 0,
                },
                "sensor_server": {"exit_code": 0},
                "load_server": {"exit_code": 0},
            }

            for i, mw in enumerate(mock_windows):
                now = base_sim + mw["w_end"]
                current_sim_time[0] = now
                window = {
                    "window_start_seconds": mw["w_start"],
                    "window_end_seconds": mw["w_end"],
                    "receiver_kbps": mw["kbps"],
                    "packet_loss_percent": mw["loss"],
                    "qos_review": {
                        "decision": mw["qos"],
                        "thresholds": {"min_throughput_kbps": 90, "max_loss_percent": 1},
                    },
                }
                lifecycle_scope = {
                    "source_ip": "10.0.0.1", "target_ip": "10.0.0.2",
                    "protocol": "udp", "dst_port": 5201,
                }
                store.publish_flow("ECG_Monitoring", lifecycle_scope)
                store.publish_qos("ECG_Monitoring", window, sample_end_monotonic=now - 0.05)

                w_abs_start = base_sim + mw["w_start"]
                w_abs_end = base_sim + mw["w_end"]

                # Confounding check in mock mode
                is_confounded = False
                confounding_reason = None
                if w_abs_end >= load_end_sim:
                    is_confounded = True
                    confounding_reason = "window_overlaps_or_follows_load_generator_cessation"

                alert = {
                    "alert_id": f"ADJUST-MOCK-{i + 1}",
                    "attack_type": "DoS_Flooding",
                    "source_ip": "10.0.0.1",
                    "target_ip": "10.0.0.2",
                    "severity": "high",
                    "affected_service": "ECG_Monitoring",
                    "detector_id": "DUMMY_TESTBED",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                resp = client.post("/alert", json=alert)
                api_resp = resp.json
                raw_rec = api_resp["recommendation"]

                step = {
                    "window_index": i + 1,
                    "window": window,
                    "load_active_during_window": not is_confounded,
                    "window_confounded_by_load_cessation": is_confounded,
                    "confounding_reason": confounding_reason,
                    "evaluation_valid": not is_confounded,
                    "api_response": api_resp,
                }

                if is_confounded:
                    step["confounding_warning"] = (
                        f"Window overlaps or follows load cessation ({confounding_reason}). "
                        "Recovery CANNOT be attributed to mitigation."
                    )
                    if action_state["stage"] == "observing_adjusted":
                        action_state["branch_verdict"] = "inconclusive"
                        action_state["verdict_details"]["reason"] = (
                            f"post_adjustment_window_confounded_by_load_cessation_{confounding_reason}"
                        )
                elif action_state["stage"] == "pending":
                    action_state["original_api_recommendation"] = copy.deepcopy(raw_rec)
                    override_plan = copy.deepcopy(raw_rec)
                    override_plan["rate_limit_kbps"] = 1800
                    override_plan["duration_seconds"] = 300
                    override_plan["experimental_override"] = {
                        "original_rate_limit_kbps": raw_rec.get("rate_limit_kbps"),
                        "override_rate_limit_kbps": 1800,
                        "rationale": "Mock override to test whether loss triggers adjustment",
                    }
                    action_state["initial_override_plan"] = copy.deepcopy(override_plan)

                    step["enforcement"] = enforcer.apply(override_plan)
                    action_state["completed_at"] = now + 0.05
                    action_state["stage"] = "observing_initial"
                    step["ovs_evidence_initial"] = {
                        "flow_dump": enforcer.run(["dump-flows", "s1"]).stdout,
                        "meter_stats": enforcer.run(["meter-stats", "s1"]).stdout,
                        "cookie": f"0x{enforcer.cookie:x}",
                        "meter_id": enforcer.meter_id,
                    }
                elif action_state["stage"] in ("observing_initial", "observing_adjusted"):
                    if w_abs_start < action_state["completed_at"]:
                        step["observation_status"] = "Transition window excluded"
                    else:
                        is_degraded = (mw["qos"] == "review_required")
                        if action_state["stage"] == "observing_initial":
                            if is_degraded:
                                stronger = copy.deepcopy(action_state["initial_override_plan"])
                                stronger["rate_limit_kbps"] = 500
                                stronger["duration_seconds"] = 300
                                stronger["adjustment_trigger"] = {
                                    "observed_throughput_kbps": mw["kbps"],
                                    "observed_loss_percent": mw["loss"],
                                    "trigger_reason": "empirical_degradation_under_1800kbps",
                                }
                                action_state["adjusted_enforcement_plan"] = copy.deepcopy(stronger)

                                enforcer.cleanup()
                                step["reassessment"] = {
                                    "adjustment_command_executed": True,
                                    "measured_throughput_kbps": mw["kbps"],
                                    "measured_loss_percent": mw["loss"],
                                    "enforcement": enforcer.apply(stronger),
                                }
                                action_state["adjustment_command_executed"] = True
                                action_state["completed_at"] = now + 0.05
                                action_state["stage"] = "observing_adjusted"
                                step["ovs_evidence_adjusted"] = {
                                    "flow_dump": enforcer.run(["dump-flows", "s1"]).stdout,
                                    "meter_stats": enforcer.run(["meter-stats", "s1"]).stdout,
                                    "cookie": f"0x{enforcer.cookie:x}",
                                    "meter_id": enforcer.meter_id,
                                }
                            else:
                                step["reassessment"] = {
                                    "adjustment_command_executed": False,
                                    "measured_throughput_kbps": mw["kbps"],
                                    "measured_loss_percent": mw["loss"],
                                    "reason": "Empirical QoS satisfied under initial limit",
                                }
                                action_state["adjustment_command_executed"] = False
                                action_state["post_adjustment_window_evaluated"] = False
                                action_state["final_measured_qos_passed"] = True
                                action_state["branch_verdict"] = "not_exercised_measured_qos_passed"
                                action_state["verdict_details"] = {
                                    "reason": "measured_qos_satisfied_under_initial_limit",
                                }
                                action_state["stage"] = "finished"
                        else:
                            action_state["post_adjustment_window_evaluated"] = True
                            action_state["final_measured_qos_passed"] = (mw["qos"] == "no_change_recommended")
                            action_state["stage"] = "finished"
                            if action_state["final_measured_qos_passed"]:
                                action_state["branch_verdict"] = "exercised_and_qos_recovered"
                            else:
                                action_state["branch_verdict"] = "exercised_but_qos_unrecovered"
                            action_state["verdict_details"] = {
                                "measured_throughput_kbps": mw["kbps"],
                                "measured_loss_percent": mw["loss"],
                                "qos_decision": mw["qos"],
                            }
                            step["post_adjustment_verdict"] = action_state["branch_verdict"]

                step["controller_stage"] = action_state["stage"]
                results.append(step)
                with (out_dir / "window_decisions.jsonl").open("a") as log:
                    log.write(json.dumps(step) + "\n")
                print(f"  Mock Window {i+1}: stage -> {action_state['stage']}, verdict -> {action_state['branch_verdict']}")

        # Post-run verdict finalization: if no eligible post-adjustment window was evaluated
        if action_state["branch_verdict"] == "inconclusive":
            if action_state["stage"] == "pending":
                action_state["verdict_details"]["reason"] = "no_windows_observed_before_finish"
            elif action_state["stage"] == "observing_initial":
                action_state["verdict_details"]["reason"] = "initial_observation_window_not_completed"
            elif action_state["stage"] == "observing_adjusted":
                if not action_state.get("verdict_details", {}).get("reason"):
                    action_state["verdict_details"]["reason"] = (
                        "adjustment_command_executed_but_no_eligible_post_adjustment_window_evaluated"
                    )

        summary_data["status"] = "success"

    except Exception as e:
        summary_data["status"] = "failed"
        summary_data["error"] = str(e)
        summary_data["traceback"] = traceback.format_exc()
        print(f"\n[ERROR] Periodic adjustment test failed: {e}")
        raise

    finally:
        stop_signal.set()
        cleanup_outcome = {
            "all_clean": True,
            "process_reap_errors": [],
            "thread_join_errors": [],
            "file_close_errors": [],
            "enforcer_cleanup": None,
            "mininet_cleanup": None,
        }

        # 1. Stop / reap child processes first
        for p in processes:
            try:
                if p.poll() is None:
                    p.terminate()
                    try:
                        p.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        p.kill()
                        p.wait(timeout=2)
            except Exception as ex:
                cleanup_outcome["all_clean"] = False
                cleanup_outcome["process_reap_errors"].append(str(ex))
                print(f"[CLEANUP ERROR] Failed to reap process: {ex}")

        # 2. Join monitor thread BEFORE closing handles
        try:
            if 'monitor' in locals() and hasattr(monitor, "thread") and monitor.thread.is_alive():
                monitor.finish()
                monitor.thread.join(timeout=3)
                if monitor.thread.is_alive():
                    raise TimeoutError("ReceiverStreamMonitor thread did not exit within timeout")
        except Exception as ex:
            cleanup_outcome["all_clean"] = False
            cleanup_outcome["thread_join_errors"].append(str(ex))
            print(f"[CLEANUP ERROR] Failed to join monitor thread: {ex}")

        # 3. Close open file handles
        for fh in open_file_handles:
            try:
                if not fh.closed:
                    fh.flush()
                    fh.close()
            except Exception as ex:
                cleanup_outcome["all_clean"] = False
                cleanup_outcome["file_close_errors"].append(str(ex))
                print(f"[CLEANUP ERROR] Failed to close file handle: {ex}")

        # 4. Clean up OVS rules created by enforcer
        try:
            enforcer.cleanup()
            cleanup_outcome["enforcer_cleanup"] = "completed"
        except Exception as ex:
            cleanup_outcome["all_clean"] = False
            cleanup_outcome["enforcer_cleanup"] = f"failed: {ex}"
            print(f"[CLEANUP ERROR] Enforcer cleanup error: {ex}")

        # 5. Stop Mininet if created
        if net is not None:
            try:
                net.stop()
                cleanup_outcome["mininet_cleanup"] = "completed"
            except Exception as ex:
                cleanup_outcome["all_clean"] = False
                cleanup_outcome["mininet_cleanup"] = f"failed: {ex}"
                print(f"[CLEANUP ERROR] Mininet stop error: {ex}")

        # 6. Populate final summary fields
        summary_data["cleanup_outcome"] = cleanup_outcome
        summary_data["total_windows_observed"] = len(results)
        summary_data["windows"] = results
        summary_data["final_controller_stage"] = action_state["stage"]
        summary_data["branch_verdict"] = action_state["branch_verdict"]
        summary_data["adjustment_command_executed"] = action_state["adjustment_command_executed"]
        summary_data["post_adjustment_window_evaluated"] = action_state["post_adjustment_window_evaluated"]
        summary_data["final_measured_qos_passed"] = action_state["final_measured_qos_passed"]
        summary_data["verdict_details"] = action_state["verdict_details"]
        summary_data["original_api_recommendation"] = action_state["original_api_recommendation"]
        summary_data["initial_override_plan"] = action_state["initial_override_plan"]
        summary_data["adjusted_enforcement_plan"] = action_state["adjusted_enforcement_plan"]

        # Write summary.json ALWAYS on both success and failure
        try:
            summary_path = out_dir / "summary.json"
            summary_path.write_text(json.dumps(summary_data, indent=2) + "\n")
            print(f"Summary saved to: {summary_path}")
        except Exception as ex:
            print(f"[CRITICAL ERROR] Failed to write summary.json: {ex}")

    print(
        f"\n[DONE] Adjustment test finished with status: {summary_data['status']}. "
        f"Verdict: {action_state['branch_verdict']}."
    )
    return summary_data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Two-Host Pilot Live Periodic Adjustment Branch Evaluation"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--live",
        action="store_true",
        help="Run live Mininet test (requires root)",
    )
    group.add_argument(
        "--mock",
        action="store_true",
        help="Run offline mock test without Mininet",
    )
    parser.add_argument(
        "--mock-scenario",
        choices=["normal", "qos_passed", "no_post_window", "early_load_cessation"],
        default="normal",
        help="Mock scenario to exercise decision logic branches offline",
    )
    args = parser.parse_args()

    if args.live:
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        if not is_root:
            sys.exit("Error: --live mode requires root privileges (run with sudo).")

    run_live_adjustment_demo(live=args.live, mock=args.mock, mock_scenario=args.mock_scenario)
