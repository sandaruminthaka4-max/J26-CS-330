#!/usr/bin/env python3
"""Sensor-Only Periodic Delay & QoS Integration Check.

Runs actual ICMP ping probes concurrently with live iperf3 medical sensor telemetry on Mininet.
Measures real reply-arrival RTT statistics aligned to periodic 5-interval (10-second) QoS windows.

Scope & Boundary:
- SENSOR-ONLY DELAY INTEGRATION: Tests the baseline delay monitoring integration path without attacker load.
  Does NOT evaluate network congestion, DoS degradation, or rate-adjustment branches (tested separately).
- Measurement & Accounting Boundaries:
  * Reports reply-arrival RTT statistics (min, avg, max, sample count) from ping stdout.
  * ICMP sent count and packet loss are reported as UNAVAILABLE (null) because the uninstrumented
    ping subprocess does not provide verified per-probe dispatch timestamps.
  * Timing limitation: launch_mono and launch_unix are captured immediately before the sensor client
    subprocess is launched as an empirical measurement-time estimate, not exact receiver-window synchronization.
  * Window alignment limitation: Reply arrivals are grouped by arrival timestamp into half-open [start, end)
    windows; exact alignment with receiver UDP 5-interval stream windows is approximate due to independent clocks.
- Collision Guard:
  * Refuses live startup if OVS bridge 's1' already exists before creating topology.
  * Does NOT delete existing bridges or execute global Mininet cleanup.
- Reliability & Provenance:
  * Preserves sensor client JSON stdout, client stderr, receiver JSONL, receiver stderr, raw ping log,
    api_events.jsonl, window_decisions.jsonl, and summary.json.
  * summary.json is guaranteed to be written on both success and failure, capturing traceback and partial windows.
  * Fails if zero valid real RTT samples are collected.

Usage:
    Live testbed (Ubuntu VM with root):
        sudo PYTHONPATH=/usr/lib/python3/dist-packages /home/sahan/iomt-research/.venv/bin/python periodic_delay_live_check.py --live
    Offline mock verification:
        python3 periodic_delay_live_check.py --mock
"""

import argparse
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
from delay_reader_v2 import PeriodicDelayMonitor
from live_qos_bridge_v2 import LiveQoSBridge
from ovs_enforcement_v2 import OVSEnforcer
from receiver_callback_monitor import ReceiverStreamMonitor


def run_live_periodic_delay(live=False, mock=False):
    if not live and not mock:
        raise ValueError("Must specify either --live or --mock explicitly")
    if live and mock:
        raise ValueError("Cannot specify both --live and --mock")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = RESULTS_DIR / f"periodic_delay_live_{timestamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    mode_label = "live_mininet_ovs" if live else "mock_offline"
    print("=== Sensor-Only Periodic Delay Integration Check ===")
    print(f"Mode:             {mode_label}")
    print(f"Output Directory: {out_dir}")

    services = json.loads((BASE / "configs/services_v2.json").read_text())
    store = ContextStore()
    app = create_app(out_dir / "api_events.jsonl", store.provide)
    client = app.test_client()

    raw_ping_file = out_dir / "raw_ping.txt"
    delay_monitor = PeriodicDelayMonitor(
        probe_interval_seconds=1.0,
        raw_log_file=raw_ping_file,
    )

    results = []
    processes = []
    threads = []
    open_file_handles = []
    net = None
    stop_signal = threading.Event()

    ping_reader_state = {
        "error": None,
        "lines_read": 0,
        "rtt_samples_parsed": 0,
    }

    summary_data = {
        "timestamp": timestamp,
        "mode": mode_label,
        "test_name": "sensor_only_periodic_delay_integration_check",
        "status": "in_progress",
        "error": None,
        "traceback": None,
        "scope_description": (
            "Sensor-only delay integration check running concurrent ping with iperf telemetry. "
            "Tests baseline delay monitoring integration path without attacker load. "
            "Does NOT claim congestion validation or live adjustment coverage."
        ),
        "timing_and_alignment_limitations": {
            "launch_timing_note": (
                "launch_mono and launch_unix captured immediately before sensor client process launch "
                "as an empirical measurement-time estimate, not exact receiver-window synchronization."
            ),
            "window_alignment_note": (
                "Reply arrivals are grouped by ICMP reply timestamp into half-open window [w_start, w_end). "
                "Exact alignment with receiver UDP 5-interval stream windows is approximate due to "
                "independent process clocks, buffering, and scheduling jitter."
            ),
            "loss_accounting_note": (
                "Verified probe-send records unavailable; periodic ICMP sent count and packet loss are "
                "reported as null (unavailable) because uninstrumented ping does not record dispatch timestamps."
            ),
        },
        "preserved_raw_logs": {
            "raw_ping": str(raw_ping_file),
            "receiver_jsonl": str(out_dir / "receiver.jsonl"),
            "receiver_stderr": str(out_dir / "receiver_stderr.txt"),
            "sensor_client_json": str(out_dir / "sensor_client.json"),
            "sensor_client_stderr": str(out_dir / "sensor_client_stderr.txt"),
            "api_events": str(out_dir / "api_events.jsonl"),
            "window_decisions": str(out_dir / "window_decisions.jsonl"),
        },
        "total_windows_observed": 0,
        "total_rtt_samples_collected": 0,
        "windows": [],
        "cleanup_outcome": {},
    }

    try:
        if live:
            # 1. Collision guard: refuse startup if s1 already exists
            check_s1 = subprocess.run(
                ["ovs-vsctl", "br-exists", "s1"],
                capture_output=True,
                text=True,
            )
            if check_s1.returncode == 0:
                raise RuntimeError(
                    "Collision guard: OVS bridge 's1' already exists on system. "
                    "Refusing live startup to protect existing testbed/bridge resources. "
                    "Do NOT delete existing bridges or execute global Mininet cleanup; "
                    "verify and clean testbed resources explicitly."
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

            # 2. Launch concurrent live ping on h1 directed to h2 (10.0.0.2)
            print("Launching concurrent ping probe on h1...")
            ping_proc = h1.popen(
                ["ping", "-n", "-D", "-i", "1", "10.0.0.2"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env={**os.environ, "LC_ALL": "C"},
            )
            processes.append(ping_proc)

            def read_ping_stream(proc):
                try:
                    for line in iter(proc.stdout.readline, ""):
                        if stop_signal.is_set():
                            break
                        line_clean = line.strip()
                        if line_clean:
                            ping_reader_state["lines_read"] += 1
                            sample = delay_monitor.feed_line(line_clean)
                            if sample is not None:
                                ping_reader_state["rtt_samples_parsed"] += 1
                except Exception as ex:
                    ping_reader_state["error"] = str(ex)

            t_ping = threading.Thread(target=read_ping_stream, args=(ping_proc,), daemon=True)
            t_ping.start()
            threads.append(t_ping)

            # 3. Start receiver server on h2
            receiver_out = (out_dir / "receiver.jsonl").open("w")
            receiver_err = (out_dir / "receiver_stderr.txt").open("w")
            open_file_handles.extend([receiver_out, receiver_err])

            sensor_server = h2.popen(
                ["iperf3", "-s", "-1", "-p", "5202", "--json-stream", "--forceflush", "-i", "2"],
                stdout=subprocess.PIPE,
                stderr=receiver_err,
                text=True,
            )
            processes.append(sensor_server)

            monitor = ReceiverStreamMonitor(sensor_server, receiver_out)
            bridge_holder = {}
            timing_holder = {}

            def on_window(window):
                bridge = bridge_holder.get("bridge")
                if bridge is None:
                    return
                pub = bridge.publish(window)
                launch_unix = timing_holder.get("launch_unix", time.time())
                w_start_unix = launch_unix + window["window_start_seconds"]
                w_end_unix = launch_unix + window["window_end_seconds"]

                # Extract delay metrics for half-open interval [start, end)
                # Without verified send timestamps from ping, sent_packets and loss remain null.
                d_metrics = delay_monitor.get_window_metrics(w_start_unix, w_end_unix)

                alert = {
                    "alert_id": f"DELAY-CHECK-{len(results) + 1}",
                    "attack_type": "DoS_Flooding",
                    "source_ip": "10.0.0.1",
                    "target_ip": "10.0.0.2",
                    "severity": "medium",
                    "affected_service": "ECG_Monitoring",
                    "detector_id": "DUMMY_TESTBED",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                resp = client.post("/alert", json=alert)

                step = {
                    "window_index": len(results) + 1,
                    "window": window,
                    "publication": pub,
                    "delay_metrics": d_metrics,
                    "window_alignment_limitation": (
                        "Reply arrivals are grouped by ICMP reply timestamp into half-open window [w_start, w_end). "
                        "Exact alignment with receiver UDP 5-interval stream windows is approximate due to "
                        "independent process clocks, buffering, and scheduling jitter."
                    ),
                    "loss_accounting_status": "unavailable_without_verified_send_records",
                    "api_response": resp.json,
                }
                results.append(step)
                with (out_dir / "window_decisions.jsonl").open("a") as log:
                    log.write(json.dumps(step) + "\n")

                print(
                    f"  Window {len(results)}: QoS {window['receiver_kbps']} kbps, {window['packet_loss_percent']}% loss | "
                    f"RTT avg: {d_metrics['rtt_avg_ms']} ms ({d_metrics['received_packets']} replies, "
                    f"sent: {d_metrics['sent_packets']}, loss: {d_metrics['packet_loss_percent']})",
                    flush=True,
                )

            monitor.on_window = on_window
            monitor.start()

            # 4. Prepare sensor client logging handles (JSON stdout and stderr preserved)
            client_out = (out_dir / "sensor_client.json").open("w")
            client_err = (out_dir / "sensor_client_stderr.txt").open("w")
            open_file_handles.extend([client_out, client_err])

            # Pause briefly to allow server bind
            time.sleep(1)

            # 5. Capture timing IMMEDIATELY before client popen
            timing_holder["launch_mono"] = time.monotonic()
            timing_holder["launch_unix"] = time.time()
            bridge_holder["bridge"] = LiveQoSBridge(store, "ECG_Monitoring", timing_holder["launch_mono"])

            # Start sensor client on h1 (UDP 100K for 35s to produce ~3 windows)
            sensor_client = h1.popen(
                ["iperf3", "-c", "10.0.0.2", "-p", "5202", "-u", "-b", "100K", "-l", "1000",
                 "-t", "35", "--pacing-timer", "1000", "--connect-timeout", "5000", "-J"],
                stdout=client_out,
                stderr=client_err,
            )
            processes.append(sensor_client)

            # 6. Confirm receiver startup via receiver.jsonl event stream
            deadline = time.monotonic() + 5
            receiver_started = False
            raw_path = out_dir / "receiver.jsonl"
            while time.monotonic() < deadline:
                if sensor_client.poll() is not None:
                    raise RuntimeError("Sensor client exited before receiver startup")
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
            print("Sensor receiver confirmed started. Streaming concurrent telemetry...")

            # 7. Wait for processes to complete
            client_rc = sensor_client.wait(timeout=45)
            server_rc = sensor_server.wait(timeout=10)
            monitor.finish()

            # 8. Verify client and server exit codes
            if client_rc != 0:
                client_err_text = (out_dir / "sensor_client_stderr.txt").read_text()
                raise RuntimeError(f"Sensor client failed with exit code {client_rc}. Stderr: {client_err_text}")
            if server_rc != 0:
                server_err_text = (out_dir / "receiver_stderr.txt").read_text()
                raise RuntimeError(f"Sensor server failed with exit code {server_rc}. Stderr: {server_err_text}")

            # 9. Verify client JSON content for iperf3 errors
            client_json_path = out_dir / "sensor_client.json"
            if client_json_path.exists() and client_json_path.stat().st_size > 0:
                try:
                    c_data = json.loads(client_json_path.read_text())
                    if "error" in c_data:
                        raise RuntimeError(f"Sensor client JSON reported error: {c_data['error']}")
                except json.JSONDecodeError as je:
                    raise RuntimeError(f"Sensor client output is invalid JSON: {je}")

            # 10. Verify receiver monitor errors
            if monitor.error is not None:
                raise RuntimeError(f"Receiver monitor reported stream error: {monitor.error}")

            # 11. Verify ping reader status and ping subprocess
            if ping_reader_state["error"] is not None:
                raise RuntimeError(f"Ping reader thread encountered error: {ping_reader_state['error']}")
            if ping_proc.poll() is not None and ping_proc.returncode != 0:
                raise RuntimeError(f"Ping probe exited prematurely with exit code {ping_proc.returncode}")

            # 12. Assert at least one window observed and valid real RTT samples collected
            if len(results) == 0:
                raise RuntimeError("Delay check failed: Zero QoS windows were collected.")
            total_rtt_samples = sum(
                w["delay_metrics"]["exact_reply_samples_count"]
                for w in results
                if "delay_metrics" in w and "exact_reply_samples_count" in w["delay_metrics"]
            )
            if total_rtt_samples == 0:
                raise RuntimeError(
                    "Delay check failed: Zero valid ICMP RTT reply samples were collected during the test. "
                    "Cannot report a successful delay integration test with no valid real RTT samples."
                )

        else:
            # Mock mode: feeds simulated ping lines and validates structure
            print("Running in mock mode with simulated ping stream...")

            # Write mock client and server files
            (out_dir / "sensor_client.json").write_text(json.dumps({
                "start": {"timestamp": {"time": datetime.now(timezone.utc).isoformat()}},
                "end": {"sum_sent": {"bits_per_second": 100000.0}},
            }, indent=2))
            (out_dir / "sensor_client_stderr.txt").write_text("")
            (out_dir / "receiver.jsonl").write_text(
                json.dumps({"event": "start", "data": {}}) + "\n"
                + json.dumps({"event": "interval", "data": {"sum": {"start": 0, "end": 2, "seconds": 2, "bits_per_second": 100000, "lost_percent": 0.0, "lost_packets": 0, "packets": 25, "jitter_ms": 0.5, "sender": False}}}) + "\n"
            )
            (out_dir / "receiver_stderr.txt").write_text("")

            base_unix = time.time()
            for sec in range(0, 32):
                t_p = base_unix + sec
                delay_monitor.feed_line(f"[{t_p:.3f}] 64 bytes from 10.0.0.2: icmp_seq={sec+1} ttl=64 time=2.450 ms")

            for i in range(3):
                w_start = base_unix + (i * 10.0)
                w_end = base_unix + ((i + 1) * 10.0)
                d_metrics = delay_monitor.get_window_metrics(w_start, w_end)
                step = {
                    "window_index": i + 1,
                    "window": {
                        "window_start_seconds": i * 10.0,
                        "window_end_seconds": (i + 1) * 10.0,
                        "receiver_kbps": 100.0,
                        "packet_loss_percent": 0.0,
                    },
                    "delay_metrics": d_metrics,
                    "window_alignment_limitation": (
                        "Reply arrivals are grouped by ICMP reply timestamp into half-open window [w_start, w_end). "
                        "Exact alignment with receiver UDP 5-interval stream windows is approximate due to "
                        "independent process clocks, buffering, and scheduling jitter."
                    ),
                    "loss_accounting_status": "unavailable_without_verified_send_records",
                }
                results.append(step)
                with (out_dir / "window_decisions.jsonl").open("a") as log:
                    log.write(json.dumps(step) + "\n")
                print(
                    f"  Mock Window {i+1}: RTT avg: {d_metrics['rtt_avg_ms']} ms "
                    f"({d_metrics['received_packets']} replies, sent: {d_metrics['sent_packets']}, "
                    f"loss: {d_metrics['packet_loss_percent']})"
                )

            # Assert valid samples in mock mode
            total_rtt_samples = sum(
                w["delay_metrics"]["exact_reply_samples_count"]
                for w in results
                if "delay_metrics" in w and "exact_reply_samples_count" in w["delay_metrics"]
            )
            if total_rtt_samples == 0:
                raise RuntimeError("Mock delay check failed: Zero RTT reply samples were recorded.")

        summary_data["status"] = "success"

    except Exception as e:
        summary_data["status"] = "failed"
        summary_data["error"] = str(e)
        summary_data["traceback"] = traceback.format_exc()
        print(f"\n[ERROR] Periodic delay check failed: {e}")
        raise

    finally:
        stop_signal.set()

        # Close open file handles reliably
        for fh in open_file_handles:
            try:
                if not fh.closed:
                    fh.flush()
                    fh.close()
            except Exception:
                pass

        # Terminate and reap child processes
        for p in processes:
            try:
                if p.poll() is None:
                    p.terminate()
                    try:
                        p.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        p.kill()
                        p.wait(timeout=2)
            except Exception:
                pass

        # Join reader threads
        for t in threads:
            try:
                t.join(timeout=2)
            except Exception:
                pass

        # Stop Mininet if it was created
        if net is not None:
            try:
                net.stop()
                summary_data["cleanup_outcome"]["mininet_stopped"] = True
            except Exception as ex:
                summary_data["cleanup_outcome"]["mininet_stop_error"] = str(ex)

        # Update summary with collected windows and sample counts
        summary_data["total_windows_observed"] = len(results)
        summary_data["total_rtt_samples_collected"] = sum(
            w["delay_metrics"]["exact_reply_samples_count"]
            for w in results
            if "delay_metrics" in w and "exact_reply_samples_count" in w["delay_metrics"]
        )
        summary_data["windows"] = results

        # Guaranteed writing of summary.json on both success and failure
        summary_path = out_dir / "summary.json"
        summary_path.write_text(json.dumps(summary_data, indent=2) + "\n")
        print(f"Summary saved to: {summary_path}")

    print(f"\n[DONE] Periodic delay check finished with status: {summary_data['status']}")
    return summary_data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Sensor-Only Periodic Delay & QoS Integration Check"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--live",
        action="store_true",
        help="Run live Mininet test with concurrent ping (requires root)",
    )
    group.add_argument(
        "--mock",
        action="store_true",
        help="Run offline mock test without Mininet",
    )
    args = parser.parse_args()

    if args.live:
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        if not is_root:
            sys.exit("Error: --live mode requires root privileges (run with sudo).")

    run_live_periodic_delay(live=args.live, mock=args.mock)
