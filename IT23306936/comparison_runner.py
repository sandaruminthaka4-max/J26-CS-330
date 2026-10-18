#!/usr/bin/env python3
"""Three-Host Matched Comparison Evaluation Runner.

Executes a counterbalanced comparison between three mitigation scenarios
on the 3-host Mininet topology (h1 medical sensor, h2 edge receiver, h3 attacker, s1 switch):
1. Baseline: Unmitigated (5 Mbit/s DoS traffic from h3 competes with 100 Kbit/s sensor traffic from h1)
2. Static: Scoped OpenFlow drop rule on h3 -> h2 UDP dst port 5201
3. Adaptive: Scoped OVS meter rate limiting (1000 Kbit/s initial, at most one adjustment to 500 Kbit/s based on measured QoS)

Architecture & Experimental Protocol:
- DIRECT-OVS POLICY COMPARISON: The comparison runner executes direct OpenFlow rules and OVS meters
  at deterministic predefined observation boundaries. It does NOT post alerts through the Flask API or
  evaluate real anomaly detector pipelines. This is labeled honestly as a direct-OVS policy evaluation.
- THREE-HOST TOPOLOGY: Consumes TOPOLOGY_CONFIG from topology_profile.py.
  Isolates the competitor adversary on h3, sensor on h1, receiver on h2.
- COUNTERBALANCED PERMUTATION SCHEDULE:
  Replaces simplistic "ABBA" scheduling with full 6-permutation Latin-square blocks.
  All six permutations of (baseline, static_block, adaptive) are used with a reproducible seed.
  Saves planned_schedule.json before executing any traffic and reports position/order balance.
- TRAFFIC & TIMING MATCHING:
  h1: sensor 10.0.0.1 -> h2 UDP 5202, 100 Kbit/s, 1000-byte payload, 60s duration.
  h3: load 10.0.0.3 -> h2 UDP 5201, 5 Mbit/s, 1000-byte payload, 70s duration.
  Attacker load remains active throughout all evaluated sensor windows.
  Trigger for static/adaptive actions occurs at the exact same predefined point: after Window 1.
- SIX PREDEFINED ~10-SECOND WINDOWS:
  Window 1 (0-10s): Pre-mitigation observation.
  Window 2 (10-20s): Initial enforcement transition window (retained in raw data, explicitly labeled).
  Window 3 (20-30s): Post-enforcement observation (adaptive triggers single adjustment if degraded and eligible).
  Window 4 (30-40s): Adjustment transition window (if adjusted).
  Window 5 (40-50s): Post-adjustment observation.
  Window 6 (50-60s): Predefined final observation window evaluated identically for all scenarios.
- SHARED STRICT MEASUREMENT VALIDATOR (Windows 3 and 6):
  Requires complete predefined windows with 5 contiguous valid receiver intervals, consistent duration,
  valid finite metrics, explicit fresh publication, and explicit load/transition eligibility.
  Validated against predefined observation boundaries with documented timing tolerances.
  Missing or invalid measurements are labeled not_evaluated or measurement_invalid_or_incomplete
  and are NEVER counted as measured QoS degradations or failures.
- FIXED ADAPTIVE SCHEDULE:
  Initial action after W1; W2 transition; only W3 may authorize one adjustment; W4 transition if adjusted;
  W5 recovery observation; W6 final comparison. No late adjustments or fallback final windows.
- SEPARATED RTT VALIDITY FROM SENSOR UDP QOS:
  PeriodicDelayMonitor records reply arrival half-open windows. Reader errors or ping exits
  exclude RTT from RTT statistics without invalidating otherwise valid UDP measurements.
  ICMP sent/loss remain null without verified send accounting.
- DIAGNOSTIC PRESERVATION & AUDITABLE CLEANUP:
  Records commands, PIDs, observed exit timestamps, return codes, receiver error events, and cleanup signals
  for all traffic processes before raising exceptions.
  Distinguishes process lifetime from measured traffic duration.
  Stops and reaps only this run's processes. Bounded joins on reader threads before closing files.
  Any unresolved process or thread fails cleanup and halts subsequent runs to protect the testbed.

Usage:
    Live VM diagnostic run (1 repeat per scenario = 3 runs total):
        sudo PYTHONPATH=/usr/lib/python3/dist-packages /home/sahan/iomt-research/.venv/bin/python comparison_runner.py --live --repeats 1

    Live full evaluation (10 repeats per scenario = 30 runs total):
        sudo PYTHONPATH=/usr/lib/python3/dist-packages /home/sahan/iomt-research/.venv/bin/python comparison_runner.py --live --repeats 10

    Offline mock verification:
        python comparison_runner.py --mock --repeats 1
"""

import argparse
import copy
import csv
import itertools
import json
import math
import os
import random
import statistics
import subprocess
import sys
import threading
import time
import traceback
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

BASE = Path(__file__).resolve().parent
RESULTS_DIR = BASE / "results"

from context_store_v2 import ContextStore
from delay_reader_v2 import PeriodicDelayMonitor
from live_qos_bridge_v2 import LiveQoSBridge
from ovs_enforcement_v2 import OVSEnforcer
from receiver_callback_monitor import ReceiverStreamMonitor
from qos_window_v2 import aggregate_receiver_window
from qos_review import review_sensor_qos
from topology_profile import TOPOLOGY_CONFIG, build_mininet_topology

SCENARIOS = ["baseline", "static_block", "adaptive"]
ALL_PERMUTATIONS: List[Tuple[str, ...]] = list(itertools.permutations(SCENARIOS))

# Documented timing tolerance for predefined observation boundaries (seconds)
TIMING_TOLERANCE_SECONDS = 1.5


def emit_live_stream_event(run_id, scen, w_record, live, stage=None, action=None, rate_limit=None):
    """Appends live/mock telemetry envelope event to logs/live_telemetry_stream.jsonl."""
    try:
        stream_file = RESULTS_DIR.parent / "logs" / "live_telemetry_stream.jsonl"
        stream_file.parent.mkdir(parents=True, exist_ok=True)
        from telemetry_contract import (
            TelemetryEnvelope, TelemetryFreshness, TrafficMetrics,
            MeasurementValidity, QoSOutcome, MitigationState, LifecycleState, SCHEMA_VERSION
        )
        qos_pass = w_record.get("qos_satisfied")
        env = TelemetryEnvelope(
            schema_version=SCHEMA_VERSION,
            mode="LIVE" if live else "DEMO",
            provenance="live_kernel_telemetry" if live else "synthetic_simulation",
            run_id=str(run_id),
            scenario=scen,
            event_id=f"evt_{run_id}_{w_record.get('window_index')}",
            window_index=w_record.get("window_index"),
            metrics=TrafficMetrics(
                sensor_throughput_kbps=w_record.get("receiver_kbps"),
                sensor_packet_loss_percent=w_record.get("packet_loss_percent"),
                icmp_rtt_avg_ms=w_record.get("icmp_reply_rtt_avg_ms"),
            ),
            validity=MeasurementValidity(
                measurement_valid=bool(w_record.get("published_fresh") is True and not w_record.get("is_confounded") and not w_record.get("is_transition_window")),
                is_transition_window=bool(w_record.get("is_transition_window")),
                transition_type=w_record.get("transition_type"),
            ),
            qos=QoSOutcome(
                status="PASS" if qos_pass is True else ("FAIL" if qos_pass is False else "UNAVAILABLE"),
                passed=qos_pass,
            ),
            mitigation=MitigationState(
                executed_action=action or ("rate_limit" if scen == "adaptive" else ("block" if scen == "static_block" else "none")),
                rate_limit_kbps=rate_limit or (1000 if scen == "adaptive" else None),
            ),
            lifecycle=LifecycleState(stage=stage or "normal_monitoring"),
            freshness=TelemetryFreshness(status="fresh"),
        )
        with stream_file.open("a", encoding="utf-8") as f_st:
            f_st.write(json.dumps(env.to_dict()) + "\n")
    except Exception:
        pass


class TrafficProcessRecord:
    """Auditable observation record for an individual process in this evaluation run."""

    def __init__(
        self,
        name: str,
        host_name: str,
        cmd: List[str],
        popen_obj: Any,
        configured_duration_seconds: Optional[float] = None,
    ):
        self.name = name
        self.host_name = host_name
        self.cmd = list(cmd)
        self.proc = popen_obj
        self.pid = getattr(popen_obj, "pid", None)
        self.started_mono = time.monotonic()
        self.started_unix = time.time()
        self.exit_mono: Optional[float] = None
        self.exit_unix: Optional[float] = None
        self.returncode: Optional[int] = None
        self.cleanup_signals: List[str] = []
        self.configured_duration_seconds = configured_duration_seconds

    def poll_exit(self) -> Optional[int]:
        if self.proc is None:
            return self.returncode
        rc = self.proc.poll()
        if rc is not None and self.returncode is None:
            self.returncode = rc
            self.exit_mono = time.monotonic()
            self.exit_unix = time.time()
        return self.returncode

    def record_exit(self, returncode: int):
        if self.returncode is None:
            self.returncode = returncode
            self.exit_mono = time.monotonic()
            self.exit_unix = time.time()

    def to_dict(self) -> Dict[str, Any]:
        self.poll_exit()
        lifetime = (
            round(self.exit_mono - self.started_mono, 3)
            if (self.exit_mono is not None and self.started_mono is not None)
            else None
        )
        return {
            "name": self.name,
            "host": self.host_name,
            "command": list(self.cmd),
            "pid": self.pid,
            "started_monotonic": self.started_mono,
            "started_unix": self.started_unix,
            "exit_monotonic": self.exit_mono,
            "exit_unix": self.exit_unix,
            "process_lifetime_seconds": lifetime,
            "configured_duration_seconds": self.configured_duration_seconds,
            "returncode": self.returncode,
            "cleanup_signals": list(self.cleanup_signals),
        }


class DiagnosticReceiverStreamMonitor(ReceiverStreamMonitor):
    """Extends ReceiverStreamMonitor to preserve receiver error events and retain interval evidence."""

    def __init__(self, process, raw_output):
        super().__init__(process, raw_output)
        self.receiver_error_events: List[Dict[str, Any]] = []

    def collect(self):
        try:
            for line in self.process.stdout:
                self.raw_output.write(line)
                self.raw_output.flush()
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    event = json.loads(line_str)
                except Exception:
                    continue

                if event.get("event") == "error":
                    self.receiver_error_events.append(deepcopy(event))
                    print(f"LIVE RECEIVER ERROR EVENT: {json.dumps(event)}", flush=True)

                if event.get("event") == "start":
                    self.pending_intervals = []
                if event.get("event") != "interval":
                    continue

                summary = event.get("data", {}).get("sum", {})
                if summary.get("sender") is not False:
                    raise ValueError("Expected receiver interval")
                if summary.get("omitted", False):
                    continue
                if summary.get("seconds", 0) <= 0:
                    continue

                sample = {
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                    "observed_monotonic": time.monotonic(),
                    "interval_start_seconds": summary["start"],
                    "interval_end_seconds": summary["end"],
                    "interval_duration_seconds": summary["seconds"],
                    "receiver_kbps": round(summary["bits_per_second"] / 1000, 3),
                    "packet_loss_percent": summary["lost_percent"],
                    "lost_packets": summary["lost_packets"],
                    "packets": summary["packets"],
                    "jitter_ms": summary.get("jitter_ms"),
                }
                self.samples.append(sample)
                self.pending_intervals.append(deepcopy(summary))

                if len(self.pending_intervals) == 5:
                    window = aggregate_receiver_window(self.pending_intervals, minimum_seconds=9.9)
                    window["intervals"] = deepcopy(self.pending_intervals)
                    window["observed_at"] = sample["observed_at"]
                    window["observed_monotonic"] = sample["observed_monotonic"]
                    window["qos_review"] = review_sensor_qos(window)
                    self.windows.append(window)
                    if self.on_window is not None:
                        self.on_window(deepcopy(window))
                    print("LIVE QOS WINDOW:", json.dumps(window), flush=True)
                    self.pending_intervals = []
                print("LIVE RECEIVER SAMPLE:", json.dumps(sample), flush=True)
        except Exception as error:
            self.error = error


def build_permutation_schedule(repeats: int, seed: int = 42) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Builds a counterbalanced schedule using complete 6-permutation blocks."""
    rng = random.Random(seed)
    schedule: List[Dict[str, Any]] = []

    full_blocks = repeats // 6
    remainder = repeats % 6

    perm_sequence: List[Tuple[str, ...]] = []
    for _ in range(full_blocks):
        block = list(ALL_PERMUTATIONS)
        rng.shuffle(block)
        perm_sequence.extend(block)

    if remainder > 0:
        partial = list(ALL_PERMUTATIONS)
        rng.shuffle(partial)
        perm_sequence.extend(partial[:remainder])

    repeat_tracker: Dict[str, int] = {s: 0 for s in SCENARIOS}
    position_counts: Dict[str, Dict[int, int]] = {s: {1: 0, 2: 0, 3: 0} for s in SCENARIOS}
    precedence_counts: Dict[str, Dict[str, int]] = {s1: {s2: 0 for s2 in SCENARIOS if s2 != s1} for s1 in SCENARIOS}

    for perm_idx, perm in enumerate(perm_sequence):
        for pos_idx, scen in enumerate(perm):
            pos_1based = pos_idx + 1
            repeat_tracker[scen] += 1
            position_counts[scen][pos_1based] += 1

            for other_scen in perm[pos_idx + 1:]:
                precedence_counts[scen][other_scen] += 1

            run_entry = {
                "run_id": len(schedule) + 1,
                "permutation_block_index": perm_idx + 1,
                "position_in_permutation": pos_1based,
                "scenario": scen,
                "repeat_index": repeat_tracker[scen],
            }
            schedule.append(run_entry)

    ideal_per_position = repeats / 3.0
    imbalance: Dict[str, Any] = {}
    for scen in SCENARIOS:
        imbalance[scen] = {
            f"position_{p}": position_counts[scen][p] for p in (1, 2, 3)
        }
        imbalance[scen]["max_deviation_from_uniform"] = round(
            max(abs(position_counts[scen][p] - ideal_per_position) for p in (1, 2, 3)), 3
        )

    metadata = {
        "seed": seed,
        "repeats_per_scenario": repeats,
        "total_planned_runs": len(schedule),
        "total_permutations_used": len(perm_sequence),
        "is_perfectly_balanced": (remainder == 0),
        "position_counts": position_counts,
        "precedence_counts": precedence_counts,
        "residual_imbalance": imbalance,
    }

    return schedule, metadata


def compute_statistics_series(values: List[float]) -> Dict[str, Optional[float]]:
    """Calculates mean, sample SD, median, min, max for a numeric list."""
    if not values:
        return {
            "mean": None,
            "sample_sd": None,
            "median": None,
            "min": None,
            "max": None,
            "count": 0,
        }
    return {
        "mean": round(statistics.mean(values), 3),
        "sample_sd": round(statistics.stdev(values), 3) if len(values) > 1 else None,
        "median": round(statistics.median(values), 3),
        "min": round(min(values), 3),
        "max": round(max(values), 3),
        "count": len(values),
    }


def validate_window_measurement(
    window: Optional[Dict[str, Any]],
    expected_window_index: int,
    timing_tolerance_seconds: float = TIMING_TOLERANCE_SECONDS,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Shared strict measurement validator for observation windows (Windows 3 and 6).

    Requirements:
    - Target window present with matching window_index
    - interval_count explicitly present and equal to 5 (never defaulted)
    - If raw interval evidence is present: exactly 5 contiguous valid non-omitted receiver intervals
    - published_fresh explicitly present and exactly True (never defaulted)
    - Valid, finite timing values (start, end, duration) with duration >= 9.9s and end > start
    - Start and end boundaries within predefined observation boundary tolerance
    - Valid, finite throughput and packet loss metrics
    - Not confounded by load generator cessation or startup
    - Not marked as a transition window
    - Explicitly eligible for evaluation

    Missing or invalid QoS results in (None, failure_reason), never degradation.
    """
    if window is None:
        return None, f"window_{expected_window_index}_missing (run terminated before window {expected_window_index})"

    actual_index = window.get("window_index")
    if actual_index != expected_window_index:
        return None, f"window_{expected_window_index}_index_mismatch (found {actual_index})"

    # 1. Fail closed on missing or invalid interval_count (do NOT default to 5)
    if "interval_count" not in window or window["interval_count"] is None:
        return None, f"window_{expected_window_index}_missing_interval_count"
    int_count = window["interval_count"]
    if not isinstance(int_count, int) or isinstance(int_count, bool) or int_count != 5:
        return None, f"window_{expected_window_index}_incomplete_intervals (found {int_count}, expected 5)"

    # 2. Fail closed on missing or stale published_fresh (do NOT default to True)
    if "published_fresh" not in window or window["published_fresh"] is None:
        return None, f"window_{expected_window_index}_missing_published_fresh"
    if window["published_fresh"] is not True:
        return None, f"window_{expected_window_index}_stale_qos (published_fresh is not True)"

    # 3. Fail closed on missing or non-finite timing values
    for t_key in ("window_start_seconds", "window_end_seconds", "window_duration_seconds"):
        if t_key not in window or window[t_key] is None:
            return None, f"window_{expected_window_index}_missing_{t_key}"
        val = window[t_key]
        if isinstance(val, bool) or not isinstance(val, (int, float)) or not math.isfinite(val):
            return None, f"window_{expected_window_index}_non_finite_{t_key} ({val})"

    start = float(window["window_start_seconds"])
    end = float(window["window_end_seconds"])
    duration = float(window["window_duration_seconds"])

    if end <= start:
        return None, f"window_{expected_window_index}_invalid_timing_order (end {end} <= start {start})"
    if duration < 9.9:
        return None, f"window_{expected_window_index}_duration_too_short (duration {duration:.2f}s < 9.9s)"
    if abs((end - start) - duration) > 0.15:
        return None, f"window_{expected_window_index}_inconsistent_duration (span {end - start:.2f}s != duration {duration:.2f}s)"

    # 4. Predefined observation boundaries check with documented timing tolerances
    expected_start = (expected_window_index - 1) * 10.0
    expected_end = expected_window_index * 10.0
    if abs(start - expected_start) > timing_tolerance_seconds:
        return None, f"window_{expected_window_index}_start_boundary_out_of_tolerance (start={start:.2f}s, expected={expected_start:.2f}s, tol={timing_tolerance_seconds}s)"
    if abs(end - expected_end) > timing_tolerance_seconds:
        return None, f"window_{expected_window_index}_end_boundary_out_of_tolerance (end={end:.2f}s, expected={expected_end:.2f}s, tol={timing_tolerance_seconds}s)"

    # 5. Interval evidence verification if raw intervals are retained
    intervals = window.get("intervals")
    if intervals is not None:
        if not isinstance(intervals, list) or len(intervals) != 5:
            return None, f"window_{expected_window_index}_invalid_interval_evidence (expected 5 intervals, found {len(intervals) if isinstance(intervals, list) else type(intervals)})"
        prev_end = None
        interval_dur_sum = 0.0
        for iv_idx, iv in enumerate(intervals):
            if not isinstance(iv, dict):
                return None, f"window_{expected_window_index}_interval_{iv_idx}_invalid_type"
            if iv.get("sender") is True or iv.get("omitted") is True:
                return None, f"window_{expected_window_index}_interval_{iv_idx}_invalid_source"
            for k in ("start", "end", "seconds"):
                v = iv.get(k)
                if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
                    return None, f"window_{expected_window_index}_interval_{iv_idx}_non_finite_{k}"
            iv_s, iv_e, iv_d = float(iv["start"]), float(iv["end"]), float(iv["seconds"])
            if iv_d <= 0 or iv_e <= iv_s:
                return None, f"window_{expected_window_index}_interval_{iv_idx}_invalid_timing"
            if prev_end is not None and abs(iv_s - prev_end) > 0.05:
                return None, f"window_{expected_window_index}_intervals_non_contiguous (gap between {prev_end:.2f}s and {iv_s:.2f}s)"
            prev_end = iv_e
            interval_dur_sum += iv_d
        if abs(interval_dur_sum - duration) > 0.15:
            return None, f"window_{expected_window_index}_interval_duration_mismatch (intervals sum {interval_dur_sum:.2f}s != duration {duration:.2f}s)"

    # 6. Fail closed on missing or non-finite throughput
    if "receiver_kbps" not in window or window["receiver_kbps"] is None:
        return None, f"window_{expected_window_index}_missing_throughput"
    tp = window["receiver_kbps"]
    if isinstance(tp, bool) or not isinstance(tp, (int, float)) or not math.isfinite(tp) or tp < 0:
        return None, f"window_{expected_window_index}_invalid_throughput ({tp})"

    # 7. Fail closed on missing or non-finite loss
    if "packet_loss_percent" not in window or window["packet_loss_percent"] is None:
        return None, f"window_{expected_window_index}_missing_loss"
    loss = window["packet_loss_percent"]
    if isinstance(loss, bool) or not isinstance(loss, (int, float)) or not math.isfinite(loss) or loss < 0 or loss > 100:
        return None, f"window_{expected_window_index}_invalid_loss ({loss})"

    # 8. Fail closed on confounding and transition status
    if window.get("is_confounded"):
        reason = window.get("confounding_reason", "load_not_active")
        return None, f"window_{expected_window_index}_confounded_by_load ({reason})"
    if window.get("is_transition_window"):
        return None, f"window_{expected_window_index}_is_transition_window ({window.get('transition_reason', 'transition')})"
    if window.get("eligible_for_evaluation") is False:
        return None, f"window_{expected_window_index}_ineligible_for_evaluation"

    return window, None


def validate_final_window(
    windows: List[Dict[str, Any]],
    timing_tolerance_seconds: float = TIMING_TOLERANCE_SECONDS,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Strictly validates predefined Window 6 using the shared measurement validator."""
    w6 = None
    for w in windows:
        if w.get("window_index") == 6:
            w6 = w
            break

    if w6 is None:
        return None, "window_6_missing (run terminated before sixth receiver window)"

    return validate_window_measurement(w6, expected_window_index=6, timing_tolerance_seconds=timing_tolerance_seconds)


def finalize_rtt_collection(
    delay_monitor: PeriodicDelayMonitor,
    ping_proc_rec: Optional[TrafficProcessRecord],
    ping_reader_errors: List[str],
    ping_err_file: Optional[Path],
    windows: List[Dict[str, Any]],
    sensor_launch_unix: Optional[float],
) -> Dict[str, Any]:
    """Finalizes RTT accounting across windows and whole run, preserving any errors and keeping ICMP sent/loss null."""
    ping_exit = ping_proc_rec.poll_exit() if ping_proc_rec else None
    ping_stderr = ""
    if ping_err_file and ping_err_file.exists():
        try:
            ping_stderr = ping_err_file.read_text(encoding="utf-8", errors="replace").strip()
        except Exception:
            pass

    if ping_reader_errors:
        status = "reader_error"
    elif ping_exit not in (0, None, -15):  # -15 is SIGTERM
        status = "unexpected_exit"
    else:
        status = "completed"

    if sensor_launch_unix is not None:
        for w in windows:
            w_start_u = sensor_launch_unix + w.get("window_start_seconds", 0.0)
            w_end_u = sensor_launch_unix + w.get("window_end_seconds", 0.0)
            d_metrics = delay_monitor.get_window_metrics(w_start_u, w_end_u)
            w["icmp_reply_rtt_avg_ms"] = d_metrics.get("rtt_avg_ms")
            w["icmp_reply_rtt_min_ms"] = d_metrics.get("rtt_min_ms")
            w["icmp_reply_rtt_max_ms"] = d_metrics.get("rtt_max_ms")
            w["icmp_reply_rtt_status"] = d_metrics.get("rtt_status")
            w["icmp_reply_rtt_reason"] = d_metrics.get("rtt_reason")
            w["icmp_reply_count"] = d_metrics.get("received_packets")
            w["icmp_sent_packets"] = None  # without verified send accounting, sent count is null
            w["icmp_packet_loss_percent"] = None  # without verified send accounting, loss is null

    return {
        "collection_status": status,
        "exit_code": ping_exit,
        "reader_errors": list(ping_reader_errors),
        "stderr": ping_stderr if ping_stderr else None,
        "rtt_accounting_model": "reply_arrival_half_open",
        "window_alignment_limitation": "launch_time_estimated_half_open_windows",
        "send_accounting": "unverified (icmp_sent_packets and icmp_packet_loss_percent null)",
    }


def extract_receiver_events(run_dir: Path) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Scans receiver.jsonl to extract all logged events and error events."""
    raw_path = run_dir / "receiver.jsonl"
    events = []
    error_events = []
    if raw_path.exists():
        try:
            for line in raw_path.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    ev = json.loads(line)
                    events.append(ev)
                    if ev.get("event") == "error":
                        error_events.append(ev)
                except json.JSONDecodeError:
                    continue
        except Exception:
            pass
    return events, error_events


def run_single_iteration_live(
    run_info: Dict[str, Any],
    out_dir: Path,
    services: Dict[str, Any],
    store: ContextStore,
) -> Dict[str, Any]:
    """Executes a single live test run on the 3-host Mininet topology."""
    scen = run_info["scenario"]
    run_id = run_info["run_id"]
    run_dir = out_dir / f"run_{run_id:03d}_{scen}"
    run_dir.mkdir(parents=True, exist_ok=True)

    net = None
    proc_records: Dict[str, TrafficProcessRecord] = {}
    open_file_handles: List[Any] = []
    enforcer = OVSEnforcer(services)
    stop_signal = threading.Event()
    callback_error = [None]
    load_client = None
    t_ping = None
    monitor = None

    timing_holder = {
        "load_started_mono": None,
        "load_started_unix": None,
        "load_ended_mono": None,
        "load_ended_unix": None,
        "measured_load_duration_seconds": None,
        "sensor_launch_mono": None,
        "sensor_launch_unix": None,
        "sensor_ended_mono": None,
        "sensor_ended_unix": None,
        "measured_sensor_duration_seconds": None,
    }

    windows: List[Dict[str, Any]] = []
    enforcement_evidence: Dict[str, Any] = {}
    action_state = {
        "stage": "pending",
        "completed_at": None,
        "adaptive_adjusted": False,
        "enforcement_latency_ms": None,
    }

    run_record: Dict[str, Any] = {
        "run_id": run_id,
        "scenario": scen,
        "repeat_index": run_info["repeat_index"],
        "permutation_block_index": run_info["permutation_block_index"],
        "position_in_permutation": run_info["position_in_permutation"],
        "architecture_type": "direct_ovs_policy_comparison",
        "is_synthetic": False,
        "execution_status": "in_progress",
        "execution_error": None,
        "measurement_status": "in_progress",
        "measurement_invalidation_reason": None,
        "timing_observations": timing_holder,
        "process_observations": {},
        "actual_sender_rates": {"sensor_sent_kbps": None, "load_sent_kbps": None},
        "receiver_error_events": [],
        "windows": [],
        "final_observation_window": None,
        "whole_run": {
            "sensor_kbps": None,
            "sensor_loss_pct": None,
            "icmp_reply_rtt_avg_ms": None,
            "qos_passed": None,
        },
        "qos_passed": None,
        "ping_collection": {},
        "enforcement_evidence": {},
        "cleanup_outcome": {},
    }

    try:
        # 1. Collision guard: inspect s1 existence. Treat inspection errors as fatal.
        try:
            check_s1 = subprocess.run(["ovs-vsctl", "br-exists", "s1"], capture_output=True, text=True)
        except Exception as ex:
            raise RuntimeError(f"OVS inspection error checking 's1' existence: {ex}")

        if check_s1.returncode == 0:
            raise RuntimeError(f"Collision guard: OVS bridge 's1' already exists before run {run_id}. Refusing startup.")
        elif check_s1.returncode != 2:
            raise RuntimeError(f"OVS inspection error on 's1' (exit {check_s1.returncode}): {check_s1.stderr.strip()}")

        sys.path.append("/usr/lib/python3/dist-packages")
        from mininet.net import Mininet
        from mininet.node import OVSBridge
        from mininet.link import TCLink

        net = Mininet(controller=None, switch=OVSBridge, link=TCLink)
        topo = build_mininet_topology(net)
        h1, h2, h3, s1 = topo["h1"], topo["h2"], topo["h3"], topo["s1"]
        net.start()

        if net.pingAll() != 0:
            raise RuntimeError(f"Initial 3-host Mininet ping connectivity check failed for run {run_id}")

        # 2. Prepare file handles for servers and clients
        raw_receiver = (run_dir / "receiver.jsonl").open("w")
        receiver_err = (run_dir / "receiver_stderr.txt").open("w")
        load_server_out = (run_dir / "load_server_stdout.txt").open("w")
        load_server_err = (run_dir / "load_server_stderr.txt").open("w")
        sensor_client_out = (run_dir / "sensor_client.json").open("w")
        sensor_client_err = (run_dir / "sensor_client_stderr.txt").open("w")
        load_client_out = (run_dir / "load_client.json").open("w")
        load_client_err = (run_dir / "load_client_stderr.txt").open("w")
        raw_ping_file = run_dir / "raw_ping.txt"
        ping_err = (run_dir / "ping_stderr.txt").open("w")

        open_file_handles.extend([
            raw_receiver, receiver_err,
            load_server_out, load_server_err,
            sensor_client_out, sensor_client_err,
            load_client_out, load_client_err,
            ping_err,
        ])

        # 3. Start receiver servers on h2
        sensor_server_cmd = ["iperf3", "-s", "-1", "-p", "5202", "--json-stream", "--forceflush", "-i", "2"]
        sensor_server = h2.popen(
            sensor_server_cmd,
            stdout=subprocess.PIPE,
            stderr=receiver_err,
            text=True,
        )
        proc_records["sensor_server"] = TrafficProcessRecord("sensor_server", "h2", sensor_server_cmd, sensor_server)

        load_server_cmd = ["iperf3", "-s", "-1", "-p", "5201"]
        load_server = h2.popen(
            load_server_cmd,
            stdout=load_server_out,
            stderr=load_server_err,
        )
        proc_records["load_server"] = TrafficProcessRecord("load_server", "h2", load_server_cmd, load_server)

        time.sleep(1)
        if sensor_server.poll() is not None:
            proc_records["sensor_server"].record_exit(sensor_server.poll())
            raise RuntimeError(f"Sensor server exited prematurely with code {sensor_server.poll()}")
        if load_server.poll() is not None:
            proc_records["load_server"].record_exit(load_server.poll())
            raise RuntimeError(f"Load server exited prematurely with code {load_server.poll()}")

        # 4. Initialize delay monitor and diagnostic receiver stream monitor
        delay_monitor = PeriodicDelayMonitor(raw_log_file=raw_ping_file)
        monitor = DiagnosticReceiverStreamMonitor(sensor_server, raw_receiver)
        bridge_holder: Dict[str, Any] = {}

        def on_window(window):
            try:
                bridge = bridge_holder.get("bridge")
                if bridge is None:
                    return

                now_mono = time.monotonic()
                w_abs_start = bridge.client_launch + window["window_start_seconds"]
                w_abs_end = bridge.client_launch + window["window_end_seconds"]
                w_idx = len(windows) + 1

                # Check competitor load generator status
                load_poll = load_client.poll() if load_client is not None else -1
                load_is_running = (load_client is not None and load_poll is None)
                if load_client is not None and load_poll is not None and timing_holder["load_ended_mono"] is None:
                    timing_holder["load_ended_mono"] = now_mono
                    timing_holder["load_ended_unix"] = time.time()
                    proc_records["load_client"].record_exit(load_poll)

                is_confounded = False
                confounding_reason = None
                if timing_holder["load_started_mono"] is not None and w_abs_start < timing_holder["load_started_mono"]:
                    is_confounded = True
                    confounding_reason = "window_started_before_load_generator_startup"
                elif timing_holder["load_ended_mono"] is not None and w_abs_end >= timing_holder["load_ended_mono"]:
                    is_confounded = True
                    confounding_reason = "window_overlaps_or_follows_load_cessation"
                elif not load_is_running:
                    is_confounded = True
                    confounding_reason = "load_generator_not_active"

                if load_is_running:
                    store.publish_flow("ECG_Monitoring", {
                        "source_ip": "10.0.0.3",
                        "target_ip": "10.0.0.2",
                        "protocol": "udp",
                        "dst_port": 5201,
                    })

                pub = bridge.publish(window)
                published_fresh = pub.get("published", False)

                # Transition window check against actual enforcement completion timestamp and explicit schedule rules
                is_transition_window = False
                transition_reason = None
                if scen in ("static_block", "adaptive"):
                    if w_idx == 2:
                        is_transition_window = True
                        transition_reason = "initial_enforcement_transition_window_2"
                    elif w_idx == 4 and action_state["adaptive_adjusted"]:
                        is_transition_window = True
                        transition_reason = "rate_adjustment_transition_window_4"
                    elif action_state["completed_at"] is not None and w_abs_start < action_state["completed_at"]:
                        is_transition_window = True
                        transition_reason = f"window_started_{round(action_state['completed_at'] - w_abs_start, 3)}s_before_enforcement_completed"

                eligible_for_evaluation = (not is_confounded) and (not is_transition_window) and (published_fresh is True)

                empirical_decision = window.get("qos_review", {}).get("decision")
                w_tp = window.get("receiver_kbps")
                w_loss = window.get("packet_loss_percent")
                qos_satisfied = (w_tp is not None and w_loss is not None and w_tp >= 90.0 and w_loss <= 1.0)

                # Extract RTT metrics for this exact half-open window using PeriodicDelayMonitor
                launch_u = timing_holder.get("sensor_launch_unix", time.time())
                w_start_u = launch_u + window.get("window_start_seconds", 0.0)
                w_end_u = launch_u + window.get("window_end_seconds", 0.0)
                d_metrics = delay_monitor.get_window_metrics(w_start_u, w_end_u)

                w_record = {
                    "window_index": w_idx,
                    "window_start_seconds": window.get("window_start_seconds"),
                    "window_end_seconds": window.get("window_end_seconds"),
                    "window_duration_seconds": window.get("window_duration_seconds"),
                    "interval_count": window.get("interval_count"),
                    "intervals": window.get("intervals"),
                    "receiver_kbps": w_tp,
                    "packet_loss_percent": w_loss,
                    "icmp_reply_rtt_avg_ms": d_metrics.get("rtt_avg_ms"),
                    "icmp_reply_rtt_min_ms": d_metrics.get("rtt_min_ms"),
                    "icmp_reply_rtt_max_ms": d_metrics.get("rtt_max_ms"),
                    "icmp_reply_rtt_status": d_metrics.get("rtt_status"),
                    "icmp_reply_rtt_reason": d_metrics.get("rtt_reason"),
                    "icmp_reply_count": d_metrics.get("received_packets"),
                    "icmp_sent_packets": None,  # unverified without dispatch timestamps
                    "icmp_packet_loss_percent": None,
                    "published_fresh": published_fresh,
                    "publication_reason": pub.get("reason"),
                    "qos_decision": empirical_decision,
                    "qos_satisfied": qos_satisfied,
                    "load_active": load_is_running and not is_confounded,
                    "is_confounded": is_confounded,
                    "confounding_reason": confounding_reason,
                    "is_transition_window": is_transition_window,
                    "transition_reason": transition_reason,
                    "eligible_for_evaluation": eligible_for_evaluation,
                    "action_taken": None,
                }

                # Enforcement logic at predefined trigger point: after Window 1 completes
                if w_idx == 1:
                    if scen == "baseline":
                        w_record["action_taken"] = "no_mitigation_baseline"
                        action_state["stage"] = "observing"

                    elif scen == "static_block":
                        t_before = time.monotonic()
                        plan_block = {
                            "action": "block",
                            "scope": {
                                "source_ip": "10.0.0.3",
                                "target_ip": "10.0.0.2",
                                "protocol": "udp",
                                "dst_port": 5201,
                            },
                            "duration_seconds": 300,
                        }
                        enforcer.apply(plan_block)
                        t_after = time.monotonic()
                        action_state["enforcement_latency_ms"] = round((t_after - t_before) * 1000, 3)
                        action_state["completed_at"] = t_after
                        action_state["stage"] = "mitigated_static"
                        w_record["action_taken"] = "static_block_applied"

                        enforcement_evidence["static_block"] = {
                            "latency_ms": action_state["enforcement_latency_ms"],
                            "flow_dump": enforcer.run(["dump-flows", "s1"]).stdout,
                            "cookie": f"0x{enforcer.cookie:x}",
                        }

                    elif scen == "adaptive":
                        t_before = time.monotonic()
                        plan_rate = {
                            "action": "rate_limit",
                            "scope": {
                                "source_ip": "10.0.0.3",
                                "target_ip": "10.0.0.2",
                                "protocol": "udp",
                                "dst_port": 5201,
                            },
                            "rate_limit_kbps": 1000,
                            "duration_seconds": 300,
                        }
                        enforcer.apply(plan_rate)
                        t_after = time.monotonic()
                        action_state["enforcement_latency_ms"] = round((t_after - t_before) * 1000, 3)
                        action_state["completed_at"] = t_after
                        action_state["stage"] = "observing_initial_limit"
                        w_record["action_taken"] = "adaptive_meter_1000kbps_applied"

                        enforcement_evidence["initial_meter"] = {
                            "latency_ms": action_state["enforcement_latency_ms"],
                            "rate_limit_kbps": 1000,
                            "flow_dump": enforcer.run(["dump-flows", "s1"]).stdout,
                            "meter_stats": enforcer.run(["meter-stats", "s1"]).stdout,
                            "cookie": f"0x{enforcer.cookie:x}",
                            "meter_id": enforcer.meter_id,
                        }

                elif w_idx == 3 and scen == "adaptive":
                    # Fixed adaptive protocol: make single adjustment decision at Window 3
                    # Validate Window 3 strictly using the shared measurement validator
                    valid_w3, invalid_reason_w3 = validate_window_measurement(
                        w_record, expected_window_index=3, timing_tolerance_seconds=TIMING_TOLERANCE_SECONDS
                    )
                    if valid_w3 is None:
                        # Missing or invalid measurement strictly means not_evaluated, never degradation
                        action_state["reassessment_outcome"] = "not_evaluated"
                        action_state["reassessment_reason"] = invalid_reason_w3
                        action_state["stage"] = "reassessment_not_evaluated"
                        w_record["action_taken"] = f"reassessment_not_evaluated: {invalid_reason_w3}"
                    else:
                        if not qos_satisfied or empirical_decision == "review_required":
                            # Degraded measured QoS: execute single rate adjustment to 500 Kbit/s
                            t_before = time.monotonic()
                            enforcer.cleanup()
                            plan_adjust = {
                                "action": "rate_limit",
                                "scope": {
                                    "source_ip": "10.0.0.3",
                                    "target_ip": "10.0.0.2",
                                    "protocol": "udp",
                                    "dst_port": 5201,
                                },
                                "rate_limit_kbps": 500,
                                "duration_seconds": 300,
                            }
                            enforcer.apply(plan_adjust)
                            t_after = time.monotonic()
                            action_state["adaptive_adjusted"] = True
                            action_state["completed_at"] = t_after
                            action_state["reassessment_outcome"] = "adjusted_to_500kbps"
                            action_state["reassessment_reason"] = f"qos_degraded (tp={w_tp}kbps, loss={w_loss}%, decision={empirical_decision})"
                            action_state["stage"] = "observing_adjusted_limit"
                            w_record["action_taken"] = "adaptive_meter_adjusted_to_500kbps"

                            enforcement_evidence["adjusted_meter"] = {
                                "latency_ms": round((t_after - t_before) * 1000, 3),
                                "rate_limit_kbps": 500,
                                "flow_dump": enforcer.run(["dump-flows", "s1"]).stdout,
                                "meter_stats": enforcer.run(["meter-stats", "s1"]).stdout,
                                "cookie": f"0x{enforcer.cookie:x}",
                                "meter_id": enforcer.meter_id,
                            }
                        else:
                            # Measured QoS passed: no adjustment needed, branch not exercised
                            action_state["reassessment_outcome"] = "not_exercised_measured_qos_passed"
                            action_state["reassessment_reason"] = f"qos_passed (tp={w_tp}kbps, loss={w_loss}%)"
                            action_state["stage"] = "observing_initial_limit_maintained"
                            w_record["action_taken"] = "reassessment_not_exercised_qos_passed"

                windows.append(w_record)
                with (run_dir / "windows.jsonl").open("a") as f_win:
                    f_win.write(json.dumps(w_record) + "\n")
                emit_live_stream_event(
                    run_id, scen, w_record, live=True,
                    stage=action_state.get("stage"),
                    action=w_record.get("action_taken"),
                    rate_limit=500 if action_state.get("adaptive_adjusted") else (1000 if scen == "adaptive" else None),
                )

            except Exception as ex:
                callback_error[0] = ex
                stop_signal.set()
                raise

        monitor.on_window = on_window
        monitor.start()

        # 5. Start concurrent ping on h1 with LC_ALL=C
        ping_env = dict(os.environ, LC_ALL="C")
        ping_cmd = ["ping", "-n", "-D", "-i", "1", "10.0.0.2"]
        ping_proc = h1.popen(
            ping_cmd,
            stdout=subprocess.PIPE,
            stderr=ping_err,
            text=True,
            env=ping_env,
        )
        proc_records["ping_proc"] = TrafficProcessRecord("ping_proc", "h1", ping_cmd, ping_proc)

        ping_reader_errors: List[str] = []

        def read_ping_stream(proc):
            try:
                for line in proc.stdout:
                    if stop_signal.is_set():
                        break
                    line_clean = line.strip()
                    if line_clean:
                        delay_monitor.feed_line(line_clean)
            except Exception as ex:
                ping_reader_errors.append(f"ping_reader_error: {ex}")

        t_ping = threading.Thread(target=read_ping_stream, args=(ping_proc,), daemon=True)
        t_ping.start()

        # 6. Start 100 Kbit/s UDP sensor stream on h1 (60s) prior to competitor load generator.
        # Startup sequencing: iperf3 initiates a control exchange before UDP streaming begins.
        # Launching the sensor stream and confirming receiver communication before starting the
        # 5 Mbit/s load generator allows observation of startup timing.
        # The load generator starts after receiver startup is confirmed (step 8).
        # timing_observations["load_started_mono"] records when load actually starts
        # relative to sensor launch, making the timing transparent.
        timing_holder["sensor_launch_mono"] = time.monotonic()
        timing_holder["sensor_launch_unix"] = time.time()
        bridge_holder["bridge"] = LiveQoSBridge(store, "ECG_Monitoring", timing_holder["sensor_launch_mono"])

        sensor_client_cmd = [
            "iperf3", "-c", "10.0.0.2", "-p", "5202", "-u", "-b", "100K", "-l", "1000",
            "-t", "60", "--pacing-timer", "1000", "--connect-timeout", "5000", "-J",
        ]
        sensor_client = h1.popen(
            sensor_client_cmd,
            stdout=sensor_client_out,
            stderr=sensor_client_err,
        )
        proc_records["sensor_client"] = TrafficProcessRecord(
            "sensor_client", "h1", sensor_client_cmd, sensor_client, configured_duration_seconds=60.0
        )

        # 7. Confirm receiver startup prior to competitor load generator.
        # Startup sequencing: verifies receiver communication before starting the competitor load.
        # Polls receiver.jsonl for iperf3 "start" or "error" events.
        # Deadline is 10s to accommodate process initialization.
        deadline_start = time.monotonic() + 10
        receiver_started = False
        raw_path = run_dir / "receiver.jsonl"
        while time.monotonic() < deadline_start:
            if callback_error[0] is not None:
                raise RuntimeError(f"Callback failure during startup: {callback_error[0]}")
            if sensor_client.poll() is not None:
                proc_records["sensor_client"].record_exit(sensor_client.poll())
                raise RuntimeError(f"Sensor client exited prematurely during startup (rc={sensor_client.poll()})")
            if raw_path.exists():
                for line in raw_path.read_text(encoding="utf-8", errors="replace").splitlines():
                    try:
                        ev = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if ev.get("event") == "error":
                        raise RuntimeError(f"Receiver iperf3 error event during startup: {ev.get('data')}")
                    if ev.get("event") == "start":
                        receiver_started = True
                        break
            if receiver_started:
                break
            time.sleep(0.05)
        if not receiver_started:
            raise RuntimeError("Receiver startup was not confirmed within deadline")

        # 8. Start 5 Mbit/s UDP load generator on h3 (70s) after sensor startup is confirmed.
        timing_holder["load_started_mono"] = time.monotonic()
        timing_holder["load_started_unix"] = time.time()
        load_client_cmd = [
            "iperf3", "-c", "10.0.0.2", "-p", "5201", "-u", "-b", "5M", "-l", "1000",
            "-t", "70", "--pacing-timer", "1000", "--connect-timeout", "5000", "-J",
        ]
        load_client = h3.popen(
            load_client_cmd,
            stdout=load_client_out,
            stderr=load_client_err,
        )
        proc_records["load_client"] = TrafficProcessRecord(
            "load_client", "h3", load_client_cmd, load_client, configured_duration_seconds=70.0
        )

        time.sleep(1)
        if load_client.poll() is not None:
            proc_records["load_client"].record_exit(load_client.poll())
            raise RuntimeError(f"Load client exited prematurely with code {load_client.poll()}")

        # 9. Wait for sensor completion (60s + 15s margin)
        deadline_sensor = time.monotonic() + 75
        while time.monotonic() < deadline_sensor:
            if callback_error[0] is not None:
                raise RuntimeError(f"Callback failure during sensor streaming: {callback_error[0]}")
            if sensor_client.poll() is not None:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("Sensor client timed out after 75s")
        sensor_rc = sensor_client.poll()
        proc_records["sensor_client"].record_exit(sensor_rc)
        timing_holder["sensor_ended_mono"] = time.monotonic()
        timing_holder["sensor_ended_unix"] = time.time()
        timing_holder["measured_sensor_duration_seconds"] = round(
            timing_holder["sensor_ended_mono"] - timing_holder["sensor_launch_mono"], 3
        )

        # 10. Wait for competitor load completion (70s total)
        deadline_load = time.monotonic() + 25
        while time.monotonic() < deadline_load:
            if callback_error[0] is not None:
                raise RuntimeError(f"Callback failure during load streaming: {callback_error[0]}")
            if load_client.poll() is not None:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("Load client timed out after 25s")
        load_rc = load_client.poll()
        proc_records["load_client"].record_exit(load_rc)
        if timing_holder["load_ended_mono"] is None:
            timing_holder["load_ended_mono"] = time.monotonic()
            timing_holder["load_ended_unix"] = time.time()
        timing_holder["measured_load_duration_seconds"] = round(
            timing_holder["load_ended_mono"] - timing_holder["load_started_mono"], 3
        )

        # Stop ping and servers, joining ping and monitor reader threads before closing files
        ping_proc_rc = None
        if ping_proc.poll() is None:
            proc_records["ping_proc"].cleanup_signals.append("SIGTERM")
            ping_proc.terminate()
            try:
                ping_proc_rc = ping_proc.wait(timeout=2)
                proc_records["ping_proc"].record_exit(ping_proc_rc)
            except subprocess.TimeoutExpired:
                proc_records["ping_proc"].cleanup_signals.append("SIGKILL")
                ping_proc.kill()
                try:
                    ping_proc_rc = ping_proc.wait(timeout=2)
                    proc_records["ping_proc"].record_exit(ping_proc_rc)
                except Exception as ex:
                    ping_reader_errors.append(f"ping_wait_error: {ex}")
        else:
            ping_proc_rc = ping_proc.poll()
            proc_records["ping_proc"].record_exit(ping_proc_rc)

        if t_ping is not None and t_ping.is_alive():
            t_ping.join(timeout=3)
            if t_ping.is_alive():
                ping_reader_errors.append("ping_reader_thread_join_timed_out")

        sensor_server_rc = None
        try:
            sensor_server_rc = sensor_server.wait(timeout=10)
            proc_records["sensor_server"].record_exit(sensor_server_rc)
        except Exception as ex:
            proc_records["sensor_server"].poll_exit()

        load_server_rc = None
        try:
            load_server_rc = load_server.wait(timeout=10)
            proc_records["load_server"].record_exit(load_server_rc)
        except Exception as ex:
            proc_records["load_server"].poll_exit()

        if monitor is not None and hasattr(monitor, "thread") and monitor.thread.is_alive():
            monitor.thread.join(timeout=3)

        if callback_error[0] is not None:
            raise RuntimeError(f"on_window callback failure: {callback_error[0]}")

        # Scan receiver events from monitor and file
        all_receiver_events, receiver_error_events = extract_receiver_events(run_dir)
        if monitor is not None and monitor.receiver_error_events:
            for ev in monitor.receiver_error_events:
                if ev not in receiver_error_events:
                    receiver_error_events.append(ev)

        # Finalize RTT collection regardless of run outcome
        ping_collection = finalize_rtt_collection(
            delay_monitor=delay_monitor,
            ping_proc_rec=proc_records.get("ping_proc"),
            ping_reader_errors=ping_reader_errors,
            ping_err_file=run_dir / "ping_stderr.txt",
            windows=windows,
            sensor_launch_unix=timing_holder.get("sensor_launch_unix"),
        )
        run_record["ping_collection"] = ping_collection

        # Whole-run RTT calculation strictly for sensor observation span
        s_start_u = timing_holder.get("sensor_launch_unix", time.time())
        whole_d_metrics = delay_monitor.get_window_metrics(s_start_u, s_start_u + 60.0)
        whole_rtt_avg = whole_d_metrics.get("rtt_avg_ms")

        # Parse client JSON outputs without fabricating missing end summaries or rates
        s_json = None
        s_err_msg = None
        sensor_json_file = run_dir / "sensor_client.json"
        if sensor_json_file.exists():
            try:
                s_text = sensor_json_file.read_text(encoding="utf-8", errors="replace").strip()
                if s_text:
                    s_json = json.loads(s_text)
            except Exception as ex:
                s_err_msg = f"Failed to parse sensor_client.json: {ex}"

        l_json = None
        load_json_file = run_dir / "load_client.json"
        if load_json_file.exists():
            try:
                l_text = load_json_file.read_text(encoding="utf-8", errors="replace").strip()
                if l_text:
                    l_json = json.loads(l_text)
            except Exception:
                pass

        sensor_sent_kbps = None
        if isinstance(s_json, dict) and isinstance(s_json.get("end"), dict):
            sum_sent = s_json["end"].get("sum_sent")
            if isinstance(sum_sent, dict) and "bits_per_second" in sum_sent and math.isfinite(sum_sent["bits_per_second"]):
                sensor_sent_kbps = round(sum_sent["bits_per_second"] / 1000.0, 3)

        load_sent_kbps = None
        if isinstance(l_json, dict) and isinstance(l_json.get("end"), dict):
            sum_sent = l_json["end"].get("sum_sent")
            if isinstance(sum_sent, dict) and "bits_per_second" in sum_sent and math.isfinite(sum_sent["bits_per_second"]):
                load_sent_kbps = round(sum_sent["bits_per_second"] / 1000.0, 3)

        run_record["actual_sender_rates"] = {
            "sensor_sent_kbps": sensor_sent_kbps,
            "load_sent_kbps": load_sent_kbps,
        }

        whole_loss = None
        whole_tp = None
        if isinstance(s_json, dict) and isinstance(s_json.get("end"), dict):
            sum_recv = s_json["end"].get("sum_received")
            if isinstance(sum_recv, dict):
                if "lost_percent" in sum_recv and math.isfinite(sum_recv["lost_percent"]):
                    whole_loss = round(float(sum_recv["lost_percent"]), 3)
                if "bits_per_second" in sum_recv and math.isfinite(sum_recv["bits_per_second"]):
                    whole_tp = round(float(sum_recv["bits_per_second"]) / 1000.0, 3)

        # Record observations BEFORE checking exit codes or raising exceptions
        run_record["process_observations"] = {name: rec.to_dict() for name, rec in proc_records.items()}
        run_record["timing_observations"] = dict(timing_holder)
        run_record["receiver_error_events"] = list(receiver_error_events)
        run_record["windows"] = list(windows)
        run_record["whole_run"] = {
            "sensor_kbps": whole_tp,
            "sensor_loss_pct": whole_loss,
            "icmp_reply_rtt_avg_ms": whole_rtt_avg,
            "qos_passed": (whole_tp is not None and whole_loss is not None and whole_tp >= 90.0 and whole_loss <= 1.0),
        }

        # 11. Verify process exit codes and error logs
        if sensor_rc != 0:
            s_err = (run_dir / "sensor_client_stderr.txt").read_text(encoding="utf-8", errors="replace").strip()
            err_detail = s_json.get("error") if isinstance(s_json, dict) else s_err_msg
            raise RuntimeError(f"Sensor client failed (code {sensor_rc}, error: {err_detail}): {s_err}")
        if load_rc != 0:
            l_err = (run_dir / "load_client_stderr.txt").read_text(encoding="utf-8", errors="replace").strip()
            raise RuntimeError(f"Load client failed (code {load_rc}): {l_err}")
        if sensor_server_rc != 0:
            ss_err = (run_dir / "receiver_stderr.txt").read_text(encoding="utf-8", errors="replace").strip()
            raise RuntimeError(f"Sensor server failed (code {sensor_server_rc}): {ss_err}")
        if load_server_rc != 0:
            ls_err = (run_dir / "load_server_stderr.txt").read_text(encoding="utf-8", errors="replace").strip()
            raise RuntimeError(f"Load server failed (code {load_server_rc}): {ls_err}")
        if monitor is not None and monitor.error is not None:
            raise RuntimeError(f"Receiver monitor reported stream error: {monitor.error}")
        if receiver_error_events:
            raise RuntimeError(f"Receiver emitted error event(s): {receiver_error_events}")
        if s_json is None or not isinstance(s_json, dict):
            raise RuntimeError(f"Sensor client output is missing or invalid JSON: {s_err_msg}")
        if "error" in s_json:
            raise RuntimeError(f"Sensor client JSON error: {s_json['error']}")
        if whole_tp is None or whole_loss is None:
            raise ValueError(f"Sensor client output is missing valid whole-run metrics in end.sum_received: {s_json.get('end')}")

        # 13. Strict final-window selection & validation (Predefined Window 6)
        valid_w6, invalid_reason = validate_final_window(windows)

        run_record["execution_status"] = "completed"

        if valid_w6 is not None:
            run_record["measurement_status"] = "completed_valid"
            run_record["final_observation_window"] = valid_w6
            run_record["qos_passed"] = valid_w6["qos_satisfied"]
        else:
            run_record["measurement_status"] = "measurement_invalid_or_incomplete"
            run_record["measurement_invalidation_reason"] = invalid_reason
            run_record["final_observation_window"] = None
            run_record["qos_passed"] = None  # NULL: missing/invalid measurement is not a QoS failure

        if scen == "adaptive":
            run_record["adaptive_reassessment"] = {
                "evaluated_at_window": 3,
                "outcome": action_state.get("reassessment_outcome"),
                "reason": action_state.get("reassessment_reason"),
                "adjusted": action_state.get("adaptive_adjusted", False),
            }

        run_record["enforcement_evidence"] = enforcement_evidence

    except Exception as e:
        run_record["execution_status"] = "failed"
        run_record["execution_error"] = str(e)
        run_record["traceback"] = traceback.format_exc()
        run_record["measurement_status"] = "execution_failed"
        run_record["qos_passed"] = None
        print(f"\n  [ERROR in Run {run_id} ({scen})]: {e}")

    finally:
        stop_signal.set()
        cleanup_outcome: Dict[str, Any] = {
            "all_clean": True,
            "process_reap_errors": [],
            "thread_join_errors": [],
            "file_close_errors": [],
            "unresolved_processes": [],
            "unresolved_threads": [],
            "cleanup_signals_issued": {},
            "enforcer_cleanup": None,
            "mininet_cleanup": None,
        }

        # 1. Stop and reap only this run's processes
        for name, p_rec in proc_records.items():
            proc = p_rec.proc
            if proc is not None:
                if proc.poll() is None:
                    try:
                        p_rec.cleanup_signals.append("SIGTERM")
                        proc.terminate()
                        try:
                            rc = proc.wait(timeout=2)
                            p_rec.record_exit(rc)
                        except subprocess.TimeoutExpired:
                            p_rec.cleanup_signals.append("SIGKILL")
                            proc.kill()
                            rc = proc.wait(timeout=2)
                            p_rec.record_exit(rc)
                    except Exception as ex:
                        cleanup_outcome["process_reap_errors"].append(f"{name} (pid {p_rec.pid}): {ex}")
                else:
                    p_rec.poll_exit()

                if proc.poll() is None:
                    cleanup_outcome["all_clean"] = False
                    cleanup_outcome["unresolved_processes"].append(f"{name} (pid {p_rec.pid}) still alive after wait")

            cleanup_outcome["cleanup_signals_issued"][name] = list(p_rec.cleanup_signals)

        # 2. Join both ping and receiver reader threads before closing their files
        if t_ping is not None:
            try:
                t_ping.join(timeout=3)
                if t_ping.is_alive():
                    cleanup_outcome["all_clean"] = False
                    cleanup_outcome["thread_join_errors"].append("ping_reader_thread still alive after bounded join")
                    cleanup_outcome["unresolved_threads"].append("ping_reader_thread")
            except Exception as ex:
                cleanup_outcome["all_clean"] = False
                cleanup_outcome["thread_join_errors"].append(f"ping_reader_thread join error: {ex}")

        if monitor is not None and getattr(monitor, "thread", None) is not None:
            try:
                monitor.thread.join(timeout=3)
                if monitor.thread.is_alive():
                    cleanup_outcome["all_clean"] = False
                    cleanup_outcome["thread_join_errors"].append("receiver_monitor_thread still alive after bounded join")
                    cleanup_outcome["unresolved_threads"].append("receiver_monitor_thread")
            except Exception as ex:
                cleanup_outcome["all_clean"] = False
                cleanup_outcome["thread_join_errors"].append(f"receiver_monitor_thread join error: {ex}")

        # 3. Close open file handles AFTER joining threads
        for fh in open_file_handles:
            try:
                if fh is not None and not getattr(fh, "closed", True):
                    fh.flush()
                    fh.close()
            except Exception as ex:
                cleanup_outcome["all_clean"] = False
                cleanup_outcome["file_close_errors"].append(str(ex))

        # 4. Cleanup enforcer rules
        try:
            enforcer.cleanup()
            cleanup_outcome["enforcer_cleanup"] = "completed"
        except Exception as ex:
            cleanup_outcome["all_clean"] = False
            cleanup_outcome["enforcer_cleanup"] = f"failed: {ex}"

        # 5. Stop Mininet
        if net is not None:
            try:
                net.stop()
                cleanup_outcome["mininet_cleanup"] = "completed"
            except Exception as ex:
                cleanup_outcome["all_clean"] = False
                cleanup_outcome["mininet_cleanup"] = f"failed: {ex}"

        if (
            cleanup_outcome["process_reap_errors"]
            or cleanup_outcome["thread_join_errors"]
            or cleanup_outcome["unresolved_processes"]
            or cleanup_outcome["unresolved_threads"]
            or cleanup_outcome["file_close_errors"]
            or cleanup_outcome["enforcer_cleanup"] != "completed"
            or (net is not None and cleanup_outcome["mininet_cleanup"] != "completed")
        ):
            cleanup_outcome["all_clean"] = False

        run_record["cleanup_outcome"] = cleanup_outcome

        # Refresh process observations with final exit statuses and cleanup signals
        run_record["process_observations"] = {name: rec.to_dict() for name, rec in proc_records.items()}
        run_record["timing_observations"] = dict(timing_holder)
        run_record["windows"] = list(windows)
        run_record["enforcement_evidence"] = enforcement_evidence

        # Ensure receiver error events are captured even on early failure paths
        if not run_record.get("receiver_error_events"):
            try:
                _, rec_err_evs = extract_receiver_events(run_dir)
                if monitor is not None and getattr(monitor, "receiver_error_events", None):
                    for ev in monitor.receiver_error_events:
                        if ev not in rec_err_evs:
                            rec_err_evs.append(ev)
                run_record["receiver_error_events"] = rec_err_evs
            except Exception:
                pass

        # Save run_summary.json immediately for this run
        (run_dir / "run_summary.json").write_text(json.dumps(run_record, indent=2) + "\n")

    return run_record


def run_single_iteration_mock(
    run_info: Dict[str, Any],
    out_dir: Path,
    services: Dict[str, Any],
    mock_defect: Optional[str] = None,
) -> Dict[str, Any]:
    """Executes a single synthetic mock iteration with support for failure injection and edge cases."""
    scen = run_info["scenario"]
    run_id = run_info["run_id"]
    run_dir = out_dir / f"run_{run_id:03d}_{scen}"
    run_dir.mkdir(parents=True, exist_ok=True)

    time.sleep(0.01)

    # 1. Simulate generic execution failure defect
    if mock_defect == "execution_failure":
        run_record = {
            "run_id": run_id,
            "scenario": scen,
            "repeat_index": run_info["repeat_index"],
            "permutation_block_index": run_info["permutation_block_index"],
            "position_in_permutation": run_info["position_in_permutation"],
            "architecture_type": "direct_ovs_policy_comparison",
            "is_synthetic": True,
            "execution_status": "failed",
            "execution_error": "Simulated Mininet connection timeout",
            "measurement_status": "execution_failed",
            "measurement_invalidation_reason": None,
            "timing_observations": {
                "load_started_mono": None, "load_started_unix": None,
                "sensor_launch_mono": None, "sensor_launch_unix": None,
            },
            "process_observations": {
                "sensor_client": {"command": ["iperf3", "-c", "10.0.0.2"], "pid": 1001, "returncode": None, "process_lifetime_seconds": None, "cleanup_signals": []},
            },
            "actual_sender_rates": {"sensor_sent_kbps": None, "load_sent_kbps": None},
            "receiver_error_events": [],
            "windows": [],
            "final_observation_window": None,
            "whole_run": {"sensor_kbps": None, "sensor_loss_pct": None, "icmp_reply_rtt_avg_ms": None, "qos_passed": None},
            "qos_passed": None,
            "ping_collection": {},
            "enforcement_evidence": {},
            "cleanup_outcome": {"all_clean": True, "mock": True},
        }
        (run_dir / "run_summary.json").write_text(json.dumps(run_record, indent=2) + "\n")
        return run_record

    # 2. Simulate observed live failure defect:
    # Baseline receiver produced 6 QoS windows, then emitted:
    # "error - unable to receive results: Bad file descriptor".
    # Sensor stderr reported "warning: Failed to read JSON data size".
    # Sensor client exited 1 with end={} and an error field.
    if mock_defect == "live_iperf_failure":
        (run_dir / "sensor_client_stderr.txt").write_text("warning: Failed to read JSON data size\n")
        (run_dir / "sensor_client.json").write_text(json.dumps({
            "end": {},
            "error": "error - unable to receive results: Bad file descriptor",
        }, indent=2))
        (run_dir / "receiver.jsonl").write_text(
            json.dumps({"event": "start"}) + "\n" +
            json.dumps({"event": "error", "data": "error - unable to receive results: Bad file descriptor"}) + "\n"
        )
        (run_dir / "receiver_stderr.txt").write_text("")
        (run_dir / "load_client.json").write_text(json.dumps({"end": {"sum_sent": {"bits_per_second": 5000000.0}}}))
        (run_dir / "load_client_stderr.txt").write_text("")

        run_record = {
            "run_id": run_id,
            "scenario": scen,
            "repeat_index": run_info["repeat_index"],
            "permutation_block_index": run_info["permutation_block_index"],
            "position_in_permutation": run_info["position_in_permutation"],
            "architecture_type": "direct_ovs_policy_comparison",
            "is_synthetic": True,
            "execution_status": "failed",
            "execution_error": "Sensor client failed (code 1, error: error - unable to receive results: Bad file descriptor): warning: Failed to read JSON data size",
            "measurement_status": "execution_failed",
            "measurement_invalidation_reason": None,
            "timing_observations": {
                "load_started_mono": 1002.0, "load_started_unix": 1700000002.0,
                "load_ended_mono": 1072.0, "load_ended_unix": 1700000072.0,
                "measured_load_duration_seconds": 70.0,
                "sensor_launch_mono": 1000.0, "sensor_launch_unix": 1700000000.0,
                "sensor_ended_mono": 1060.0, "sensor_ended_unix": 1700000060.0,
                "measured_sensor_duration_seconds": 60.0,
            },
            "process_observations": {
                "sensor_server": {"name": "sensor_server", "host": "h2", "command": ["iperf3", "-s", "-p", "5202"], "pid": 1101, "returncode": 0, "process_lifetime_seconds": 65.0, "cleanup_signals": ["SIGTERM"]},
                "load_server": {"name": "load_server", "host": "h2", "command": ["iperf3", "-s", "-p", "5201"], "pid": 1102, "returncode": 0, "process_lifetime_seconds": 75.0, "cleanup_signals": ["SIGTERM"]},
                "sensor_client": {"name": "sensor_client", "host": "h1", "command": ["iperf3", "-c", "10.0.0.2", "-p", "5202"], "pid": 1103, "returncode": 1, "process_lifetime_seconds": 60.2, "configured_duration_seconds": 60.0, "cleanup_signals": []},
                "load_client": {"name": "load_client", "host": "h3", "command": ["iperf3", "-c", "10.0.0.2", "-p", "5201"], "pid": 1104, "returncode": 0, "process_lifetime_seconds": 70.1, "configured_duration_seconds": 70.0, "cleanup_signals": []},
                "ping_proc": {"name": "ping_proc", "host": "h1", "command": ["ping", "-i", "1", "10.0.0.2"], "pid": 1105, "returncode": 0, "process_lifetime_seconds": 61.0, "cleanup_signals": ["SIGTERM"]},
            },
            "actual_sender_rates": {"sensor_sent_kbps": None, "load_sent_kbps": 5000.0},
            "receiver_error_events": [{"event": "error", "data": "error - unable to receive results: Bad file descriptor"}],
            "windows": [],
            "final_observation_window": None,
            "whole_run": {"sensor_kbps": None, "sensor_loss_pct": None, "icmp_reply_rtt_avg_ms": 71.7, "qos_passed": None},
            "qos_passed": None,
            "ping_collection": {
                "collection_status": "completed",
                "exit_code": 0,
                "reader_errors": [],
                "stderr": None,
                "rtt_accounting_model": "reply_arrival_half_open",
                "window_alignment_limitation": "launch_time_estimated_half_open_windows",
                "send_accounting": "unverified (icmp_sent_packets and icmp_packet_loss_percent null)",
            },
            "enforcement_evidence": {},
            "cleanup_outcome": {
                "all_clean": True,
                "process_reap_errors": [],
                "thread_join_errors": [],
                "file_close_errors": [],
                "cleanup_signals_issued": {"sensor_server": ["SIGTERM"], "load_server": ["SIGTERM"], "ping_proc": ["SIGTERM"]},
            },
        }
        (run_dir / "run_summary.json").write_text(json.dumps(run_record, indent=2) + "\n")
        return run_record

    # 6 mock windows per scenario
    if scen == "baseline":
        mock_windows = [
            {"idx": 1, "kbps": 22.5, "loss": 77.5, "rtt": 71.0, "is_trans": False, "trans_type": None, "fresh": True},
            {"idx": 2, "kbps": 23.0, "loss": 77.0, "rtt": 72.0, "is_trans": False, "trans_type": None, "fresh": True},
            {"idx": 3, "kbps": 21.8, "loss": 78.2, "rtt": 70.5, "is_trans": False, "trans_type": None, "fresh": True},
            {"idx": 4, "kbps": 22.0, "loss": 78.0, "rtt": 73.0, "is_trans": False, "trans_type": None, "fresh": True},
            {"idx": 5, "kbps": 23.5, "loss": 76.5, "rtt": 71.5, "is_trans": False, "trans_type": None, "fresh": True},
            {"idx": 6, "kbps": 22.8, "loss": 77.2, "rtt": 72.2, "is_trans": False, "trans_type": None, "fresh": True},
        ]
        whole_tp, whole_loss, whole_rtt = 22.6, 77.4, 71.7
        evidence = {}

    elif scen == "static_block":
        mock_windows = [
            {"idx": 1, "kbps": 22.0, "loss": 78.0, "rtt": 72.0, "is_trans": False, "trans_type": None, "fresh": True},
            {"idx": 2, "kbps": 85.0, "loss": 15.0, "rtt": 12.0, "is_trans": True, "trans_type": "initial_enforcement_transition", "fresh": True},
            {"idx": 3, "kbps": 100.0, "loss": 0.0, "rtt": 2.2, "is_trans": False, "trans_type": None, "fresh": True},
            {"idx": 4, "kbps": 100.1, "loss": 0.0, "rtt": 2.1, "is_trans": False, "trans_type": None, "fresh": True},
            {"idx": 5, "kbps": 99.8, "loss": 0.0, "rtt": 2.3, "is_trans": False, "trans_type": None, "fresh": True},
            {"idx": 6, "kbps": 100.0, "loss": 0.0, "rtt": 2.2, "is_trans": False, "trans_type": None, "fresh": True},
        ]
        whole_tp, whole_loss, whole_rtt = 92.5, 7.5, 15.5
        evidence = {
            "static_block": {
                "latency_ms": 0.05,
                "cookie": "0x5354415449430001",
                "flow_dump": "cookie=0x5354415449430001, table=0, priority=110, ip,nw_src=10.0.0.3,nw_dst=10.0.0.2,tp_dst=5201 actions=drop",
            }
        }

    else:  # adaptive
        stale_flag = (mock_defect == "stale_qos")
        qos_passed_flag = (mock_defect == "adaptive_qos_passed")
        w3_invalid_timing_flag = (mock_defect == "w3_invalid_timing")
        w3_loss = 0.5 if qos_passed_flag else 8.0
        w4_trans = not qos_passed_flag and not stale_flag and not w3_invalid_timing_flag
        mock_windows = [
            {"idx": 1, "kbps": 22.0, "loss": 78.0, "rtt": 72.0, "is_trans": False, "trans_type": None, "fresh": True},
            {"idx": 2, "kbps": 75.0, "loss": 25.0, "rtt": 25.0, "is_trans": True, "trans_type": "initial_enforcement_transition", "fresh": True},
            {"idx": 3, "kbps": 99.0 if qos_passed_flag else 92.0, "loss": w3_loss, "rtt": 8.5, "is_trans": False, "trans_type": None, "fresh": not stale_flag},
            {"idx": 4, "kbps": 95.0, "loss": 5.0, "rtt": 5.0, "is_trans": w4_trans, "trans_type": "rate_adjustment_transition" if w4_trans else None, "fresh": True},
            {"idx": 5, "kbps": 99.5, "loss": 0.5, "rtt": 2.5, "is_trans": False, "trans_type": None, "fresh": True},
            {"idx": 6, "kbps": 100.0, "loss": 0.0, "rtt": 2.4, "is_trans": False, "trans_type": None, "fresh": True},
        ]
        whole_tp, whole_loss, whole_rtt = 88.0, 12.0, 19.2
        evidence = {
            "initial_meter": {"latency_ms": 0.08, "rate_limit_kbps": 1000, "cookie": "0x4144505400000001", "meter_id": 1001},
        }
        if not stale_flag and not qos_passed_flag and not w3_invalid_timing_flag:
            evidence["adjusted_meter"] = {"latency_ms": 0.06, "rate_limit_kbps": 500, "cookie": "0x4144505400000001", "meter_id": 1001}

    if mock_defect == "missing_window_6":
        mock_windows = mock_windows[:5]

    formatted_windows = []
    for mw in mock_windows:
        w_satisfied = (mw["kbps"] >= 90.0 and mw["loss"] <= 1.0)
        is_conf = (mock_defect == "confounded_final_window" and mw["idx"] == 6)

        int_cnt = 5
        if mock_defect == "missing_interval_count" and mw["idx"] == 6:
            int_cnt = None

        fresh_val = mw["fresh"]
        if mock_defect == "missing_published_fresh" and mw["idx"] == 6:
            fresh_val = None

        tp_val = mw["kbps"]
        if mock_defect == "non_finite_metric" and mw["idx"] == 6:
            tp_val = float("nan")

        w_start = (mw["idx"] - 1) * 10.0
        w_end = mw["idx"] * 10.0
        if mock_defect == "w3_invalid_timing" and mw["idx"] == 3:
            w_start = 35.0  # Timing out of boundary tolerance
            w_end = 45.0

        # Build contiguous intervals evidence
        intervals_evidence = []
        for iv_idx in range(5):
            iv_s = w_start + iv_idx * 2.0
            iv_e = iv_s + 2.0
            pkts = 25
            lost_pkts = int(round(pkts * (mw["loss"] / 100.0)))
            intervals_evidence.append({
                "sender": False,
                "omitted": False,
                "start": iv_s,
                "end": iv_e,
                "seconds": 2.0,
                "bytes": int(round((mw["kbps"] * 1000 / 8) * 2.0)),
                "bits_per_second": mw["kbps"] * 1000.0,
                "packets": pkts,
                "lost_packets": lost_pkts,
                "lost_percent": mw["loss"],
            })

        formatted_windows.append({
            "window_index": mw["idx"],
            "window_start_seconds": w_start,
            "window_end_seconds": w_end,
            "window_duration_seconds": 10.0,
            "interval_count": int_cnt,
            "intervals": intervals_evidence if int_cnt == 5 else None,
            "receiver_kbps": tp_val,
            "packet_loss_percent": mw["loss"],
            "icmp_reply_rtt_avg_ms": mw["rtt"],
            "icmp_reply_rtt_min_ms": round(mw["rtt"] * 0.9, 1),
            "icmp_reply_rtt_max_ms": round(mw["rtt"] * 1.1, 1),
            "icmp_reply_rtt_status": "reply_received",
            "icmp_reply_rtt_reason": "valid",
            "icmp_reply_count": 10,
            "icmp_sent_packets": None,
            "icmp_packet_loss_percent": None,
            "qos_satisfied": w_satisfied,
            "published_fresh": fresh_val,
            "load_active": not is_conf,
            "is_confounded": is_conf,
            "confounding_reason": "window_overlaps_load_cessation" if is_conf else None,
            "is_transition_window": mw["is_trans"],
            "transition_type": mw["trans_type"],
            "eligible_for_evaluation": (not is_conf) and (not mw["is_trans"]) and (fresh_val is True),
        })

    with (run_dir / "windows.jsonl").open("w", encoding="utf-8") as f_win:
        for mw in formatted_windows:
            f_win.write(json.dumps(mw) + "\n")
            w_num = mw.get("window_index", 1)
            emit_live_stream_event(
                run_id, scen, mw, live=False,
                stage="post_adjustment_stable" if w_num >= 5 else ("initial_monitoring" if w_num == 1 else "rate_limiting"),
                action="rate_limit" if scen == "adaptive" else ("block" if scen == "static_block" else "none"),
                rate_limit=500 if (scen == "adaptive" and w_num >= 4) else (1000 if scen == "adaptive" else None),
            )

    # Validate final window strictly using production validation function
    valid_w6, invalid_reason = validate_final_window(formatted_windows)

    if mock_defect == "missing_loss":
        whole_loss_entry = None
    else:
        whole_loss_entry = whole_loss

    # Write mock files
    sum_recv_dict = {"bits_per_second": whole_tp * 1000}
    if whole_loss_entry is not None:
        sum_recv_dict["lost_percent"] = whole_loss_entry

    (run_dir / "sensor_client.json").write_text(json.dumps({
        "end": {"sum_sent": {"bits_per_second": 100000.0}, "sum_received": sum_recv_dict},
    }, indent=2))
    (run_dir / "sensor_client_stderr.txt").write_text("")
    (run_dir / "load_client.json").write_text(json.dumps({
        "end": {"sum_sent": {"bits_per_second": 5000000.0}},
    }, indent=2))
    (run_dir / "load_client_stderr.txt").write_text("")
    (run_dir / "receiver.jsonl").write_text(json.dumps({"event": "start"}) + "\n")
    (run_dir / "receiver_stderr.txt").write_text("")
    (run_dir / "load_server_stdout.txt").write_text("")
    (run_dir / "load_server_stderr.txt").write_text("")
    (run_dir / "raw_ping.txt").write_text(f"[{time.time():.3f}] 64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time={whole_rtt} ms\n")

    if mock_defect == "missing_loss":
        meas_status = "measurement_invalid_or_incomplete"
        inv_reason = "sensor_output_missing_lost_percent"
        final_qos = None
    elif valid_w6 is not None:
        meas_status = "completed_valid"
        inv_reason = None
        final_qos = valid_w6["qos_satisfied"]
    else:
        meas_status = "measurement_invalid_or_incomplete"
        inv_reason = invalid_reason
        final_qos = None

    # Evaluate adaptive reassessment with shared strict measurement validator
    reassessment_meta = None
    if scen == "adaptive":
        w3_candidate = next((w for w in formatted_windows if w["window_index"] == 3), None)
        valid_w3, inv_w3 = validate_window_measurement(w3_candidate, expected_window_index=3)

        if valid_w3 is None:
            reassessment_meta = {
                "evaluated_at_window": 3,
                "outcome": "not_evaluated",
                "reason": inv_w3,
                "adjusted": False,
            }
        elif mock_defect == "adaptive_qos_passed":
            reassessment_meta = {
                "evaluated_at_window": 3,
                "outcome": "not_exercised_measured_qos_passed",
                "reason": "qos_passed",
                "adjusted": False,
            }
        else:
            reassessment_meta = {
                "evaluated_at_window": 3,
                "outcome": "adjusted_to_500kbps",
                "reason": "qos_degraded",
                "adjusted": True,
            }

    ping_coll_status = "reader_error" if mock_defect == "ping_reader_error" else "completed"
    ping_reader_errs = ["simulated_ping_pipe_broken"] if mock_defect == "ping_reader_error" else []

    run_record = {
        "run_id": run_id,
        "scenario": scen,
        "repeat_index": run_info["repeat_index"],
        "permutation_block_index": run_info["permutation_block_index"],
        "position_in_permutation": run_info["position_in_permutation"],
        "architecture_type": "direct_ovs_policy_comparison",
        "is_synthetic": True,
        "data_source": "synthetic_offline_mock",
        "research_evidence_warning": "MOCK SYNTHETIC DATA - NOT RESEARCH EVIDENCE",
        "execution_status": "completed",
        "execution_error": None,
        "measurement_status": meas_status,
        "measurement_invalidation_reason": inv_reason,
        "timing_observations": {
            "load_started_mono": 1002.0, "load_started_unix": 1700000002.0,
            "load_ended_mono": 1072.0, "load_ended_unix": 1700000072.0,
            "measured_load_duration_seconds": 70.0,
            "sensor_launch_mono": 1000.0, "sensor_launch_unix": 1700000000.0,
            "sensor_ended_mono": 1060.0, "sensor_ended_unix": 1700000060.0,
            "measured_sensor_duration_seconds": 60.0,
        },
        "process_observations": {
            "sensor_server": {"name": "sensor_server", "host": "h2", "command": ["iperf3", "-s", "-p", "5202"], "pid": 2001, "returncode": 0, "process_lifetime_seconds": 65.0, "cleanup_signals": ["SIGTERM"]},
            "load_server": {"name": "load_server", "host": "h2", "command": ["iperf3", "-s", "-p", "5201"], "pid": 2002, "returncode": 0, "process_lifetime_seconds": 75.0, "cleanup_signals": ["SIGTERM"]},
            "sensor_client": {"name": "sensor_client", "host": "h1", "command": ["iperf3", "-c", "10.0.0.2", "-p", "5202"], "pid": 2003, "returncode": 0, "process_lifetime_seconds": 60.1, "configured_duration_seconds": 60.0, "cleanup_signals": []},
            "load_client": {"name": "load_client", "host": "h3", "command": ["iperf3", "-c", "10.0.0.2", "-p", "5201"], "pid": 2004, "returncode": 0, "process_lifetime_seconds": 70.1, "configured_duration_seconds": 70.0, "cleanup_signals": []},
            "ping_proc": {"name": "ping_proc", "host": "h1", "command": ["ping", "-i", "1", "10.0.0.2"], "pid": 2005, "returncode": 0, "process_lifetime_seconds": 60.5, "cleanup_signals": ["SIGTERM"]},
        },
        "actual_sender_rates": {"sensor_sent_kbps": 100.0, "load_sent_kbps": 5000.0},
        "receiver_error_events": [],
        "windows": formatted_windows,
        "final_observation_window": valid_w6,
        "whole_run": {
            "sensor_kbps": whole_tp,
            "sensor_loss_pct": whole_loss_entry,
            "icmp_reply_rtt_avg_ms": whole_rtt,
            "qos_passed": (whole_tp >= 90.0 and whole_loss_entry is not None and whole_loss_entry <= 1.0),
        },
        "qos_passed": final_qos,
        "enforcement_evidence": evidence,
        "ping_collection": {
            "collection_status": ping_coll_status,
            "exit_code": 0,
            "reader_errors": ping_reader_errs,
            "stderr": None,
            "rtt_accounting_model": "reply_arrival_half_open",
            "window_alignment_limitation": "launch_time_estimated_half_open_windows",
            "send_accounting": "unverified (icmp_sent_packets and icmp_packet_loss_percent null)",
        },
        "adaptive_reassessment": reassessment_meta,
        "cleanup_outcome": {
            "all_clean": (mock_defect not in ("cleanup_failure", "cleanup_thread_failure")),
            "mock": True,
            "unresolved_processes": ["simulated_leaked_process"] if mock_defect == "cleanup_failure" else [],
            "unresolved_threads": ["receiver_monitor_thread"] if mock_defect == "cleanup_thread_failure" else [],
            "thread_join_errors": ["receiver_monitor_thread still alive after bounded join"] if mock_defect == "cleanup_thread_failure" else [],
            "error": "Simulated uncleaned process or thread" if mock_defect in ("cleanup_failure", "cleanup_thread_failure") else None,
        },
    }

    (run_dir / "run_summary.json").write_text(json.dumps(run_record, indent=2) + "\n")
    return run_record


def run_comparison(
    repeats: int = 10,
    live: bool = False,
    mock: bool = False,
    seed: int = 42,
    mock_defect: Optional[str] = None,
    scenario: str = "all",
) -> Dict[str, Any]:
    if not live and not mock:
        raise ValueError("Must specify either --live or --mock explicitly")
    if live and mock:
        raise ValueError("Cannot specify both --live and --mock")
    if repeats < 1:
        raise ValueError("Repeats per scenario must be an integer >= 1")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    out_dir = RESULTS_DIR / f"matched_comparison_{timestamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    mode_label = "live_mininet_ovs" if live else "mock_synthetic"
    print("=== Three-Host Matched Comparison Evaluation Runner ===")
    print(f"Mode:             {mode_label}")
    print(f"Architecture:     direct_ovs_policy_comparison")
    print(f"Repeats/Scenario: {repeats}")
    print(f"Scenario Filter:  {scenario}")
    print(f"Random Seed:      {seed}")
    print(f"Output Directory: {out_dir}")

    # 1. Build and save planned schedule
    if scenario != "all" and scenario in SCENARIOS:
        schedule = [
            {
                "run_id": i + 1,
                "permutation_block_index": 1,
                "position_in_permutation": 1,
                "scenario": scenario,
                "repeat_index": i + 1,
            }
            for i in range(repeats)
        ]
        sched_meta = {
            "seed": seed,
            "repeats_per_scenario": repeats,
            "total_planned_runs": len(schedule),
            "total_permutations_used": 1,
            "single_scenario_filter": scenario,
            "is_perfectly_balanced": True,
            "position_counts": {s: {1: repeats if s == scenario else 0, 2: 0, 3: 0} for s in SCENARIOS},
            "precedence_counts": {s1: {s2: 0 for s2 in SCENARIOS if s2 != s1} for s1 in SCENARIOS},
            "residual_imbalance": {},
        }
    else:
        schedule, sched_meta = build_permutation_schedule(repeats, seed=seed)

    (out_dir / "planned_schedule.json").write_text(json.dumps({
        "schedule_metadata": sched_meta,
        "planned_runs": schedule,
    }, indent=2) + "\n")
    print(f"Planned schedule saved: {len(schedule)} runs total across {sched_meta['total_permutations_used']} permutation blocks.")

    # 2. Context store & services
    services = json.loads((BASE / "configs/services_v2.json").read_text())
    store = ContextStore(clock=time.monotonic if live else (lambda: 10000.0))

    # 3. Prepare CSV and Manifest outputs
    csv_path = out_dir / "comparison_raw.csv"
    manifest_path = out_dir / "runs_manifest.jsonl"

    csv_fieldnames = [
        "run_id", "scenario", "repeat_index", "permutation_block", "position",
        "execution_status", "measurement_status", "invalidation_reason", "is_synthetic",
        "final_sensor_kbps", "final_loss_pct", "final_rtt_ms", "final_qos_passed",
        "whole_sensor_kbps", "whole_loss_pct", "whole_rtt_ms", "whole_qos_passed",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as f_csv:
        writer = csv.DictWriter(f_csv, fieldnames=csv_fieldnames)
        writer.writeheader()

    # 4. Execute schedule
    records: List[Dict[str, Any]] = []
    cleanup_failed_stop = False

    print("\nExecuting counterbalanced runs...")
    for idx, run_info in enumerate(schedule):
        scen = run_info["scenario"]
        rep_idx = run_info["repeat_index"]
        print(f"  [{idx+1}/{len(schedule)}] Running {scen.upper()} (repeat {rep_idx}/{repeats}, block {run_info['permutation_block_index']})...", end="", flush=True)

        if live:
            rec = run_single_iteration_live(run_info, out_dir, services, store)
        else:
            rec = run_single_iteration_mock(run_info, out_dir, services, mock_defect=mock_defect)

        records.append(rec)

        with manifest_path.open("a", encoding="utf-8") as f_man:
            f_man.write(json.dumps(rec) + "\n")

        fw = rec.get("final_observation_window") or {}
        wr = rec.get("whole_run") or {}
        csv_row = {
            "run_id": rec["run_id"],
            "scenario": rec["scenario"],
            "repeat_index": rec["repeat_index"],
            "permutation_block": rec["permutation_block_index"],
            "position": rec["position_in_permutation"],
            "execution_status": rec["execution_status"],
            "measurement_status": rec["measurement_status"],
            "invalidation_reason": rec.get("measurement_invalidation_reason"),
            "is_synthetic": rec["is_synthetic"],
            "final_sensor_kbps": fw.get("receiver_kbps"),
            "final_loss_pct": fw.get("packet_loss_percent"),
            "final_rtt_ms": fw.get("icmp_reply_rtt_avg_ms"),
            "final_qos_passed": rec.get("qos_passed"),
            "whole_sensor_kbps": wr.get("sensor_kbps"),
            "whole_loss_pct": wr.get("sensor_loss_pct"),
            "whole_rtt_ms": wr.get("icmp_reply_rtt_avg_ms"),
            "whole_qos_passed": wr.get("qos_passed"),
        }
        with csv_path.open("a", newline="", encoding="utf-8") as f_csv:
            writer = csv.DictWriter(f_csv, fieldnames=csv_fieldnames)
            writer.writerow(csv_row)

        if rec["execution_status"] != "completed":
            print(f" EXECUTION FAILED: {rec['execution_error']}")
        elif rec["measurement_status"] != "completed_valid":
            print(f" MEASUREMENT INVALID: {rec['measurement_invalidation_reason']} (QoS: NULL)")
        else:
            print(f" VALID. Window 6: {fw.get('receiver_kbps')} kbps, Loss: {fw.get('packet_loss_percent')}%, QoS: {'PASS' if rec['qos_passed'] else 'FAIL'}")

        # Check cleanup outcome: STOP further runs if cleanup failed
        cleanup = rec.get("cleanup_outcome", {})
        if not cleanup.get("all_clean", True):
            print(f"\n[CRITICAL SAFETY STOP] Cleanup failure in run {rec['run_id']}! Halting further runs to protect testbed.")
            cleanup_failed_stop = True
            break

    # 5. Aggregate Statistical Summary
    stats_summary: Dict[str, Any] = {}
    total_valid = 0
    total_exec_failed = 0
    total_meas_invalid = 0

    for scen in SCENARIOS:
        scen_records = [r for r in records if r["scenario"] == scen]
        exec_failed = [r for r in scen_records if r["execution_status"] != "completed"]
        meas_invalid = [r for r in scen_records if r["execution_status"] == "completed" and r["measurement_status"] != "completed_valid"]
        valid_records = [r for r in scen_records if r["measurement_status"] == "completed_valid"]

        total_valid += len(valid_records)
        total_exec_failed += len(exec_failed)
        total_meas_invalid += len(meas_invalid)

        # Metrics strictly over valid_records
        final_throughputs = [r["final_observation_window"]["receiver_kbps"] for r in valid_records]
        final_losses = [r["final_observation_window"]["packet_loss_percent"] for r in valid_records]

        # Separate RTT validity from UDP QoS: exclude runs where ping collection failed
        final_rtts = [
            r["final_observation_window"]["icmp_reply_rtt_avg_ms"]
            for r in valid_records
            if r["final_observation_window"].get("icmp_reply_rtt_avg_ms") is not None
            and r.get("ping_collection", {}).get("collection_status") == "completed"
        ]
        final_passes = sum(1 for r in valid_records if r.get("qos_passed") is True)
        final_fails = sum(1 for r in valid_records if r.get("qos_passed") is False)

        whole_throughputs = [r["whole_run"]["sensor_kbps"] for r in valid_records if r.get("whole_run") and r["whole_run"].get("sensor_kbps") is not None]
        whole_losses = [r["whole_run"]["sensor_loss_pct"] for r in valid_records if r.get("whole_run") and r["whole_run"].get("sensor_loss_pct") is not None]
        whole_rtts = [
            r["whole_run"]["icmp_reply_rtt_avg_ms"]
            for r in valid_records
            if r.get("whole_run")
            and r["whole_run"].get("icmp_reply_rtt_avg_ms") is not None
            and r.get("ping_collection", {}).get("collection_status") == "completed"
        ]
        whole_passes = sum(1 for r in valid_records if r.get("whole_run") and r["whole_run"].get("qos_passed") is True)

        stats_summary[scen] = {
            "total_scheduled_runs": len(scen_records),
            "completed_valid_runs": len(valid_records),
            "execution_failure_count": len(exec_failed),
            "measurement_invalid_count": len(meas_invalid),
            "final_window_metrics": {
                "window_description": "Predefined final observation window (Window 6: 50-60s) evaluated identically for all scenarios",
                "qos_pass_count": final_passes,
                "qos_fail_count": final_fails,
                "qos_pass_rate_pct": round(100.0 * final_passes / len(valid_records), 1) if valid_records else None,
                "throughput_kbps": compute_statistics_series(final_throughputs),
                "packet_loss_percent": compute_statistics_series(final_losses),
                "icmp_reply_rtt_ms": compute_statistics_series(final_rtts),
            },
            "whole_run_metrics": {
                "window_description": "Full 60-second end-of-stream iperf and overall ICMP summary",
                "qos_pass_count": whole_passes,
                "qos_pass_rate_pct": round(100.0 * whole_passes / len(valid_records), 1) if valid_records else None,
                "throughput_kbps": compute_statistics_series(whole_throughputs),
                "packet_loss_percent": compute_statistics_series(whole_losses),
                "icmp_reply_rtt_ms": compute_statistics_series(whole_rtts),
            },
        }

    if live:
        if total_valid == len(schedule):
            derived_status = "COMPLETED_ALL_VALID"
        elif total_valid > 0:
            derived_status = "PARTIALLY_COMPLETED_WITH_FAILURES"
        else:
            derived_status = "FAILED_LIVE_EXECUTION"
    else:
        derived_status = "PENDING_LIVE_VM_EXECUTION"

    comparison_summary = {
        "timestamp": timestamp,
        "mode": mode_label,
        "is_synthetic": (not live),
        "data_source": "mininet_live_testbed" if live else "synthetic_offline_mock",
        "scope_and_boundary_limitations": {
            "architecture_type": "direct_ovs_policy_comparison",
            "pilot_scope": "Three-host pilot evaluation (h1, h2, h3, s1) on Mininet.",
            "alert_api_integration": "bypassed_in_matched_comparison (direct OpenFlow/meter enforcement used for deterministic timing; not an alert API evaluation)",
            "detector_integration": "not_evaluated (synthetic trigger after Window 1)",
            "ryu_status": "Ryu integration remains an OPEN proposal requirement (direct OVS/OF1.3 used for pilot).",
            "live_verification_status": derived_status,
        },
        "repeats_per_scenario": repeats,
        "total_scheduled_runs": len(schedule),
        "total_valid_completed_runs": total_valid,
        "total_execution_failures": total_exec_failed,
        "total_measurement_invalid_runs": total_meas_invalid,
        "cleanup_failed_halted": cleanup_failed_stop,
        "schedule_metadata": sched_meta,
        "statistics": stats_summary,
        "preserved_raw_artifacts": {
            "planned_schedule": str(out_dir / "planned_schedule.json"),
            "comparison_raw_csv": str(csv_path),
            "runs_manifest_jsonl": str(manifest_path),
            "runs_directory": str(out_dir),
        },
    }

    summary_json_path = out_dir / "comparison_summary.json"
    summary_json_path.write_text(json.dumps(comparison_summary, indent=2) + "\n")

    print("\n=== Matched Comparison Statistical Summary (Final Window 6) ===")
    for scen, s in stats_summary.items():
        fw = s["final_window_metrics"]
        print(f"\nScenario: {scen.upper()}")
        print(f"  Valid: {s['completed_valid_runs']}/{s['total_scheduled_runs']} | Exec Fails: {s['execution_failure_count']} | Meas Invalid: {s['measurement_invalid_count']}")
        print(f"  QoS Pass Rate:  {fw['qos_pass_rate_pct']}% (Pass: {fw['qos_pass_count']}, Fail: {fw['qos_fail_count']})")
        if fw['throughput_kbps']['mean'] is not None:
            sd_str = f"SD {fw['throughput_kbps']['sample_sd']}" if fw['throughput_kbps']['sample_sd'] is not None else "SD null (n<2)"
            print(f"  Throughput:     Mean {fw['throughput_kbps']['mean']} ({sd_str}, Median {fw['throughput_kbps']['median']}) kbps")
        if fw['packet_loss_percent']['mean'] is not None:
            sd_str = f"SD {fw['packet_loss_percent']['sample_sd']}" if fw['packet_loss_percent']['sample_sd'] is not None else "SD null (n<2)"
            print(f"  Packet Loss:    Mean {fw['packet_loss_percent']['mean']}% ({sd_str}, Median {fw['packet_loss_percent']['median']}%)")
        if fw['icmp_reply_rtt_ms']['mean'] is not None:
            sd_str = f"SD {fw['icmp_reply_rtt_ms']['sample_sd']}" if fw['icmp_reply_rtt_ms']['sample_sd'] is not None else "SD null (n<2)"
            print(f"  ICMP RTT:       Mean {fw['icmp_reply_rtt_ms']['mean']} ({sd_str}, Median {fw['icmp_reply_rtt_ms']['median']}) ms")

    print(f"\nResults saved to:\n  - Summary JSON: {summary_json_path}\n  - Raw CSV:      {csv_path}\n  - Manifest:     {manifest_path}")
    return comparison_summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Three-Host Matched Comparison Evaluation Runner"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--live",
        action="store_true",
        help="Run live Mininet test on Linux VM (requires root privileges)",
    )
    group.add_argument(
        "--mock",
        action="store_true",
        help="Run offline mock test with synthetic outputs (does not require Mininet/root)",
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=10,
        help="Repeats per scenario (positive integer, default 10)",
    )
    parser.add_argument(
        "--scenario",
        type=str,
        default="all",
        choices=["all", "baseline", "static_block", "adaptive"],
        help="Select scenario to run ('all', 'baseline', 'static_block', 'adaptive'). Default: all",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for counterbalanced schedule generation (default 42)",
    )
    args = parser.parse_args()

    if args.repeats < 1:
        sys.exit("Error: --repeats must be an integer >= 1.")

    if args.live:
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        if not is_root:
            sys.exit("Error: --live mode requires root privileges (run with sudo). Never silently falls back to mock.")

    run_comparison(repeats=args.repeats, live=args.live, mock=args.mock, seed=args.seed, scenario=args.scenario)
