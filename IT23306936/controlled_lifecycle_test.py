#!/usr/bin/env python3
"""Controlled Rule Lifecycle Verification Test (FR9 Milestone).

Verifies the 6 key rule-lifecycle requirements on Open vSwitch:
1. Fresh, scope-matched threat-ended evidence is required.
2. Transition, duplicate, and stale windows cannot authorize cleanup.
3. Two distinct stable post-threat windows authorize cleanup.
4. Only owned flows and meters are removed (canary rule/meter preserved).
5. Explicit cleanup is distinguished from hard-timeout expiry:
   Parses actual flow duration and hard_timeout (>=300s) from OVS,
   asserting >240s remaining before explicit deletion.
6. Raw snapshots, pre/post flow dumps, and outcomes saved (even on failure).

Scope and Verification Boundaries:
    This test runs with controlled/synthetic gate inputs to validate:
    - CleanupGate state transition rules.
    - Real OVS resource installation and deletion mechanics.
    - Scope isolation (canary flow/meter preservation).
    - Separation of explicit removal from hard-timeout expiry.
    It does NOT establish measured live QoS telemetry or actual detector
    threat cessation. Full end-to-end telemetry lifecycle validation
    remains a separate test (e.g. rule_lifecycle_demo.py).

Usage:
    Live testbed (Ubuntu VM with root):
        sudo /home/sahan/iomt-research/.venv/bin/python controlled_lifecycle_test.py --live
    Offline mock verification:
        python3 controlled_lifecycle_test.py --mock
"""

import argparse
import json
import math
import os
import re
import secrets
import subprocess
import sys
import time
import traceback
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
RESULTS_DIR = BASE / "results"


class MockOVS:
    """Simulates OVS for offline / mock verification."""
    def __init__(self):
        self.flows = {}
        self.meters = {}

    def run(self, args):
        cmd = args[0]
        if cmd == "dump-flows":
            lines = ["OFPST_FLOW reply (OF1.3) (xid=0x2):"]
            for cookie, flow in self.flows.items():
                dur = flow.get("duration", 12.5)
                ht = flow.get("hard_timeout", 0)
                ht_str = f"hard_timeout={ht}, " if ht > 0 else ""
                lines.append(
                    f" cookie=0x{cookie:x}, duration={dur:.3f}s, table=0, n_packets=0, n_bytes=0, "
                    f"{ht_str}{flow['match']} actions={flow['actions']}"
                )
            lines.append(" cookie=0x0, duration=60.000s, table=0, priority=0 actions=NORMAL")
            return subprocess.CompletedProcess(args, 0, stdout="\n".join(lines) + "\n", stderr="")

        elif cmd == "add-flow":
            match_part = args[2]
            cookie = 0
            if "cookie=0x" in match_part:
                c_str = match_part.split("cookie=0x")[1].split(",")[0]
                cookie = int(c_str, 16)
            ht = 0
            if "hard_timeout=" in match_part:
                ht_str = match_part.split("hard_timeout=")[1].split(",")[0]
                ht = int(ht_str)
            self.flows[cookie] = {
                "match": match_part,
                "actions": "meter" if "actions=meter" in match_part else "drop",
                "duration": 5.25,
                "hard_timeout": ht,
            }
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        elif cmd == "del-flows":
            c_part = [a for a in args if "cookie=0x" in a]
            if c_part:
                c_str = c_part[0].split("cookie=0x")[1].split("/")[0]
                cookie = int(c_str, 16)
                self.flows.pop(cookie, None)
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        elif cmd == "add-meter":
            meter_part = args[2]
            m_id = int(meter_part.split("meter=")[1].split(",")[0])
            self.meters[m_id] = meter_part
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        elif cmd == "del-meters":
            m_part = args[2]
            m_id = int(m_part.split("meter=")[1])
            self.meters.pop(m_id, None)
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        elif cmd == "meter-stats":
            lines = ["OFPST_METER reply (OF1.3) (xid=0x2):"]
            for m_id in self.meters:
                lines.append(f" meter:{m_id} flow_count:1 packet_in_count:0 byte_in_count:0")
            return subprocess.CompletedProcess(args, 0, stdout="\n".join(lines) + "\n", stderr="")

        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")


def parse_flow_timeout_and_duration(dump_text, cookie):
    """Extracts duration, hard_timeout and calculates remaining seconds for a given cookie."""
    cookie_str = f"cookie=0x{cookie:x}"
    for line in dump_text.splitlines():
        if cookie_str in line:
            dur_match = re.search(r"duration=([\d.]+)s?", line)
            ht_match = re.search(r"hard_timeout=(\d+)", line)
            if not dur_match:
                raise ValueError(f"Could not parse 'duration' from flow line: {line.strip()}")
            if not ht_match:
                raise ValueError(f"Could not parse 'hard_timeout' from flow line: {line.strip()}")

            duration_sec = float(dur_match.group(1))
            hard_timeout_sec = int(ht_match.group(1))
            remaining_sec = hard_timeout_sec - duration_sec
            return {
                "flow_line": line.strip(),
                "duration_seconds": duration_sec,
                "hard_timeout_seconds": hard_timeout_sec,
                "remaining_seconds": round(remaining_sec, 3),
            }
    raise ValueError(f"Flow with cookie 0x{cookie:x} not found in flow dump")


def run_controlled_lifecycle(live=False, mock=False):
    if not live and not mock:
        raise ValueError("Must explicitly specify either live=True or mock=True")
    if live and mock:
        raise ValueError("Cannot specify both live=True and mock=True")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = RESULTS_DIR / f"controlled_lifecycle_{timestamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    mode_label = "live_ovs_controlled_inputs" if live else "mock_offline"
    print(f"=== Controlled Lifecycle Verification Test ===")
    print(f"Execution Mode:    {mode_label}")
    print(f"Results Directory: {out_dir}")

    services = json.loads((BASE / "configs/services_v2.json").read_text())
    from ovs_enforcement_v2 import OVSEnforcer
    from rule_lifecycle_v2 import CleanupGate

    lifecycle_scope = {
        "source_ip": "10.0.0.1",
        "target_ip": "10.0.0.2",
        "protocol": "udp",
        "dst_port": 5201,
    }
    gate = CleanupGate(lifecycle_scope, services["ECG_Monitoring"]["qos"], required_windows=2)
    enforcer = OVSEnforcer(services)

    net = None
    mock_ovs = None
    if mock:
        mock_ovs = MockOVS()
        enforcer.run = mock_ovs.run

    test_log = []
    verifications = {}
    failure_info = None
    test_passed = False

    # Unique 64-bit cookie and meter ID for unowned canary resources to avoid collisions
    canary_cookie = secrets.randbits(64)
    while canary_cookie == enforcer.cookie:
        canary_cookie = secrets.randbits(64)

    canary_meter = secrets.randbelow(1000000) + 10000
    while canary_meter == enforcer.meter_id:
        canary_meter = secrets.randbelow(1000000) + 10000

    canary_installed = False
    enforcement_installed = False

    pre_removal_dump = ""
    pre_removal_meters = ""
    post_cleanup_dump = ""
    post_cleanup_meters = ""
    timeout_parsed_info = None

    try:
        if live:
            # Setup isolated Mininet test topology with switch s1
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

            print("Starting isolated Mininet topology (h1, h2, s1)...")
            net = Mininet(controller=None, switch=OVSBridge, link=TCLink)
            h1 = net.addHost("h1", ip="10.0.0.1/8")
            h2 = net.addHost("h2", ip="10.0.0.2/8")
            s1 = net.addSwitch("s1")
            net.addLink(h1, s1)
            net.addLink(h2, s1, bw=2, max_queue_size=20, use_htb=True)
            net.start()
            print("Mininet topology started successfully.")

        # 1. Setup canary (unowned) rule and meter to verify scope isolation
        print(f"Installing canary resources (cookie=0x{canary_cookie:x}, meter={canary_meter})...")
        enforcer.run(["add-meter", "s1", f"meter={canary_meter},kbps,stats,bands=type=drop,rate=5000"])
        enforcer.run([
            "add-flow", "s1",
            f"cookie=0x{canary_cookie:x},priority=50,udp,nw_src=10.0.0.99,nw_dst=10.0.0.2,tp_dst=5201,actions=drop"
        ])
        canary_installed = True
        print("Canary rule and meter installed on s1.")

        # 2. Install mitigation rule with hard_timeout=300
        recommendation = {
            "action": "rate_limit",
            "scope": lifecycle_scope,
            "rate_limit_kbps": 1000,
            "duration_seconds": 300,
        }
        applied = enforcer.apply(recommendation)
        enforcement_installed = True
        owned_cookie = enforcer.cookie
        owned_meter = enforcer.meter_id
        print(f"Mitigation applied: cookie=0x{owned_cookie:x}, meter={owned_meter}, hard_timeout=300s")

        t_base = time.monotonic() if live else 10000.0
        now = t_base + 10.0

        # Requirement 1a: Active threat keeps rule
        w_active = {
            "window_start_seconds": 0.0, "window_end_seconds": 10.0,
            "window_duration_seconds": 10.0, "receiver_kbps": 99.5, "packet_loss_percent": 0.0,
        }
        thr_active = {
            "scope": deepcopy(lifecycle_scope),
            "status": "active",
            "ended_at_monotonic": None,
            "observed_monotonic": now,
        }
        dec_active = gate.observe(w_active, now - 0.5, thr_active, now)
        assert dec_active["action"] == "keep", "Active threat must not authorize cleanup"
        verifications["active_threat_rejected"] = True
        test_log.append({"test": "threat_active", "decision": dec_active})
        print("  [PASS] 1a: Active threat keeps rule.")

        # Requirement 1b: Scope mismatch keeps rule
        thr_mismatch = {
            "scope": {**lifecycle_scope, "dst_port": 9999},
            "status": "ended",
            "ended_at_monotonic": now - 5.0,
            "observed_monotonic": now,
        }
        dec_mismatch = gate.observe(w_active, now - 0.5, thr_mismatch, now)
        assert dec_mismatch["action"] == "keep" and "scope mismatch" in dec_mismatch["reason"].lower()
        verifications["scope_mismatch_rejected"] = True
        test_log.append({"test": "scope_mismatch", "decision": dec_mismatch})
        print("  [PASS] 1b: Scope-mismatched threat evidence rejected.")

        # Requirement 1c & 2a: Stale threat evidence (>10s old) keeps rule
        thr_stale = {
            "scope": deepcopy(lifecycle_scope),
            "status": "ended",
            "ended_at_monotonic": now - 30.0,
            "observed_monotonic": now - 15.0,
        }
        dec_stale = gate.observe(w_active, now - 0.5, thr_stale, now)
        assert dec_stale["action"] == "keep" and "stale" in dec_stale["reason"].lower()
        verifications["stale_threat_rejected"] = True
        test_log.append({"test": "stale_threat", "decision": dec_stale})
        print("  [PASS] 1c: Stale threat evidence rejected.")

        # Requirement 2b: Transition window overlapping threat cessation keeps rule
        t_ended = now - 5.0
        w_trans = {
            "window_start_seconds": 10.0, "window_end_seconds": 20.0,
            "window_duration_seconds": 10.0, "receiver_kbps": 99.8, "packet_loss_percent": 0.0,
        }
        sample_end_trans = now + 2.0
        thr_ended = {
            "scope": deepcopy(lifecycle_scope),
            "status": "ended",
            "ended_at_monotonic": t_ended,
            "observed_monotonic": now + 2.0,
        }
        dec_trans = gate.observe(w_trans, sample_end_trans, thr_ended, now + 2.0)
        assert dec_trans["action"] == "keep" and "transition" in dec_trans["reason"].lower()
        assert dec_trans["stable_windows"] == 0
        verifications["transition_window_rejected"] = True
        test_log.append({"test": "transition_window", "decision": dec_trans})
        print("  [PASS] 2b: Window overlapping threat transition rejected.")

        # Requirement 3a: Post-threat window 1 -> stable_count=1, action=keep
        now_w1 = now + 12.0
        w1 = {
            "window_start_seconds": 20.0, "window_end_seconds": 30.0,
            "window_duration_seconds": 10.0, "receiver_kbps": 100.0, "packet_loss_percent": 0.0,
        }
        thr_w1 = {
            "scope": deepcopy(lifecycle_scope),
            "status": "ended",
            "ended_at_monotonic": t_ended,
            "observed_monotonic": now_w1,
        }
        dec_w1 = gate.observe(w1, now_w1, thr_w1, now_w1)
        assert dec_w1["action"] == "keep" and dec_w1["stable_windows"] == 1
        verifications["post_threat_window_1_recorded"] = True
        test_log.append({"test": "stable_window_1", "decision": dec_w1})
        print("  [PASS] 3a: Post-threat stable window 1 recorded (stable_windows=1).")

        # Requirement 2c: Duplicate window rejected without count reset
        dec_dup = gate.observe(w1, now_w1, thr_w1, now_w1 + 0.1)
        assert dec_dup["action"] == "keep" and dec_dup["stable_windows"] == 1
        assert "duplicate" in dec_dup["reason"].lower() or "older" in dec_dup["reason"].lower()
        verifications["duplicate_window_rejected"] = True
        test_log.append({"test": "duplicate_window", "decision": dec_dup})
        print("  [PASS] 2c: Duplicate window rejected without count increment.")

        # Requirement 3b: Two distinct stable post-threat windows authorize cleanup
        now_w2 = now + 22.0
        w2 = {
            "window_start_seconds": 30.0, "window_end_seconds": 40.0,
            "window_duration_seconds": 10.0, "receiver_kbps": 100.0, "packet_loss_percent": 0.0,
        }
        thr_w2 = {
            "scope": deepcopy(lifecycle_scope),
            "status": "ended",
            "ended_at_monotonic": t_ended,
            "observed_monotonic": now_w2,
        }
        dec_w2 = gate.observe(w2, now_w2, thr_w2, now_w2)
        assert dec_w2["action"] == "remove" and dec_w2["stable_windows"] == 2
        verifications["two_stable_windows_authorize_cleanup"] = True
        test_log.append({"test": "stable_window_2", "decision": dec_w2})
        print("  [PASS] 3b: Two distinct stable windows authorize cleanup (action=remove).")

        # Requirement 5: Verify owned flows/meters exist and parse actual hard_timeout and duration
        pre_removal_dump = enforcer.run(["dump-flows", "s1"]).stdout
        pre_removal_meters = enforcer.run(["meter-stats", "s1"]).stdout

        cookie_str = f"cookie=0x{owned_cookie:x}"
        assert cookie_str in pre_removal_dump, "Owned flow must exist in OVS prior to explicit removal"
        assert f"meter:{owned_meter} " in pre_removal_meters, "Owned meter must exist in OVS prior to explicit removal"

        # Parse flow line duration and hard_timeout
        timeout_parsed_info = parse_flow_timeout_and_duration(pre_removal_dump, owned_cookie)
        assert timeout_parsed_info["hard_timeout_seconds"] >= 300, (
            f"Expected hard_timeout >= 300, got {timeout_parsed_info['hard_timeout_seconds']}"
        )
        assert timeout_parsed_info["remaining_seconds"] > 240.0, (
            f"Expected >240s remaining before explicit cleanup, got {timeout_parsed_info['remaining_seconds']}s"
        )
        verifications["explicit_cleanup_distinguished_from_hard_timeout"] = True
        print(
            f"  [PASS] 5: Hard-timeout distinction verified: duration={timeout_parsed_info['duration_seconds']}s, "
            f"hard_timeout={timeout_parsed_info['hard_timeout_seconds']}s, "
            f"remaining={timeout_parsed_info['remaining_seconds']}s (>240s)."
        )

        # Requirement 4: Perform cleanup and verify ONLY owned flows/meters are removed
        enforcer.cleanup()
        enforcement_installed = False

        post_cleanup_dump = enforcer.run(["dump-flows", "s1"]).stdout
        post_cleanup_meters = enforcer.run(["meter-stats", "s1"]).stdout

        owned_flow_removed = cookie_str not in post_cleanup_dump
        owned_meter_removed = f"meter:{owned_meter} " not in post_cleanup_meters
        canary_flow_preserved = f"cookie=0x{canary_cookie:x}" in post_cleanup_dump
        canary_meter_preserved = f"meter:{canary_meter} " in post_cleanup_meters

        assert owned_flow_removed, "Owned flow must be deleted after cleanup"
        assert owned_meter_removed, "Owned meter must be deleted after cleanup"
        assert canary_flow_preserved, "Canary flow must be preserved after cleanup"
        assert canary_meter_preserved, "Canary meter must be preserved after cleanup"

        verifications["only_owned_flows_and_meters_removed"] = True
        verifications["canary_resources_preserved"] = True
        print("  [PASS] 4: Only owned flow/meter removed; canary flow/meter strictly preserved.")

        test_passed = True

    except Exception as e:
        failure_info = {
            "error_type": type(e).__name__,
            "error_message": str(e),
            "traceback": traceback.format_exc(),
        }
        print(f"\n[FAIL] Test encountered error: {type(e).__name__}: {e}")
        traceback.print_exc()

    finally:
        # Guarantee cleanup of ONLY resources created by this test
        print("Executing guaranteed cleanup of test resources...")
        if enforcement_installed:
            try:
                enforcer.cleanup()
            except Exception as ce:
                print(f"Warning: Enforcer cleanup error: {ce}")

        if canary_installed:
            try:
                enforcer.run(["del-flows", "s1", f"cookie=0x{canary_cookie:x}/-1"])
                enforcer.run(["del-meters", "s1", f"meter={canary_meter}"])
                print("Canary flow and meter successfully deleted.")
            except Exception as ce:
                print(f"Warning: Canary cleanup error: {ce}")

        if net is not None:
            try:
                net.stop()
                print("Mininet topology stopped.")
            except Exception as ce:
                print(f"Warning: Mininet stop error: {ce}")

        # Save complete raw evidence, flow dumps and outcome to summary.json
        summary = {
            "timestamp": timestamp,
            "mode": mode_label,
            "scope_description": (
                "Controlled test validating CleanupGate lifecycle transitions and explicit OVS resource cleanup "
                "(flow/meter parsing, canary isolation, timeout distinction). Does NOT establish measured live "
                "QoS telemetry or actual detector threat cessation. Live end-to-end telemetry lifecycle remains "
                "a separate pending test."
            ),
            "test_succeeded": test_passed,
            "final_status": "ALL_LIFECYCLE_REQUIREMENTS_VERIFIED" if test_passed else "FAILED",
            "telemetry_lifecycle_validation_status": "PENDING_END_TO_END_TEST",
            "owned_cookie": f"0x{enforcer.cookie:x}",
            "owned_meter_id": enforcer.meter_id,
            "canary_cookie": f"0x{canary_cookie:x}",
            "canary_meter_id": canary_meter,
            "timeout_parsing": timeout_parsed_info,
            "verifications": verifications,
            "requirements_verified": {
                "fresh_scope_matched_threat_required": (
                    verifications.get("active_threat_rejected", False)
                    and verifications.get("scope_mismatch_rejected", False)
                    and verifications.get("stale_threat_rejected", False)
                ),
                "transition_duplicate_stale_rejected": (
                    verifications.get("transition_window_rejected", False)
                    and verifications.get("duplicate_window_rejected", False)
                ),
                "two_distinct_stable_windows_authorize_cleanup": verifications.get(
                    "two_stable_windows_authorize_cleanup", False
                ),
                "only_owned_flows_and_meters_removed": verifications.get(
                    "only_owned_flows_and_meters_removed", False
                ),
                "explicit_cleanup_distinguished_from_hard_timeout": verifications.get(
                    "explicit_cleanup_distinguished_from_hard_timeout", False
                ),
                "raw_evidence_saved": True,
            },
            "pre_removal_dump_flows": pre_removal_dump,
            "pre_removal_meter_stats": pre_removal_meters,
            "post_cleanup_dump_flows": post_cleanup_dump,
            "post_cleanup_meter_stats": post_cleanup_meters,
            "test_decisions": test_log,
            "failure_info": failure_info,
        }

        summary_file = out_dir / "summary.json"
        summary_file.write_text(json.dumps(summary, indent=2) + "\n")
        print(f"Outcome and evidence written to: {summary_file}")

    if not test_passed:
        raise RuntimeError(f"Controlled lifecycle verification failed: {failure_info['error_message']}")

    print("\n[SUCCESS] Controlled lifecycle verification completed successfully.")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Controlled Rule Lifecycle Verification Test")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--live", action="store_true", help="Run live OVS test with Mininet (requires root)")
    group.add_argument("--mock", action="store_true", help="Run offline mock test without Mininet/OVS")
    args = parser.parse_args()

    if args.live:
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        if not is_root:
            sys.exit("Error: --live mode requires root privileges (run with sudo).")

    run_controlled_lifecycle(live=args.live, mock=args.mock)
