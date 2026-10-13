import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.append("/usr/lib/python3/dist-packages")
from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.link import TCLink

from alert_api_v2 import create_app
from context_store_v2 import ContextStore
from live_qos_bridge_v2 import LiveQoSBridge
from receiver_callback_monitor import ReceiverStreamMonitor
from ovs_enforcement_v2 import OVSEnforcer
from rule_lifecycle_v2 import CleanupGate
from threading import Thread, Lock


def main():
    folder = Path(__file__).resolve().parent / "results" / (
        "lifecycle_demo_" + datetime.now().strftime("%Y%m%d_%H%M%S")
    )
    folder.mkdir(parents=True)
    store = ContextStore()
    client = create_app(folder / "api_events.jsonl", store.provide).test_client()
    net = Mininet(controller=None, switch=OVSBridge, link=TCLink)
    processes = []
    results = []
    bridge_holder = {}
    services = json.loads(
        (Path(__file__).resolve().parent / "configs/services_v2.json").read_text()
    )
    enforcer = OVSEnforcer(services)
    action_state = {"stage": "pending"}
    threat_lock = Lock()
    threat_state = {"status": "active", "ended_at": None}
    lifecycle_scope = {
        "source_ip": "10.0.0.1", "target_ip": "10.0.0.2",
        "protocol": "udp", "dst_port": 5201,
    }
    gate = CleanupGate(lifecycle_scope, services["ECG_Monitoring"]["qos"])

    def watch_load(process):
        while process.poll() is None:
            time.sleep(0.05)
        with threat_lock:
            threat_state["status"] = (
                "ended" if process.returncode == 0 else "unknown"
            )
            threat_state["ended_at"] = time.monotonic()

    load_client = None

    try:
        h1 = net.addHost("h1", ip="10.0.0.1/8")
        h2 = net.addHost("h2", ip="10.0.0.2/8")
        s1 = net.addSwitch("s1")
        net.addLink(h1, s1)
        net.addLink(h2, s1, bw=2, max_queue_size=20, use_htb=True)
        net.start()
        if net.pingAll() != 0:
            raise RuntimeError("Connectivity check failed")

        with (folder / "receiver.jsonl").open("w") as raw, \
             (folder / "receiver_stderr.txt").open("w") as errors, \
             (folder / "load.json").open("w") as load_output, \
             (folder / "load_stderr.txt").open("w") as load_errors:

            sensor_server = h2.popen(
                ["iperf3", "-s", "-1", "-p", "5202",
                 "--json-stream", "--forceflush", "-i", "2"],
                stdout=subprocess.PIPE, stderr=errors, text=True,
            )
            load_server = h2.popen(
                ["iperf3", "-s", "-1", "-p", "5201"],
                stdout=subprocess.DEVNULL, stderr=load_errors,
            )
            processes.extend((sensor_server, load_server))

            monitor = ReceiverStreamMonitor(sensor_server, raw)

            def on_window(window):
                if load_client is not None and load_client.poll() is None:
                    # Trusted mapping from this controlled traffic generator.
                    store.publish_flow("ECG_Monitoring", {
                        "source_ip": "10.0.0.1",
                        "target_ip": "10.0.0.2",
                        "protocol": "udp",
                        "dst_port": 5201,
                    })

                publication = bridge_holder["bridge"].publish(window)
                alert = {
                    "alert_id": f"PERIODIC-{len(results) + 1}",
                    "attack_type": "DoS_Flooding",
                    "source_ip": "10.0.0.1",
                    "target_ip": "10.0.0.2",
                    "severity": "high",
                    "affected_service": "ECG_Monitoring",
                    "detector_id": "DUMMY_TESTBED",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                response = client.post("/alert", json=alert)
                if response.status_code != 201:
                    raise RuntimeError(response.get_data(as_text=True))
                result = {
                    "window": window,
                    "publication": publication,
                    "api_response": response.json,
                }
                recommendation = response.json["recommendation"]
                fresh = publication["published"]

                if fresh and action_state["stage"] == "pending":
                    if recommendation["action"] == "rate_limit":
                        action_state["initial_recommendation"] = dict(recommendation)
                        result["enforcement"] = enforcer.apply(recommendation)
                        action_state["completed_at"] = time.monotonic()
                        action_state["stage"] = "observing_initial"

                elif fresh and action_state["stage"] in (
                    "observing_initial", "observing_adjusted"
                ):
                    conservative_start = (
                        bridge_holder["bridge"].client_launch
                        + window["window_start_seconds"]
                    )
                    if conservative_start < action_state["completed_at"]:
                        result["observation_status"] = "Transition window excluded"
                    else:
                        failed = (
                            window["qos_review"]["decision"] == "review_required"
                        )
                        if action_state["stage"] == "observing_initial" and failed:
                            stronger = dict(action_state["initial_recommendation"])
                            stronger["rate_limit_kbps"] = 500
                            enforcer.cleanup()
                            result["reassessment"] = {
                                "performed": True,
                                "enforcement": enforcer.apply(stronger),
                            }
                            action_state["completed_at"] = time.monotonic()
                            action_state["stage"] = "observing_adjusted"
                        else:
                            result["final_decision"] = window["qos_review"]["decision"]
                            result["reassessment"] = {
                                "performed": action_state["stage"] == "observing_adjusted"
                            }
                            action_state["stage"] = "finished"

                if enforcer.flow_created and publication["published"]:
                    with threat_lock:
                        simulated_status = {
                            "scope": lifecycle_scope,
                            "status": threat_state["status"],
                            "ended_at_monotonic": threat_state["ended_at"],
                            "observed_monotonic": time.monotonic(),
                            "source": "Simulated test-harness status",
                        }

                    lifecycle = gate.observe(
                        window,
                        publication["sample_end_monotonic"],
                        simulated_status,
                        time.monotonic(),
                    )
                    result["threat_status"] = simulated_status
                    result["lifecycle"] = lifecycle

                    if lifecycle["action"] == "remove":
                        cookie_text = f"cookie=0x{enforcer.cookie:x},"
                        before = enforcer.run(["dump-flows", "s1"]).stdout
                        if cookie_text not in before:
                            raise RuntimeError(
                                "Rule disappeared before lifecycle cleanup"
                            )
                        enforcer.cleanup()
                        after = enforcer.run(["dump-flows", "s1"]).stdout
                        meters = enforcer.run(["meter-stats", "s1"]).stdout
                        if cookie_text in after:
                            raise RuntimeError("Owned flow remains after cleanup")
                        if f"meter:{enforcer.meter_id} " in meters:
                            raise RuntimeError("Owned meter remains after cleanup")
                        result["cleanup_verification"] = {
                            "owned_flow_removed": True,
                            "owned_meter_removed": True,
                            "after_flows": after,
                            "after_meter_stats": meters,
                        }
                        action_state["stage"] = "cleaned"
                        print("LIFECYCLE CLEANUP VERIFIED", flush=True)

                result["controller_stage"] = action_state["stage"]
                results.append(result)
                with (folder / "window_decisions.jsonl").open("a") as log:
                    log.write(json.dumps(result) + "\n")
                print(
                    "PERIODIC API:",
                    window["receiver_kbps"], "Kbit/s |",
                    window["packet_loss_percent"], "% loss |",
                    response.json["recommendation"]["action"],
                    flush=True,
                )

            monitor.on_window = on_window
            monitor.start()
            time.sleep(1)

            launch = time.monotonic()
            bridge_holder["bridge"] = LiveQoSBridge(
                store, "ECG_Monitoring", launch
            )
            sensor_client = h1.popen(
                ["iperf3", "-c", "10.0.0.2", "-p", "5202",
                 "-u", "-b", "100K", "-l", "1000", "-t", "80",
                 "--pacing-timer", "1000",
                 "--connect-timeout", "5000", "-J"],
                stdout=subprocess.DEVNULL, stderr=errors,
            )
            processes.append(sensor_client)

            deadline = time.monotonic() + 5
            receiver_started = False
            while time.monotonic() < deadline:
                if sensor_client.poll() is not None:
                    raise RuntimeError(
                        "Sensor client exited before receiver startup"
                    )
                raw_path = folder / "receiver.jsonl"
                for line in raw_path.read_text().splitlines():
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if event.get("event") == "error":
                        raise RuntimeError(str(event.get("data")))
                    if event.get("event") == "start":
                        receiver_started = True
                if receiver_started:
                    break
                time.sleep(0.05)
            if not receiver_started:
                raise RuntimeError("Receiver startup was not confirmed")
            print("Sensor receiver started; starting load", flush=True)

            load_client = h1.popen(
                ["iperf3", "-c", "10.0.0.2", "-p", "5201",
                 "-u", "-b", "5M", "-l", "1000", "-t", "30",
                 "--pacing-timer", "1000",
                 "--connect-timeout", "5000", "-J"],
                stdout=load_output, stderr=load_errors,
            )
            processes.append(load_client)
            Thread(target=watch_load, args=(load_client,), daemon=True).start()



            for process in (sensor_client, load_client):
                if process.wait(timeout=95) != 0:
                    raise RuntimeError("Traffic generator failed")
            for process in (sensor_server, load_server):
                if process.wait(timeout=10) != 0:
                    raise RuntimeError("Receiver failed")
            monitor.finish()

        load_data = json.loads((folder / "load.json").read_text())
        print(
            "Load sender Kbit/s:",
            round(load_data["end"]["sum_sent"]["bits_per_second"] / 1000, 3),
        )
        (folder / "summary.json").write_text(
            json.dumps(results, indent=2) + "\n"
        )
        print("Periodic decisions:", len(results))
        print("Completed. Results:", folder / "summary.json")

    finally:
        try:
            enforcer.cleanup()
        except Exception as error:
            print("Rule cleanup error:", error, flush=True)
        for process in processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        net.stop()


if __name__ == "__main__":
    main()
