import json
import select
import socket
import struct
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

DURATION = 30
PAYLOAD_BYTES = 1000
STREAMS = {
    "sensor": {"port": 5202, "rate_kbps": 100},
    "load": {"port": 5201, "rate_kbps": 5000},
}
BASE = Path(__file__).resolve().parent


def worker(mode, start):
    end = start + DURATION

    if mode == "receiver":
        sockets = {}
        received = {label: set() for label in STREAMS}
        try:
            for label, config in STREAMS.items():
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sockets[sock] = label
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
                sock.bind(("10.0.0.2", config["port"]))
                sock.setblocking(False)

            print("READY", flush=True)

            # Allow one second for packets already in transit to arrive.
            while time.monotonic() < end + 1:
                ready, _, _ = select.select(list(sockets), [], [], 0.1)
                for sock in ready:
                    while True:
                        try:
                            packet, _ = sock.recvfrom(2048)
                        except BlockingIOError:
                            break
                        if len(packet) == PAYLOAD_BYTES:
                            sequence = struct.unpack("!Q", packet[:8])[0]
                            label = sockets[sock]
                            expected = int(
                                STREAMS[label]["rate_kbps"] * 1000
                                * DURATION / (8 * PAYLOAD_BYTES)
                            )
                            if sequence < expected:
                                received[label].add(sequence)

            print(json.dumps({
                label: len(numbers)
                for label, numbers in received.items()
            }), flush=True)
        finally:
            for sock in sockets:
                sock.close()

    elif mode == "sender":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sent = {label: 0 for label in STREAMS}
        timing = {
            label: {"max_lateness_ms": 0.0, "late_over_5ms_packets": 0}
            for label in STREAMS
        }
        expected = {
            label: int(config["rate_kbps"] * 1000 * DURATION
                       / (8 * PAYLOAD_BYTES))
            for label, config in STREAMS.items()
        }
        intervals = {
            label: 8 * PAYLOAD_BYTES / (config["rate_kbps"] * 1000)
            for label, config in STREAMS.items()
        }

        try:
            while time.monotonic() < end:
                label = min(
                    STREAMS,
                    key=lambda name: start + sent[name] * intervals[name],
                )
                if sent[label] >= expected[label]:
                    if all(sent[name] >= expected[name] for name in STREAMS):
                        break
                    candidates = [
                        name for name in STREAMS
                        if sent[name] < expected[name]
                    ]
                    label = min(
                        candidates,
                        key=lambda name: start + sent[name] * intervals[name],
                    )

                due = start + sent[label] * intervals[label]
                delay = due - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                if time.monotonic() >= end:
                    break

                lateness_ms = max(
                    0.0, (time.monotonic() - due) * 1000
                )
                timing[label]["max_lateness_ms"] = max(
                    timing[label]["max_lateness_ms"], lateness_ms
                )
                if lateness_ms > 5:
                    timing[label]["late_over_5ms_packets"] += 1

                packet = (
                    struct.pack("!Q", sent[label])
                    + bytes(PAYLOAD_BYTES - 8)
                )
                sock.sendto(packet, ("10.0.0.2", STREAMS[label]["port"]))
                sent[label] += 1

            print(json.dumps({
                "sent": sent,
                "timing": timing,
            }), flush=True)
        finally:
            sock.close()


def ovs(*args):
    subprocess.run(
        ["ovs-ofctl", "-O", "OpenFlow13", *args],
        check=True,
    )



def capture_counters(h1, h2):
    ovs_counters = {}
    for command in ("dump-flows", "meter-stats"):
        result = subprocess.run(
            ["ovs-ofctl", "-O", "OpenFlow13", command, "s1"],
            capture_output=True, text=True,
        )
        ovs_counters[command] = {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    data = {
        "ovs": ovs_counters,
        "h1_snmp": h1.cmd("cat /proc/net/snmp"),
        "h2_snmp": h2.cmd("cat /proc/net/snmp"),
    }
    for interface in ("h1-eth0", "h2-eth0"):
        host = h1 if interface.startswith("h1") else h2
        data[interface] = host.cmd(
            "tc -s qdisc show dev " + interface
        )
    for interface in ("s1-eth1", "s1-eth2"):
        result = subprocess.run(
            ["tc", "-s", "qdisc", "show", "dev", interface],
            capture_output=True, text=True,
        )
        data[interface] = {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    return data

def measure(h1, h2, scenario, folder):
    from qos_review import review_sensor_qos

    time.sleep(2)
    counters_before = capture_counters(h1, h2)
    start = time.monotonic() + 3
    processes = []

    try:
        receiver = h2.popen(
            ["/usr/bin/python3", str(Path(__file__).resolve()),
             "--worker", "receiver", str(start)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        processes.append(receiver)
        ready, _, _ = select.select([receiver.stdout], [], [], 5)
        if not ready or receiver.stdout.readline().strip() != "READY":
            raise RuntimeError("UDP receiver did not become ready")
        if time.monotonic() >= start:
            raise RuntimeError("Receiver startup missed scheduled start")

        sender = h1.popen(
            ["/usr/bin/python3", str(Path(__file__).resolve()),
             "--worker", "sender", str(start)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        processes.append(sender)

        sent_output, sent_error = sender.communicate(timeout=DURATION + 10)
        if sender.returncode != 0:
            raise RuntimeError(sent_error)

        received_output, received_error = receiver.communicate(timeout=10)
        if receiver.returncode != 0:
            raise RuntimeError(received_error)

        sender_report = json.loads(sent_output)
        sent = sender_report["sent"]
        received = json.loads(received_output)
        result = {
            "scenario": scenario,
            "sender_timing": sender_report["timing"],
        }

        for label, config in STREAMS.items():
            expected = int(
                config["rate_kbps"] * 1000 * DURATION
                / (8 * PAYLOAD_BYTES)
            )
            if sent[label] == 0:
                raise RuntimeError(f"No packets sent for {label}")
            if received[label] > sent[label]:
                raise RuntimeError(f"Invalid packet counts for {label}")

            result[label + "_metrics"] = {
                "sent_packets": sent[label],
                "received_packets": received[label],
                "expected_sent_packets": expected,
                "offered_kbps": round(
                    sent[label] * PAYLOAD_BYTES * 8 / DURATION / 1000, 3
                ),
                "receiver_kbps": round(
                    received[label] * PAYLOAD_BYTES * 8
                    / DURATION / 1000, 3
                ),
                "packet_loss_percent": round(
                    100 * (sent[label] - received[label]) / sent[label], 3
                ),
                "sender_schedule_complete": sent[label] == expected,
            }

        result["sensor_qos_review"] = review_sensor_qos(
            result["sensor_metrics"]
        )
        (folder / f"{scenario}.json").write_text(
            json.dumps(result, indent=2) + "\n"
        )
        print(json.dumps(result, indent=2), flush=True)
        diagnostics = {
            "scenario": scenario,
            "before": counters_before,
            "after": capture_counters(h1, h2),
        }
        (folder / f"{scenario}_counters.json").write_text(
            json.dumps(diagnostics, indent=2) + "\n"
        )
        return result
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait()


def main():
    from mininet.net import Mininet
    from mininet.node import OVSBridge
    from mininet.link import TCLink

    folder = BASE / "results" / (
        "ovs_diagnostic_" + datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    )
    folder.mkdir(parents=True)
    net = Mininet(controller=None, switch=OVSBridge, link=TCLink)

    try:
        h1 = net.addHost("h1", ip="10.0.0.1/8")
        h2 = net.addHost("h2", ip="10.0.0.2/8")
        s1 = net.addSwitch("s1")
        net.addLink(h1, s1)
        net.addLink(h2, s1, bw=2, max_queue_size=20, use_htb=True)
        net.start()

        subprocess.run(
            ["ovs-vsctl", "set", "bridge", "s1",
             "protocols=OpenFlow10,OpenFlow13"], check=True,
        )
        if net.pingAll() != 0:
            raise RuntimeError("Connectivity test failed")

        measurements = [measure(h1, h2, "baseline", folder)]

        ovs("add-meter", "s1",
            "meter=1,kbps,stats,bands=type=drop,rate=1000")
        ovs("add-flow", "s1",
            "cookie=0x23,priority=110,"
            "udp,nw_src=10.0.0.1,nw_dst=10.0.0.2,"
            "tp_dst=5201,actions=meter:1,normal")

        limited = measure(h1, h2, "limited", folder)
        measurements.append(limited)
        reassessment = {
            "performed": False,
            "reason": "Sensor QoS meets test thresholds",
        }

        if limited["sensor_qos_review"]["decision"] == "review_required":
            ovs("mod-meter", "s1",
                "meter=1,kbps,stats,bands=type=drop,rate=500")
            adjusted = measure(h1, h2, "adjusted", folder)
            measurements.append(adjusted)
            reassessment = {
                "performed": True,
                "adjusted_rate_limit_kbps": 500,
                "final_decision": adjusted["sensor_qos_review"]["decision"],
            }

        ovs("del-flows", "s1", "cookie=0x23/-1")
        ovs("del-meters", "s1", "meter=1")
        ovs("add-flow", "s1",
            "cookie=0x24,priority=120,"
            "udp,nw_src=10.0.0.1,nw_dst=10.0.0.2,actions=drop")

        measurements.append(
            measure(h1, h2, "static_udp_block", folder)
        )

        report = {
            "mode": "matched_udp_adaptive_vs_static",
            "duration_seconds": DURATION,
            "receiver_drain_seconds": 1,
            "payload_bytes": PAYLOAD_BYTES,
            "streams": STREAMS,
            "jitter_measured": False,
            "static_scope": "All UDP from 10.0.0.1 to 10.0.0.2",
            "measurements": measurements,
            "reassessment": reassessment,
        }
        path = folder / "comparison.json"
        path.write_text(json.dumps(report, indent=2) + "\n")
        print("Completed. Results:", path, flush=True)
    finally:
        net.stop()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        worker(sys.argv[2], float(sys.argv[3]))
    else:
        main()
