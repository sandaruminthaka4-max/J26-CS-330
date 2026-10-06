import json
import subprocess
import time
from pathlib import Path

from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.link import TCLink

from qos_reader import read_udp_metrics
from qos_review import review_sensor_qos

BASE = Path(__file__).resolve().parent
RESULTS = BASE / "results"
RESULTS.mkdir(exist_ok=True)


def ovs(*args):
    subprocess.run(
        ["ovs-ofctl", "-O", "OpenFlow13", *args],
        check=True,
    )


def measure(h1, scenario):
    time.sleep(2)
    processes = []
    files = []

    try:
        for label, port, rate in (
            ("sensor", "5202", "100K"),
            ("load", "5201", "5M"),
        ):
            path = RESULTS / f"congested_{scenario}_{label}.json"
            output = path.open("w")
            files.append(output)

            process = h1.popen(
                ["iperf3", "-c", "10.0.0.2", "-p", port,
                 "-u", "-b", rate, "-t", "10", "-J",
                 "--connect-timeout", "5000"],
                stdout=output,
            )
            processes.append(process)

        for process in processes:
            if process.wait(timeout=20) != 0:
                raise RuntimeError("Traffic test failed")
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait()
        for output in files:
            output.close()

    sensor = read_udp_metrics(
        RESULTS / f"congested_{scenario}_sensor.json"
    )
    load = read_udp_metrics(
        RESULTS / f"congested_{scenario}_load.json"
    )

    return {
        "scenario": scenario,
        "sensor_metrics": sensor,
        "load_metrics": load,
        "sensor_qos_review": review_sensor_qos(sensor),
    }


def main():
    net = Mininet(controller=None, switch=OVSBridge, link=TCLink)
    servers = []

    try:
        h1 = net.addHost("h1", ip="10.0.0.1/8")
        h2 = net.addHost("h2", ip="10.0.0.2/8")
        s1 = net.addSwitch("s1")
        net.addLink(h1, s1)
        net.addLink(h2, s1, bw=2, max_queue_size=20, use_htb=True)
        net.start()

        if net.pingAll() != 0:
            raise RuntimeError("Connectivity test failed")

        subprocess.run(
            ["ovs-vsctl", "set", "bridge", "s1",
             "protocols=OpenFlow10,OpenFlow13"],
            check=True,
        )

        for port in ("5201", "5202"):
            servers.append(
                h2.popen(["iperf3", "-s", "-p", port])
            )
        time.sleep(0.5)

        baseline = measure(h1, "baseline")

        ovs(
            "add-meter", "s1",
            "meter=1,kbps,stats,bands=type=drop,rate=1000",
        )
        ovs(
            "add-flow", "s1",
            "cookie=0x23,priority=110,hard_timeout=60,"
            "ip,nw_src=10.0.0.1,nw_dst=10.0.0.2,"
            "udp,tp_dst=5201,actions=meter:1,normal",
        )

        limited = measure(h1, "limited")
        measurements = [baseline, limited]
        reassessment = {
            "performed": False,
            "reason": "Sensor QoS meets test thresholds",
        }

        if (
            limited["sensor_qos_review"]["decision"]
            == "review_required"
        ):
            ovs(
                "mod-meter", "s1",
                "meter=1,kbps,stats,bands=type=drop,rate=500",
            )

            adjusted = measure(h1, "adjusted")
            measurements.append(adjusted)
            reassessment = {
                "performed": True,
                "reason": "Sensor QoS failed after the first mitigation",
                "adjusted_rate_limit_kbps": 500,
                "final_decision": adjusted["sensor_qos_review"]["decision"],
            }

        ovs("del-flows", "s1", "cookie=0x23/-1")
        ovs(
            "add-flow", "s1",
            "cookie=0x24,priority=120,"
            "ip,nw_src=10.0.0.1,nw_dst=10.0.0.2,"
            "udp,actions=drop",
        )

        receiver_code = """
import json
import socket
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("10.0.0.2", 5203))
sock.settimeout(0.2)
print("READY", flush=True)

received = set()
deadline = time.monotonic() + 12
while time.monotonic() < deadline:
    try:
        packet, _ = sock.recvfrom(2048)
        received.add(int(packet.decode()))
    except socket.timeout:
        pass
sock.close()
print(json.dumps({"received_packets": len(received)}), flush=True)
"""
        sender_code = """
import json
import socket
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sent = 0
for number in range(1000):
    sock.sendto(str(number).encode(), ("10.0.0.2", 5203))
    sent += 1
    time.sleep(0.01)
sock.close()
print(json.dumps({"sent_packets": sent}))
"""
        import select

        receiver = h2.popen(
            ["/usr/bin/python3", "-u", "-c", receiver_code],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            ready, _, _ = select.select([receiver.stdout], [], [], 5)
            if not ready or receiver.stdout.readline().strip() != "READY":
                raise RuntimeError("UDP receiver did not become ready")

            sender = h1.popen(
                ["/usr/bin/python3", "-c", sender_code],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                sent_output, sent_error = sender.communicate(timeout=20)
            finally:
                if sender.poll() is None:
                    sender.kill()
                    sender.wait()

            if sender.returncode != 0:
                raise RuntimeError(sent_error)

            received_output, received_error = receiver.communicate(timeout=20)
            if receiver.returncode != 0:
                raise RuntimeError(received_error)

            sent = json.loads(sent_output)["sent_packets"]
            received = json.loads(received_output)["received_packets"]
            static = {
                "scenario": "static_udp_block",
                "measurement_method": "Numbered UDP packets on port 5203",
                "sent_packets": sent,
                "received_packets": received,
                "packet_loss_percent": round(
                    100 * (sent - received) / sent, 3
                ),
            }
            measurements.append(static)
        finally:
            if receiver.poll() is None:
                receiver.kill()
                receiver.wait()

        report = {
            "mode": "adaptive_vs_static_udp_block",
            "static_scope": "All UDP from 10.0.0.1 to 10.0.0.2",
            "rate_limit_kbps": 1000,
            "measurements": measurements,
            "reassessment": reassessment,
        }
        path = RESULTS / "static_comparison.json"
        path.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
        print("Saved:", path)

    finally:
        try:
            for server in servers:
                if server.poll() is None:
                    server.terminate()
                server.wait(timeout=5)
        finally:
            net.stop()


if __name__ == "__main__":
    main()
