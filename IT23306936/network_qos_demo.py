import json
from datetime import datetime, timezone
from pathlib import Path

from mininet.net import Mininet
from mininet.node import OVSBridge

from qos_reader import read_udp_metrics
from qos_review import review_sensor_qos

BASE = Path(__file__).resolve().parent
RESULTS = BASE / "results"
RESULTS.mkdir(exist_ok=True)


def main():
    net = Mininet(controller=None, switch=OVSBridge)
    server = None

    try:
        h1 = net.addHost("h1", ip="10.0.0.1/8")
        h2 = net.addHost("h2", ip="10.0.0.2/8")
        h3 = net.addHost("h3", ip="10.0.0.3/8")
        s1 = net.addSwitch("s1")

        for host in (h1, h2, h3):
            net.addLink(host, s1)

        net.start()

        if net.pingAll() != 0:
            raise RuntimeError("Connectivity test failed")

        server = h2.popen(["iperf3", "-s", "-p", "5202"])
        measurement = RESULTS / "automated_sensor_udp.json"

        with measurement.open("w") as output:
            client = h1.popen(
                ["iperf3", "-c", "10.0.0.2", "-p", "5202",
                 "-u", "-b", "100K", "-t", "10", "-J",
                 "--connect-timeout", "5000"],
                stdout=output,
            )
            try:
                code = client.wait(timeout=20)
            except Exception:
                client.kill()
                client.wait()
                raise

        if code != 0:
            raise RuntimeError(
                "iperf3 failed; inspect automated_sensor_udp.json"
            )

        metrics = read_udp_metrics(measurement)
        report = {
            "reviewed_at": datetime.now(timezone.utc).isoformat(),
            "sensor_metrics": metrics,
            "qos_review": review_sensor_qos(metrics),
            "mode": "automated_measurement_review",
        }

        path = RESULTS / "automated_qos_review.json"
        path.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
        print("Saved:", path)

    finally:
        if server is not None:
            if server.poll() is None:
                server.terminate()
            server.wait(timeout=5)
        net.stop()


if __name__ == "__main__":
    main()
