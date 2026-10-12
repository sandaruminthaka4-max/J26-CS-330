import json
import subprocess
import time
from datetime import datetime
from pathlib import Path

from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.link import TCLink

BASE = Path(__file__).resolve().parent
STREAMS = (
    ("sensor", "5202", "100K", 100),
    ("load", "5201", "5M", 5000),
)


def main():
    folder = BASE / "results" / (
        "iperf_generator_" + datetime.now().strftime("%Y%m%d_%H%M%S")
    )
    folder.mkdir(parents=True)
    net = Mininet(controller=None, switch=OVSBridge, link=TCLink)
    processes = []
    files = []

    try:
        h1 = net.addHost("h1", ip="10.0.0.1/8")
        h2 = net.addHost("h2", ip="10.0.0.2/8")
        s1 = net.addSwitch("s1")
        net.addLink(h1, s1)
        net.addLink(h2, s1, bw=20, max_queue_size=20, use_htb=True)
        net.start()

        if net.pingAll() != 0:
            raise RuntimeError("Connectivity test failed")

        for label, port, rate, target in STREAMS:
            processes.append(h2.popen(
                ["iperf3", "-s", "-p", port],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ))
        time.sleep(1)

        clients = []
        for label, port, rate, target in STREAMS:
            output = (folder / f"{label}.json").open("w")
            errors = (folder / f"{label}_stderr.txt").open("w")
            files.extend((output, errors))
            client = h1.popen(
                ["iperf3", "-c", "10.0.0.2", "-p", port,
                 "-u", "-b", rate, "-l", "1000", "-t", "30",
                 "--pacing-timer", "1000",
                 "--connect-timeout", "5000", "-J"],
                stdout=output, stderr=errors,
            )
            processes.append(client)
            clients.append((label, target, client))

        for label, target, client in clients:
            if client.wait(timeout=45) != 0:
                raise RuntimeError(
                    f"{label} test failed; inspect {folder}/{label}_stderr.txt"
                )

        for file in files:
            file.close()

        for label, target, client in clients:
            report = json.loads((folder / f"{label}.json").read_text())
            if "error" in report:
                raise RuntimeError(report["error"])

            print(f"\n{label} | target: {target} Kbit/s")
            end = report["end"]
            for name in ("sum", "sum_sent", "sum_received"):
                summary = end.get(name)
                if summary is not None:
                    print(name, json.dumps(summary))

            for index, stream in enumerate(end.get("streams", [])):
                if "udp" in stream:
                    print(f"stream_{index}_udp",
                          json.dumps(stream["udp"]))

        print("\nCompleted. Results folder:", folder, flush=True)

    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        for file in files:
            if not file.closed:
                file.close()
        net.stop()


if __name__ == "__main__":
    main()
