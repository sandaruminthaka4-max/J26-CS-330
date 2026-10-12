import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.append("/usr/lib/python3/dist-packages")
from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.link import TCLink
from receiver_stream_monitor import ReceiverStreamMonitor


def main():
    folder = Path(__file__).resolve().parent / "results" / (
        "receiver_live_" + datetime.now().strftime("%Y%m%d_%H%M%S")
    )
    folder.mkdir(parents=True)
    net = Mininet(controller=None, switch=OVSBridge, link=TCLink)
    processes = []

    try:
        h1 = net.addHost("h1", ip="10.0.0.1/8")
        h2 = net.addHost("h2", ip="10.0.0.2/8")
        s1 = net.addSwitch("s1")
        net.addLink(h1, s1)
        net.addLink(h2, s1, bw=2, max_queue_size=20, use_htb=True)
        net.start()
        if net.pingAll() != 0:
            raise RuntimeError("Connectivity check failed")

        with (folder / "receiver.jsonl").open("w") as output, \
             (folder / "receiver_stderr.txt").open("w") as errors:
            server = h2.popen(
                ["iperf3", "-s", "-1", "-p", "5202",
                 "--json-stream", "--forceflush", "-i", "2"],
                stdout=subprocess.PIPE, stderr=errors, text=True,
            )
            processes.append(server)
            monitor = ReceiverStreamMonitor(server, output)
            monitor.start()
            time.sleep(1)

            client = h1.popen(
                ["iperf3", "-c", "10.0.0.2", "-p", "5202",
                 "-u", "-b", "100K", "-l", "1000", "-t", "10",
                 "--pacing-timer", "1000",
                 "--connect-timeout", "5000", "-J"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True,
            )
            processes.append(client)
            stdout, stderr = client.communicate(timeout=25)
            (folder / "sender.json").write_text(stdout)
            if client.returncode != 0:
                raise RuntimeError(stderr or stdout)
            if server.wait(timeout=10) != 0:
                raise RuntimeError("Receiver failed; inspect receiver_stderr.txt")

            samples = monitor.finish()
            (folder / "periodic_samples.json").write_text(
                json.dumps(samples, indent=2) + "\n"
            )

        events = [
            json.loads(line)
            for line in (folder / "receiver.jsonl").read_text().splitlines()
            if line.strip()
        ]
        print("Event types:", [event.get("event") for event in events])
        intervals = [e for e in events if e.get("event") == "interval"]
        print("Receiver interval events:", len(intervals))
        for event in intervals[:2]:
            print(json.dumps(event, indent=2))

        print("Completed. Results folder:", folder)

    finally:
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
