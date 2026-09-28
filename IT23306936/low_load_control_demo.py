from datetime import datetime

from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.link import TCLink

import fair_comparison_demo as demo


def main():
    folder = demo.BASE / "results" / (
        "low_load_" + datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    )
    folder.mkdir(parents=True)

    net = Mininet(controller=None, switch=OVSBridge, link=TCLink)
    original_rate = demo.STREAMS["load"]["rate_kbps"]

    try:
        h1 = net.addHost("h1", ip="10.0.0.1/8")
        h2 = net.addHost("h2", ip="10.0.0.2/8")
        s1 = net.addSwitch("s1")
        net.addLink(h1, s1)
        net.addLink(h2, s1, bw=2, max_queue_size=20, use_htb=True)
        net.start()

        if net.pingAll() != 0:
            raise RuntimeError("Connectivity test failed")

        # This also controls the separate sender worker.
        worker_path = folder / "low_load_worker.py"
        code = (demo.BASE / "fair_comparison_demo.py").read_text()
        old = '"load": {"port": 5201, "rate_kbps": 5000}'
        new = '"load": {"port": 5201, "rate_kbps": 100}'
        assert code.count(old) == 1, "Expected stream configuration not found"
        worker_path.write_text(code.replace(old, new))

        demo.STREAMS["load"]["rate_kbps"] = 100
        demo.__file__ = str(worker_path)
        demo.measure(h1, h2, "low_load_control", folder)
        print("Completed. Results:", folder / "low_load_control.json")
    finally:
        demo.STREAMS["load"]["rate_kbps"] = original_rate
        net.stop()


if __name__ == "__main__":
    main()
