import argparse
import json
from pathlib import Path


def read_udp_metrics(path):
    data = json.loads(Path(path).read_text())

    if "error" in data:
        raise ValueError(data["error"])

    end = data.get("end", {})
    receiver = end.get("sum_received")

    if receiver is None:
        for stream in end.get("streams", []):
            udp = stream.get("udp", {})
            if udp.get("sender") is False:
                receiver = udp
                break

    if receiver is None:
        raise ValueError("Receiver summary not found")

    return {
        "receiver_kbps": round(receiver["bits_per_second"] / 1000, 3),
        "packet_loss_percent": round(receiver["lost_percent"], 3),
        "jitter_ms": round(receiver["jitter_ms"], 3),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=Path)
    args = parser.parse_args()

    try:
        print(json.dumps(read_udp_metrics(args.file), indent=2))
    except (OSError, ValueError, KeyError) as error:
        raise SystemExit(f"Cannot read metrics: {error}")
