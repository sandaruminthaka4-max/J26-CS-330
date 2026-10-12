import math


def aggregate_receiver_window(intervals, minimum_seconds=10):
    if not intervals:
        raise ValueError("No receiver intervals")

    seconds = 0.0
    received_bytes = 0
    packets = 0
    lost = 0
    previous_end = None

    for item in intervals:
        if item.get("sender") is not False or item.get("omitted", False):
            raise ValueError("Expected non-omitted receiver intervals")

        start = item["start"]
        end = item["end"]
        duration = item["seconds"]
        for value in (start, end, duration):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
            ):
                raise ValueError("Invalid interval timing")
        if duration <= 0 or end <= start:
            raise ValueError("Invalid interval duration")
        if abs((end - start) - duration) > 0.01:
            raise ValueError("Inconsistent interval timing")
        if previous_end is not None and abs(start - previous_end) > 0.01:
            raise ValueError("Intervals are not contiguous")

        count = item["packets"]
        missing = item["lost_packets"]
        byte_count = item["bytes"]
        for value in (count, missing, byte_count):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("Invalid packet or byte count")
        if missing > count:
            raise ValueError("Lost packets exceed packet count")

        seconds += duration
        received_bytes += byte_count
        packets += count
        lost += missing
        previous_end = end

    if seconds < minimum_seconds:
        raise ValueError("Observation window is too short")
    if packets == 0:
        raise ValueError("Packet loss cannot be determined without packet counts")

    return {
        "window_start_seconds": intervals[0]["start"],
        "window_end_seconds": intervals[-1]["end"],
        "window_duration_seconds": seconds,
        "interval_count": len(intervals),
        "receiver_kbps": round(received_bytes * 8 / seconds / 1000, 3),
        "packet_loss_percent": round(100 * lost / packets, 3),
        "packets": packets,
        "lost_packets": lost,
        "received_bytes": received_bytes,
    }
