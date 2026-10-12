import re


def read_ping_metrics(text):
    count = re.search(
        r"(\d+) packets transmitted,\s*(\d+) received",
        text,
    )
    if count is None:
        raise ValueError("Ping packet summary not found")

    sent, received = map(int, count.groups())
    if sent <= 0 or not 0 <= received <= sent:
        raise ValueError("Invalid ping packet counts")

    summary = re.search(
        r"(?:rtt|round-trip) min/avg/max/(?:mdev|stddev) = "
        r"([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms",
        text,
    )

    result = {
        "measurement_method": "ICMP round-trip time",
        "sent_packets": sent,
        "received_packets": received,
        "packet_loss_percent": round(100 * (sent - received) / sent, 3),
        "rtt_min_ms": None,
        "rtt_avg_ms": None,
        "rtt_max_ms": None,
    }
    if received > 0:
        if summary is None:
            raise ValueError("RTT summary missing despite received packets")
        minimum, average, maximum, _ = map(float, summary.groups())
        result.update(
            rtt_min_ms=minimum,
            rtt_avg_ms=average,
            rtt_max_ms=maximum,
        )
    return result


import math
from collections import deque
from pathlib import Path
from threading import Lock

PING_LINE_PATTERN = re.compile(
    r"(?:\[([\d.]+)\]\s*)?.*?icmp_seq=(\d+).*?time([=<])([\d.]+)\s*ms"
)


def parse_ping_line(line, session_id="default"):
    match = PING_LINE_PATTERN.search(line)
    if not match:
        return None
    timestamp_str, seq_str, comparison, rtt_str = match.groups()
    timestamp = None
    if timestamp_str is not None:
        try:
            timestamp = float(timestamp_str)
            if not math.isfinite(timestamp):
                return None
        except ValueError:
            return None

    try:
        seq = int(seq_str)
        rtt = float(rtt_str)
        if seq < 0 or not math.isfinite(rtt) or rtt < 0:
            return None
    except ValueError:
        return None

    return {
        "session_id": str(session_id),
        "timestamp_unix": timestamp,
        "icmp_sequence": seq,
        "rtt_ms": rtt,
        "is_upper_bound": comparison == "<",
        "is_dup_flag": "(DUP!)" in line,
    }


class PeriodicDelayMonitor:
    """Thread-safe periodic ICMP delay monitor and accounting engine.

    Measurement invariants:
    - Half-open window boundary: start <= timestamp < end.
    - Explicit input validation for timestamps, probe interval and packet counts.
    - Never infers sent_packets from window duration or probe interval.
    - Without verified send records, returns sent_packets=None and loss=None with
      an explicit unavailable reason; reply-only RTT statistics are still reported.
    - Deduplicates replies by (session_id, icmp_sequence).
    - Preserves time<... upper-bound estimates; excludes them from exact RTT min/avg/max.
    - Verified per-window loss requires verified probe send records, session/sequence
      correlation, and an elapsed late-reply timeout.
    - Bounded memory history (FIFO) and optional raw line logging.
    """

    def __init__(
        self,
        probe_interval_seconds=1.0,
        late_reply_timeout_seconds=1.0,
        max_history_samples=10_000,
        session_id="default",
        raw_log_file=None,
    ):
        for name, val in [
            ("probe_interval_seconds", probe_interval_seconds),
            ("late_reply_timeout_seconds", late_reply_timeout_seconds),
        ]:
            if (
                isinstance(val, bool)
                or not isinstance(val, (int, float))
                or not math.isfinite(val)
                or (val <= 0 if name == "probe_interval_seconds" else val < 0)
            ):
                raise ValueError(f"{name} must be a positive finite number: {val}")

        if (
            isinstance(max_history_samples, bool)
            or not isinstance(max_history_samples, int)
            or max_history_samples <= 0
        ):
            raise ValueError(f"max_history_samples must be a positive integer: {max_history_samples}")

        self.probe_interval = float(probe_interval_seconds)
        self.late_reply_timeout = float(late_reply_timeout_seconds)
        self.max_history = int(max_history_samples)
        self.default_session_id = str(session_id)
        self.raw_log_file = Path(raw_log_file) if raw_log_file is not None else None

        self._lock = Lock()
        self._samples = deque(maxlen=self.max_history)
        self._sent_probes = deque(maxlen=self.max_history)
        self._seen_replies = set()
        self._seen_reply_order = deque(maxlen=self.max_history)
        self._duplicate_reply_count = 0

    def record_probe_sent(self, seq, send_time_unix, session_id=None):
        """Records verified transmission of a probe sequence."""
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise ValueError(f"seq must be a non-negative integer: {seq}")
        if (
            isinstance(send_time_unix, bool)
            or not isinstance(send_time_unix, (int, float))
            or not math.isfinite(send_time_unix)
        ):
            raise ValueError(f"send_time_unix must be a finite number: {send_time_unix}")

        sid = self.default_session_id if session_id is None else str(session_id)
        with self._lock:
            self._sent_probes.append({
                "session_id": sid,
                "seq": seq,
                "send_time_unix": float(send_time_unix),
            })

    def record_reply_sample(self, sample):
        """Records an incoming reply sample with session/sequence deduplication."""
        sid = sample.get("session_id", self.default_session_id)
        seq = sample["icmp_sequence"]
        key = (sid, seq)
        with self._lock:
            if key in self._seen_replies or sample.get("is_dup_flag", False):
                self._duplicate_reply_count += 1
                dup = dict(sample)
                dup["is_duplicate"] = True
                return dup

            if len(self._seen_reply_order) >= self.max_history:
                oldest = self._seen_reply_order.popleft()
                self._seen_replies.discard(oldest)
            self._seen_replies.add(key)
            self._seen_reply_order.append(key)

            sample_record = dict(sample)
            sample_record["is_duplicate"] = False
            self._samples.append(sample_record)
            return sample_record

    def feed_line(self, line, session_id=None):
        if self.raw_log_file is not None:
            with self.raw_log_file.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        sample = parse_ping_line(line, session_id=session_id or self.default_session_id)
        if sample is not None:
            return self.record_reply_sample(sample)
        return None

    def feed_text(self, text, session_id=None):
        for line in text.splitlines():
            self.feed_line(line, session_id=session_id)

    def get_window_metrics(
        self,
        start_unix,
        end_unix,
        now_unix=None,
        verified_sent_count=None,
        expected_count=None,  # alias for backwards compatibility
    ):
        """Calculates delay and accounting metrics for half-open interval [start_unix, end_unix)."""
        for name, val in [("start_unix", start_unix), ("end_unix", end_unix)]:
            if (
                isinstance(val, bool)
                or not isinstance(val, (int, float))
                or not math.isfinite(val)
            ):
                raise ValueError(f"{name} must be a finite number: {val}")

        if start_unix >= end_unix:
            raise ValueError(
                f"Window boundaries must be strictly ordered start < end: start={start_unix}, end={end_unix}"
            )

        sent_count_param = verified_sent_count if verified_sent_count is not None else expected_count
        if sent_count_param is not None:
            if isinstance(sent_count_param, bool) or not isinstance(sent_count_param, int) or sent_count_param < 0:
                raise ValueError(f"verified_sent_count must be a non-negative integer: {sent_count_param}")

        if now_unix is not None:
            if isinstance(now_unix, bool) or not isinstance(now_unix, (int, float)) or not math.isfinite(now_unix):
                raise ValueError(f"now_unix must be a finite number: {now_unix}")
            if now_unix < start_unix:
                raise ValueError(f"now_unix ({now_unix}) cannot precede window start ({start_unix})")

        effective_now = now_unix if now_unix is not None else end_unix

        with self._lock:
            # 1. Half-open filter: start <= timestamp < end
            window_samples = [
                s for s in self._samples
                if s["timestamp_unix"] is not None and start_unix <= s["timestamp_unix"] < end_unix
            ]
            sent_in_window = [
                p for p in self._sent_probes
                if start_unix <= p["send_time_unix"] < end_unix
            ]
            seen_replies_snapshot = set(self._seen_replies)
            dup_count = self._duplicate_reply_count

        received_count = len(window_samples)

        # 2. Separate exact RTT samples from upper-bound readings (<...)
        exact_rtts = [s["rtt_ms"] for s in window_samples if not s["is_upper_bound"]]
        upper_bound_rtts = [s["rtt_ms"] for s in window_samples if s["is_upper_bound"]]

        if exact_rtts:
            rtt_min_ms = round(min(exact_rtts), 3)
            rtt_avg_ms = round(sum(exact_rtts) / len(exact_rtts), 3)
            rtt_max_ms = round(max(exact_rtts), 3)
            rtt_status = "measured"
            rtt_reason = None
        else:
            rtt_min_ms = None
            rtt_avg_ms = None
            rtt_max_ms = None
            if upper_bound_rtts:
                rtt_status = "upper_bound_only"
                rtt_reason = "Only upper-bound readings (<...) received; exact RTT is undefined"
            else:
                rtt_status = "unavailable"
                rtt_reason = "No ICMP replies received in window"

        upper_bound_min_ms = round(min(upper_bound_rtts), 3) if upper_bound_rtts else None

        # 3. Verified send accounting and packet loss resolution
        sent_packets = None
        packet_loss_percent = None
        loss_status = "unavailable"
        loss_unavailable_reason = None

        if sent_count_param is not None:
            # Caller supplied explicit verified sent count
            sent_packets = sent_count_param
            if sent_packets > 0:
                lost = max(0, sent_packets - received_count)
                packet_loss_percent = round(100.0 * lost / sent_packets, 3)
                loss_status = "verified_caller_count"
                loss_unavailable_reason = None
            else:
                loss_status = "unavailable"
                loss_unavailable_reason = "Verified sent packet count is zero"

        elif sent_in_window:
            # Internal probe-send tracking correlated by sequence & late-reply timeout
            sent_count = len(sent_in_window)
            sent_packets = sent_count
            correlated_received = 0
            pending_probes = 0

            for p in sent_in_window:
                key = (p["session_id"], p["seq"])
                if key in seen_replies_snapshot:
                    correlated_received += 1
                else:
                    if effective_now < p["send_time_unix"] + self.late_reply_timeout:
                        pending_probes += 1

            if pending_probes > 0:
                packet_loss_percent = None
                loss_status = "pending_late_reply_timeout"
                loss_unavailable_reason = (
                    f"Reply-wait period not completed: {pending_probes} probes still within "
                    f"{self.late_reply_timeout}s timeout"
                )
            else:
                lost = sent_count - correlated_received
                packet_loss_percent = round(100.0 * max(0, lost) / sent_count, 3)
                loss_status = "verified_send_correlation"
                loss_unavailable_reason = None

        else:
            # Unverified sends: never infer from duration/probe interval!
            sent_packets = None
            packet_loss_percent = None
            loss_status = "unavailable"
            loss_unavailable_reason = (
                "Verified probe-send records unavailable; periodic ICMP loss cannot be inferred "
                "from window duration or probe interval"
            )

        return {
            "measurement_method": "ICMP round-trip time (reply-arrival window)",
            "window_start_unix": start_unix,
            "window_end_unix": end_unix,
            "window_duration_seconds": round(end_unix - start_unix, 3),
            "window_label": "reply_arrival_half_open",
            "window_alignment_status": "Reply arrival timestamp window; not established as synchronized with receiver-side UDP measurement window",
            "sent_packets": sent_packets,
            "received_packets": received_count,
            "packet_loss_percent": packet_loss_percent,
            "loss_status": loss_status,
            "loss_unavailable_reason": loss_unavailable_reason,
            "rtt_min_ms": rtt_min_ms,
            "rtt_avg_ms": rtt_avg_ms,
            "rtt_max_ms": rtt_max_ms,
            "rtt_status": rtt_status,
            "rtt_unavailable_reason": rtt_reason,
            "exact_reply_samples_count": len(exact_rtts),
            "upper_bound_reply_samples_count": len(upper_bound_rtts),
            "upper_bound_min_ms": upper_bound_min_ms,
            "duplicate_replies_count": dup_count,
        }


