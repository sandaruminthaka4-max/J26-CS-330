import math


class CleanupGate:
    def __init__(self, scope, qos_limits, required_windows=2):
        self.scope = dict(scope)
        self.limits = dict(qos_limits)
        self.required = required_windows
        self.stable_count = 0
        self.last_end = None

    def hold(self, reason, reset=True):
        if reset:
            self.stable_count = 0
        return {
            "action": "keep",
            "reason": reason,
            "stable_windows": self.stable_count,
        }

    def observe(self, window, measurement_end, threat, now):
        if not isinstance(threat, dict):
            return self.hold("Threat status unavailable")
        if threat.get("scope") != self.scope:
            return self.hold("Threat status scope mismatch")

        threat_time = threat.get("observed_monotonic")
        ended_at = threat.get("ended_at_monotonic")
        for value in (threat_time, measurement_end, now):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
            ):
                return self.hold("Invalid timestamps")

        if not 0 <= now - threat_time <= 10:
            return self.hold("Threat status is stale or future-dated")
        if threat.get("status") != "ended":
            return self.hold("Threat is not confirmed ended")
        if not 0 <= now - measurement_end <= 10:
            return self.hold("QoS sample is stale or future-dated")

        duration = window.get("window_duration_seconds")
        throughput = window.get("receiver_kbps")
        loss = window.get("packet_loss_percent")
        for value in (duration, throughput, loss):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value < 0
            ):
                return self.hold("Invalid QoS sample")
        if duration < 9.9 or loss > 100:
            return self.hold("Invalid observation window")

        if (
            isinstance(ended_at, bool)
            or not isinstance(ended_at, (int, float))
            or not math.isfinite(ended_at)
            or not 0 <= ended_at <= threat_time
        ):
            return self.hold("Invalid threat-ended timestamp")

        start = measurement_end - duration
        if start < ended_at:
            return self.hold("Window overlaps threat-ended transition")

        if self.last_end is not None:
            if measurement_end <= self.last_end:
                return self.hold("Duplicate or older window", reset=False)
            if start < self.last_end - 0.01:
                return self.hold("Overlapping windows")
            if start > self.last_end + 0.1:
                self.stable_count = 0

        self.last_end = measurement_end
        if (
            throughput < self.limits["min_throughput_kbps"]
            or loss > self.limits["max_loss_percent"]
        ):
            return self.hold("QoS remains degraded")

        if self.limits.get("max_delay_ms") is not None:
            return self.hold("Delay-aware cleanup is not implemented yet")

        self.stable_count += 1
        return {
            "action": "remove" if self.stable_count >= self.required else "keep",
            "reason": "Fresh ended status and stable post-ended QoS windows",
            "stable_windows": self.stable_count,
        }
