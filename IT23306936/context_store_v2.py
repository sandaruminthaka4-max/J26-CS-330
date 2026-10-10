import math
import time
from copy import deepcopy
from threading import Lock


class ContextStore:
    def __init__(self, max_age_seconds=10, clock=time.monotonic):
        self.max_age = max_age_seconds
        self.clock = clock
        self.flows = {}
        self.qos = {}
        self.lock = Lock()

    def publish_flow(self, service_name, flow, malicious_confirmed=False):
        # Called only by the trusted testbed/controller adapter.
        # Not exposed as an alert API endpoint.
        key = (service_name, flow["source_ip"], flow["target_ip"])
        with self.lock:
            self.flows[key] = {
                "flow": deepcopy(flow),
                "sampled_at": self.clock(),
                "malicious_confirmed": malicious_confirmed is True,
            }

    def publish_qos(self, service_name, metrics, sample_end_monotonic):
        # Use the actual measurement end time, not file-read time.
        now = self.clock()
        if (
            isinstance(sample_end_monotonic, bool)
            or not isinstance(sample_end_monotonic, (int, float))
            or not math.isfinite(sample_end_monotonic)
            or sample_end_monotonic > now
        ):
            raise ValueError("Invalid QoS measurement timestamp")

        with self.lock:
            previous = self.qos.get(service_name)
            if previous and sample_end_monotonic < previous["sampled_at"]:
                raise ValueError("Cannot replace QoS with an older sample")
            self.qos[service_name] = {
                "metrics": deepcopy(metrics),
                "sampled_at": sample_end_monotonic,
            }

    def provide(self, alert, service):
        now = self.clock()
        key = (
            alert["affected_service"],
            alert["source_ip"],
            alert["target_ip"],
        )
        context = {}
        with self.lock:
            flow = self.flows.get(key)
            if flow:
                age = now - flow["sampled_at"]
                if 0 <= age <= self.max_age:
                    context["verified_flow"] = deepcopy(flow["flow"])
                    context["malicious_confirmed"] = flow["malicious_confirmed"]

            qos = self.qos.get(alert["affected_service"])
            if qos:
                age = now - qos["sampled_at"]
                if 0 <= age <= self.max_age:
                    context["qos"] = deepcopy(qos["metrics"])
                    context["qos_age_seconds"] = age

        return context
