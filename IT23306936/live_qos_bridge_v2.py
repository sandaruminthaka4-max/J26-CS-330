from qos_freshness_v2 import prepare_qos_sample


class LiveQoSBridge:
    def __init__(self, store, service_name, client_launch_monotonic):
        self.store = store
        self.service_name = service_name
        self.client_launch = client_launch_monotonic

    def publish(self, window):
        sample = prepare_qos_sample(
            window,
            client_launch_monotonic=self.client_launch,
            observed_monotonic=window["observed_monotonic"],
            now_monotonic=self.store.clock(),
            max_age_seconds=self.store.max_age,
        )
        if sample is None:
            return {"published": False, "reason": "Sample expired"}

        self.store.publish_qos(
            self.service_name,
            sample["metrics"],
            sample_end_monotonic=sample["sample_end_monotonic"],
        )
        return {
            "published": True,
            "sample_end_monotonic": sample["sample_end_monotonic"],
            "qos_age_seconds": sample["qos_age_seconds"],
            "timestamp_basis": sample["timestamp_basis"],
        }
