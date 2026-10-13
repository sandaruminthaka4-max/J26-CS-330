import math
from copy import deepcopy


def prepare_qos_sample(window, client_launch_monotonic,
                       observed_monotonic, now_monotonic,
                       max_age_seconds=10):
    end = window["window_end_seconds"]

    for value in (
        client_launch_monotonic, observed_monotonic,
        now_monotonic, end, max_age_seconds,
    ):
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value < 0
        ):
            raise ValueError("Invalid timing value")

    estimated_end = client_launch_monotonic + end

    if observed_monotonic > now_monotonic:
        raise ValueError("Observation timestamp is in the future")
    if estimated_end > observed_monotonic:
        raise ValueError("Measurement timing is inconsistent")

    age = now_monotonic - estimated_end
    if age > max_age_seconds:
        return None

    return {
        "metrics": deepcopy(window),
        "sample_end_monotonic": estimated_end,
        "qos_age_seconds": age,
        "timestamp_basis": "Client launch plus receiver-relative end",
        "timing_note": "Conservative estimate for the same-VM testbed",
    }
