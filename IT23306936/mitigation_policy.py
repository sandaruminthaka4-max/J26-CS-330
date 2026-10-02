def choose_action(attack_type, criticality):
    if criticality not in {"critical", "noncritical"}:
        raise ValueError("Unknown device criticality")

    if attack_type == "dos":
        if criticality == "critical":
            return {
                "action": "rate_limit",
                "reason": "Preserve connectivity for the critical device",
            }

        return {
            "action": "block",
            "duration_seconds": 60,
            "reason": "Temporarily isolate the noncritical test device",
        }

    return {
        "action": "review",
        "reason": "Automatic policy not implemented for this attack type",
    }
