import ipaddress
import math


def choose_action(alert, service, context):
    def decision(action, reason, flow=None):
        result = {
            "action": action,
            "reason": reason,
            "enforcement_enabled": False,
            "policy_version": "experimental_v2",
        }
        if flow is not None:
            result["scope"] = flow
        if action == "rate_limit":
            result["rate_limit_kbps"] = 1000
        if action in {"rate_limit", "block"}:
            result["duration_seconds"] = context.get("rule_duration_seconds", 300)
        return result

    raw_flow = context.get("verified_flow")
    if not isinstance(raw_flow, dict):
        return decision("review", "Verified suspicious flow is unavailable")

    try:
        source = str(ipaddress.IPv4Address(raw_flow["source_ip"]))
        target = str(ipaddress.IPv4Address(raw_flow["target_ip"]))
        protocol = raw_flow["protocol"]
        port = raw_flow["dst_port"]
    except (KeyError, ValueError, TypeError):
        return decision("review", "Invalid flow context")

    if (
        source != alert["source_ip"]
        or target != alert["target_ip"]
        or protocol not in {"udp", "tcp"}
        or isinstance(port, bool)
        or not isinstance(port, int)
        or not 1 <= port <= 65535
    ):
        return decision("review", "Flow context does not match the alert")

    flow = {
        "source_ip": source,
        "target_ip": target,
        "protocol": protocol,
        "dst_port": port,
    }

    protected = context.get("protected_services")
    if not isinstance(protected, list):
        return decision("review", "Protected service registry is unavailable")

    for protected_service in protected:
        if (
            target == protected_service["target_ip"]
            and protocol == protected_service["protocol"]
            and port == protected_service["port"]
        ):
            return decision(
                "review", "Rule scope overlaps a registered critical service"
            )

    criticality = service.get("criticality")
    if criticality not in {"critical", "noncritical"}:
        return decision("review", "Invalid service criticality")

    if criticality == "critical":
        if (
            target == service["target_ip"]
            and protocol == service["protocol"]
            and port == service["port"]
        ):
            return decision(
                "review",
                "Suspicious flow overlaps the protected service",
            )

        qos = context.get("qos")
        age = context.get("qos_age_seconds")
        if (
            isinstance(age, bool)
            or not isinstance(age, (int, float))
            or not math.isfinite(age)
            or not 0 <= age <= 10
            or not isinstance(qos, dict)
        ):
            return decision("review", "Fresh QoS context is unavailable")

        limits = service.get("qos")
        if not isinstance(limits, dict):
            return decision("review", "QoS limits are unavailable")

        throughput = qos.get("receiver_kbps")
        loss = qos.get("packet_loss_percent")
        for value in (throughput, loss):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value < 0
            ):
                return decision("review", "Invalid QoS measurements")
        if loss > 100:
            return decision("review", "Invalid packet loss")

        delay_limit = limits.get("max_delay_ms")
        if delay_limit is not None:
            delay = qos.get("delay_ms")
            if (
                isinstance(delay, bool)
                or not isinstance(delay, (int, float))
                or not math.isfinite(delay)
                or delay < 0
            ):
                return decision("review", "Delay measurement unavailable")
            if delay > delay_limit:
                return decision("review", "Protected service delay is degraded")

        if (
            throughput < limits["min_throughput_kbps"]
            or loss > limits["max_loss_percent"]
        ):
            if alert["attack_type"] == "dos":
                # Heuristic: When critical service QoS is degraded during a DoS incident,
                # the policy rate-limits the verified suspicious load flow to protect telemetry delivery.
                # In testbed evaluation, this mapping is controlled by construction.
                result = decision(
                    "rate_limit",
                    "Recover degraded critical QoS by limiting the separate flooding flow",
                    flow,
                )
                result["qos_state"] = "degraded"
                result["reassessment_required"] = True
                return result
            return decision(
                "review",
                "Critical QoS is degraded; attack-specific recovery is required",
            )

    attack = alert["attack_type"]
    severity = alert["severity"]
    confirmed = context.get("malicious_confirmed") is True

    if attack == "dos":
        if criticality == "noncritical" and severity == "high":
            return decision("block", "High-severity noncritical DoS flow", flow)
        return decision("rate_limit", "Limit the identified flooding flow", flow)

    if attack == "reconnaissance":
        if severity == "high" and confirmed:
            return decision("block", "Confirmed severe reconnaissance", flow)
        return decision("rate_limit", "Restrict the identified probing flow", flow)

    if attack == "mitm":
        if not confirmed:
            return decision("review", "MITM confirmation is unavailable")
        return decision("block", "Block the confirmed malicious flow", flow)

    return decision("review", "Unsupported attack type")
