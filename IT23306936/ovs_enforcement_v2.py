import ipaddress
import secrets
import subprocess
import time


def build_plan(recommendation, services, meter_id, cookie):
    action = recommendation.get("action")
    if action not in {"rate_limit", "block"}:
        raise ValueError("Only rate_limit or block can be enforced")

    scope = recommendation["scope"]
    source = str(ipaddress.IPv4Address(scope["source_ip"]))
    target = str(ipaddress.IPv4Address(scope["target_ip"]))
    protocol = scope["protocol"]
    port = scope["dst_port"]
    duration = recommendation["duration_seconds"]

    if protocol not in {"udp", "tcp"}:
        raise ValueError("Invalid protocol")
    for value, maximum in ((port, 65535), (duration, 3600)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("Port and duration must be integers")
        if not 1 <= value <= maximum:
            raise ValueError("Port or duration out of range")

    for service in services.values():
        if (
            service["criticality"] == "critical"
            and target == service["target_ip"]
            and protocol == service["protocol"]
            and port == service["port"]
        ):
            raise ValueError("Rule overlaps a protected critical service")

    match = (
        f"cookie=0x{cookie:x},priority=110,hard_timeout={duration},"
        f"{protocol},nw_src={source},nw_dst={target},tp_dst={port},"
    )
    commands = []
    if action == "rate_limit":
        rate = recommendation["rate_limit_kbps"]
        if (
            isinstance(rate, bool)
            or not isinstance(rate, int)
            or not 1 <= rate <= 100000
        ):
            raise ValueError("Invalid rate limit")
        commands.append([
            "add-meter", "s1",
            f"meter={meter_id},kbps,stats,bands=type=drop,rate={rate}",
        ])
        match += f"actions=meter:{meter_id},normal"
    else:
        match += "actions=drop"

    commands.append(["add-flow", "s1", match])
    return commands


class OVSEnforcer:
    def __init__(self, services):
        self.services = services
        self.meter_id = secrets.randbelow(1000000) + 10000
        self.cookie = secrets.randbits(64)
        self.meter_created = False
        self.flow_created = False

    def run(self, arguments):
        return subprocess.run(
            ["ovs-ofctl", "-O", "OpenFlow13", *arguments],
            check=True, capture_output=True, text=True, timeout=5,
        )

    def apply(self, recommendation):
        if self.flow_created or self.meter_created:
            raise RuntimeError("Clean up the previous action before applying")
        plan = build_plan(
            recommendation, self.services, self.meter_id, self.cookie
        )
        started = time.monotonic()
        try:
            for command in plan:
                self.run(command)
                if command[0] == "add-meter":
                    self.meter_created = True
                elif command[0] == "add-flow":
                    self.flow_created = True
        except Exception:
            self.cleanup()
            raise

        return {
            "status": "ovs_commands_completed",
            "action": recommendation["action"],
            "scope": recommendation["scope"],
            "cookie": f"0x{self.cookie:x}",
            "meter_id": self.meter_id if self.meter_created else None,
            "command_completion_ms": round(
                (time.monotonic() - started) * 1000, 3
            ),
            "duration_seconds": recommendation["duration_seconds"],
        }

    def cleanup(self):
        if self.flow_created:
            self.run(["del-flows", "s1", f"cookie=0x{self.cookie:x}/-1"])
            self.flow_created = False
        if self.meter_created:
            self.run(["del-meters", "s1", f"meter={self.meter_id}"])
            self.meter_created = False
