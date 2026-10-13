#!/usr/bin/env python3
"""Three-Host Mininet Network Topology & Experiment Profiles.

Codifies the 3-host Mininet topology and matched experiment profiles:
- h1: Legitimate medical sensor node (10.0.0.1)
- h2: Hospital Edge Server / Gateway (10.0.0.2)
- h3: Dedicated adversary / attacker host (10.0.0.3)
- s1: Open vSwitch OpenFlow 1.3 bridge with 2 Mbit/s bottleneck link to h2.

Scope & Architecture Distinction:
- This is a new, dedicated three-host topology profile (h1 sensor, h2 edge receiver,
  h3 attacker, s1 switch).
- It explicitly differs from the earlier two-host pilot topology (h1 sensor+load, h2 receiver)
  by establishing a separate adversarial network namespace and physical/virtual link for h3,
  aligning with the proposal's multi-host threat model.
- Prescribes experimental network and traffic configurations; does NOT prescribe experimental
  outcomes (e.g. expected loss percentages are empirical observations, not assertions).
"""

from dataclasses import dataclass
from typing import Dict, Any, Optional


@dataclass(frozen=True)
class LinkProfile:
    bw_mbps: float
    delay_ms: float
    max_queue_size: int = 20
    use_htb: bool = True


@dataclass(frozen=True)
class HostConfig:
    name: str
    ip: str
    role: str


TOPOLOGY_CONFIG = {
    "hosts": [
        HostConfig(name="h1", ip="10.0.0.1/8", role="Medical Sensor Client (ECG Telemetry)"),
        HostConfig(name="h2", ip="10.0.0.2/8", role="Hospital Edge Server & Ingestion Gateway"),
        HostConfig(name="h3", ip="10.0.0.3/8", role="Adversary / Attacker Host (DoS Flooding)"),
    ],
    "switch": {"name": "s1", "protocols": "OpenFlow13"},
    "links": {
        "h1-s1": LinkProfile(bw_mbps=10.0, delay_ms=1.0, max_queue_size=100, use_htb=True),
        "h3-s1": LinkProfile(bw_mbps=10.0, delay_ms=1.0, max_queue_size=100, use_htb=True),
        "s1-h2": LinkProfile(bw_mbps=2.0, delay_ms=1.0, max_queue_size=20, use_htb=True),
    },
}


EXPERIMENT_PROFILES = {
    "profile_baseline": {
        "name": "Unmitigated Baseline",
        "description": "5 Mbit/s DoS attack from h3 competes with 100 Kbit/s sensor from h1 on 2 Mbit/s bottleneck. No OpenFlow rules applied.",
        "attacker_host": "h3",
        "sensor_host": "h1",
        "target_host": "h2",
        "sensor_port": 5202,
        "sensor_rate_kbps": 100,
        "attack_port": 5201,
        "attack_rate_kbps": 5000,
    },
    "profile_static_block": {
        "name": "Static OpenFlow Blocking",
        "description": "DoS alert triggers immediate hard OpenFlow drop rule (actions=drop) on attacker flow from h3 to h2 port 5201.",
        "attacker_host": "h3",
        "sensor_host": "h1",
        "target_host": "h2",
        "sensor_port": 5202,
        "sensor_rate_kbps": 100,
        "attack_port": 5201,
        "attack_rate_kbps": 5000,
        "enforcement_action": "block",
    },
    "profile_adaptive_rate_limit": {
        "name": "Safety-Constrained Adaptive Rate Limiting",
        "description": "DoS alert triggers scoped OVS meter rate limiting (1000 Kbit/s initial, at most one dynamic 500 Kbit/s adjustment if degraded).",
        "attacker_host": "h3",
        "sensor_host": "h1",
        "target_host": "h2",
        "sensor_port": 5202,
        "sensor_rate_kbps": 100,
        "attack_port": 5201,
        "attack_rate_kbps": 5000,
        "enforcement_action": "rate_limit",
        "initial_limit_kbps": 1000,
        "adjusted_limit_kbps": 500,
    },
}


def build_mininet_topology(net, config: Optional[Dict[str, Any]] = None):
    """Configures Mininet instance consuming TOPOLOGY_CONFIG consistently.

    Sets up:
    - Hosts defined in config["hosts"] with designated IPs
    - Switch s1 configured with OpenFlow13 protocols
    - Links with bandwidth, delay, max_queue_size, and use_htb from config["links"]
    """
    cfg = config or TOPOLOGY_CONFIG

    # 1. Add hosts
    hosts = {}
    for h_cfg in cfg["hosts"]:
        hosts[h_cfg.name] = net.addHost(h_cfg.name, ip=h_cfg.ip)

    # 2. Add switch with OpenFlow13 protocol
    sw_cfg = cfg["switch"]
    s1 = net.addSwitch(sw_cfg["name"], protocols=sw_cfg["protocols"])

    # 3. Add links according to link profiles
    links = cfg["links"]

    # h1 -> s1 access link
    l_h1 = links["h1-s1"]
    net.addLink(
        hosts["h1"], s1,
        bw=l_h1.bw_mbps,
        delay=f"{l_h1.delay_ms}ms",
        max_queue_size=l_h1.max_queue_size,
        use_htb=l_h1.use_htb,
    )

    # h3 -> s1 access link
    l_h3 = links["h3-s1"]
    net.addLink(
        hosts["h3"], s1,
        bw=l_h3.bw_mbps,
        delay=f"{l_h3.delay_ms}ms",
        max_queue_size=l_h3.max_queue_size,
        use_htb=l_h3.use_htb,
    )

    # s1 -> h2 bottleneck link
    l_h2 = links["s1-h2"]
    net.addLink(
        hosts["h2"], s1,
        bw=l_h2.bw_mbps,
        delay=f"{l_h2.delay_ms}ms",
        max_queue_size=l_h2.max_queue_size,
        use_htb=l_h2.use_htb,
    )

    return {"h1": hosts["h1"], "h2": hosts["h2"], "h3": hosts["h3"], "s1": s1}
