#!/usr/bin/env python3
"""Controller and Detector Integration Interfaces.

Defines standardized interfaces and contracts between the individual IoMT mitigation
component (IT23306936) and external components:
1. External Anomaly Detectors (REST Alert Ingestion Contract, Proposal Table 1 & 3).
2. SDN Controllers (Abstract EnforcementAdapter, concrete Direct-OVS engine, and open Ryu adapter).
"""

from abc import ABC, abstractmethod
from copy import deepcopy
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import urllib.request
import urllib.error

from alert_validation_v2 import validate_alert

logger = logging.getLogger("iomt.interfaces")


# ==============================================================================
# 1. Detector Integration Interface (Proposal Section 3.4, Table 1 & 3)
# ==============================================================================

class DetectorAlertInterface:
    """Standardized validation and ingestion contract for external detector alerts.
    
    Accepts alerts from:
    - IT23326354 (Lightweight DoS/Flooding Detection)
    - IT23285224 (Reconnaissance Attack Detection)
    - IT23368248 (Protocol Anomaly Detection for MITM)
    
    Reuses the existing validated alert contract from alert_validation_v2.py
    to prevent divergent validation logic.
    """

    def __init__(self, services: Optional[Dict[str, Any]] = None, auth_token: Optional[str] = None):
        self.auth_token = auth_token or os.environ.get("IOMT_ALERT_AUTH_TOKEN")
        if services is not None:
            self.services = services
        else:
            services_file = Path(__file__).resolve().parent / "configs/services_v2.json"
            if services_file.exists():
                try:
                    self.services = json.loads(services_file.read_text(encoding="utf-8"))
                except Exception:
                    self.services = {}
            else:
                self.services = {}

    def verify_auth_header(self, auth_header: Optional[str]) -> Tuple[bool, Optional[str]]:
        """Verifies optional Bearer token authentication."""
        if not self.auth_token:
            return True, None  # Open if no token configured (e.g. localhost testbed)
        if not auth_header:
            return False, "Missing Authorization header"
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return False, "Invalid Authorization header format (expected Bearer <token>)"
        if parts[1] != self.auth_token:
            return False, "Invalid authentication token"
        return True, None

    def validate_schema(self, payload: Any) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """Strictly validates alert payload using the authoritative alert_validation_v2 contract.
        
        Required fields (Proposal Table 1 & 3):
        - alert_id: non-empty string
        - attack_type: 'dos', 'dos_flooding', 'reconnaissance', 'mitm'
        - source_ip: valid IPv4 string
        - target_ip: valid IPv4 matching registered service
        - severity: 'low', 'medium', 'high'
        - affected_service: registered service name in services_v2.json
        - timestamp: ISO 8601 string with timezone
        """
        if not isinstance(payload, dict):
            return False, "Alert payload must be a JSON object", None

        # Check attack type first with clear error
        attack_type = str(payload.get("attack_type", "")).lower()
        if attack_type not in ("dos", "dos_flooding", "reconnaissance", "mitm"):
            return False, f"Invalid attack_type '{payload.get('attack_type')}' (allowed: DoS_Flooding, Reconnaissance, MITM)", None

        # Default detector_id if omitted by external alert
        augmented = dict(payload)
        if "detector_id" not in augmented:
            augmented["detector_id"] = "external_anomaly_detector"

        try:
            validated_alert, service_config = validate_alert(augmented, self.services)
            validated_alert["service_criticality"] = service_config.get("criticality")
            return True, None, validated_alert
        except ValueError as ex:
            return False, str(ex), None


# ==============================================================================
# 2. SDN Controller Interface & Adapters (Proposal Section 4.2 & 4.3)
# ==============================================================================

class EnforcementAdapter(ABC):
    """Abstract interface for OpenFlow mitigation enforcement.
    
    Decouples policy decision logic from the specific controller implementation.
    """

    @abstractmethod
    def get_controller_type(self) -> str:
        """Returns the controller/engine identifier."""
        pass

    @abstractmethod
    def is_available(self) -> Tuple[bool, str]:
        """Checks if the controller/adapter is ready to enforce rules."""
        pass

    @abstractmethod
    def apply(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        """Applies rate-limiting, blocking, or rerouting rule."""
        pass

    @abstractmethod
    def cleanup(self) -> Dict[str, Any]:
        """Removes owned mitigation rules and meters."""
        pass

    @abstractmethod
    def query_status(self) -> Dict[str, Any]:
        """Queries active flows and meter statistics."""
        pass


class OVSEnforcementAdapter(EnforcementAdapter):
    """Concrete Direct-OVS OpenFlow 1.3 adapter (Interim Testbed Engine).
    
    Executes directly against Open vSwitch on the local testbed via ovs-ofctl.
    """

    def __init__(self, enforcer=None, services: Optional[Dict[str, Any]] = None, bridge: str = "s1"):
        from ovs_enforcement_v2 import OVSEnforcer
        self.bridge = bridge
        if enforcer is not None:
            self.enforcer = enforcer
        else:
            if services is None:
                services_file = Path(__file__).resolve().parent / "configs/services_v2.json"
                if services_file.exists():
                    try:
                        services = json.loads(services_file.read_text(encoding="utf-8"))
                    except Exception:
                        services = {}
                else:
                    services = {}
            self.enforcer = OVSEnforcer(services)

    def get_controller_type(self) -> str:
        return "direct_ovs_of13"

    def is_available(self) -> Tuple[bool, str]:
        try:
            res = self.enforcer.run(["show", self.bridge])
            if res.returncode == 0:
                return True, f"OVS bridge '{self.bridge}' available"
            return False, f"OVS show returned {res.returncode}: {res.stderr}"
        except Exception as ex:
            return False, f"OVS unavailable (testbed offline or Windows host): {ex}"

    def apply(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        return self.enforcer.apply(plan)

    def cleanup(self) -> Dict[str, Any]:
        self.enforcer.cleanup()
        return {"status": "cleaned", "bridge": self.bridge}

    def query_status(self) -> Dict[str, Any]:
        try:
            flows = self.enforcer.run(["dump-flows", self.bridge]).stdout
            meters = self.enforcer.run(["meter-stats", self.bridge]).stdout
            return {
                "bridge": self.bridge,
                "cookie": f"0x{self.enforcer.cookie:x}",
                "meter_id": self.enforcer.meter_id,
                "flow_dump": flows,
                "meter_stats": meters,
            }
        except Exception as ex:
            return {"error": str(ex)}


class RyuEnforcementAdapter(EnforcementAdapter):
    """Ryu OpenFlow Controller REST API Adapter.
    
    Retained as an OPEN proposal requirement (Proposal Section 4.2).
    Connects to Ryu's `ofctl_rest` application when deployed in an isolated environment.
    
    Invariants Enforced:
    1. Explicit scope is required; missing source/target/protocol/port values are NEVER defaulted.
    2. Critical service protections are strictly enforced.
    3. Protocol-specific matching ensures valid OpenFlow matches (UDP vs TCP).
    4. Cleanup errors are NEVER suppressed or reported as success.
    5. Ryu status is honestly marked as pending supervisor alignment unless active.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8080",
        dpid: int = 1,
        cookie: int = 0x4a2e1,
        meter_id: int = 100,
        timeout_seconds: float = 2.0,
        services: Optional[Dict[str, Any]] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.dpid = dpid
        self.cookie = cookie
        self.meter_id = meter_id
        self.timeout = timeout_seconds
        if services is not None:
            self.services = services
        else:
            services_file = Path(__file__).resolve().parent / "configs/services_v2.json"
            if services_file.exists():
                try:
                    self.services = json.loads(services_file.read_text(encoding="utf-8"))
                except Exception:
                    self.services = {}
            else:
                self.services = {}

    def get_controller_type(self) -> str:
        return "ryu_rest_controller"

    def is_available(self) -> Tuple[bool, str]:
        """Probes Ryu REST API endpoint. Kept explicitly disabled/pending by default."""
        url = f"{self.base_url}/stats/switches"
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode())
                    if self.dpid in data:
                        return True, f"Ryu controller online, DPID {self.dpid} connected"
                    return False, f"Ryu controller online, but DPID {self.dpid} not connected: {data}"
                return False, f"Ryu HTTP probe returned status {resp.status}"
        except Exception as ex:
            return False, f"Ryu controller unavailable (Open Proposal Requirement): {ex}"

    def apply(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        """Translates high-level mitigation plan to Ryu REST flow/meter JSON.
        
        Requires explicit scope fields without default substitution.
        """
        action = plan.get("action")
        scope = plan.get("scope")
        if not isinstance(scope, dict):
            raise ValueError("Mitigation plan requires an explicit 'scope' dictionary")

        # Invariant: Require explicit flow scope. NEVER default missing values.
        source_ip = scope.get("source_ip")
        dst_port = scope.get("dst_port")
        proto = str(scope.get("protocol", "")).lower()

        if not source_ip or not isinstance(source_ip, str):
            raise ValueError("Explicit 'source_ip' required in scope; defaulting is prohibited")
        if dst_port is None or not isinstance(dst_port, int) or not (1 <= dst_port <= 65535):
            raise ValueError("Explicit valid 'dst_port' (1-65535) required in scope; defaulting is prohibited")
        if proto not in ("udp", "tcp"):
            raise ValueError(f"Explicit protocol ('udp' or 'tcp') required in scope, got: '{proto}'")

        # Invariant: Enforce critical-service protections
        target_ip = scope.get("target_ip")
        for s_name, s_cfg in self.services.items():
            if s_cfg.get("criticality") == "critical":
                crit_ip = s_cfg.get("target_ip")
                crit_port = s_cfg.get("target_port")
                if target_ip and crit_ip and target_ip == crit_ip and dst_port == crit_port:
                    raise ValueError(f"Action rejected: destination {target_ip}:{dst_port} matches protected critical service '{s_name}'")

        hard_timeout = plan.get("duration_seconds", 300)
        results = {"controller": "ryu_rest", "actions_applied": []}

        # Protocol-specific match dict
        match_dict: Dict[str, Any] = {
            "eth_type": 0x0800,  # IPv4
            "ipv4_src": source_ip,
        }
        if target_ip:
            match_dict["ipv4_dst"] = target_ip

        if proto == "udp":
            match_dict["ip_proto"] = 17
            match_dict["udp_dst"] = dst_port
        elif proto == "tcp":
            match_dict["ip_proto"] = 6
            match_dict["tcp_dst"] = dst_port

        if action == "rate_limit":
            rate_kbps = plan.get("rate_limit_kbps", 1000)
            meter_payload = {
                "dpid": self.dpid,
                "meter_id": self.meter_id,
                "flags": ["KBPS", "STATS"],
                "bands": [
                    {
                        "type": "DROP",
                        "rate": rate_kbps,
                        "burst_size": max(10, int(rate_kbps * 0.1)),
                    }
                ],
            }
            self._post("/stats/meterentry/add", meter_payload)
            results["actions_applied"].append(f"meter_{self.meter_id}_rate_{rate_kbps}kbps")

            flow_payload = {
                "dpid": self.dpid,
                "cookie": self.cookie,
                "cookie_mask": 0xFFFFFFFFFFFFFFFF,
                "table_id": 0,
                "priority": 200,
                "hard_timeout": hard_timeout,
                "match": match_dict,
                "instructions": [
                    {"type": "METER", "meter_id": self.meter_id},
                    {"type": "APPLY_ACTIONS", "actions": [{"type": "OUTPUT", "port": "NORMAL"}]},
                ],
            }
            self._post("/stats/flowentry/add", flow_payload)
            results["actions_applied"].append("flow_meter_instruction")

        elif action == "block":
            flow_payload = {
                "dpid": self.dpid,
                "cookie": self.cookie,
                "cookie_mask": 0xFFFFFFFFFFFFFFFF,
                "table_id": 0,
                "priority": 300,
                "hard_timeout": hard_timeout,
                "match": match_dict,
                "instructions": [],  # Empty actions = DROP
            }
            self._post("/stats/flowentry/add", flow_payload)
            results["actions_applied"].append("flow_drop_instruction")
        else:
            raise ValueError(f"Unsupported action '{action}' for Ryu adapter")

        return results

    def cleanup(self) -> Dict[str, Any]:
        """Deletes owned flows and meters by cookie and meter_id.
        
        Invariant: Never reports cleanup success after suppressing errors.
        """
        errors = []
        flow_del = {
            "dpid": self.dpid,
            "cookie": self.cookie,
            "cookie_mask": 0xFFFFFFFFFFFFFFFF,
        }
        try:
            self._post("/stats/flowentry/delete", flow_del)
        except Exception as ex:
            errors.append(f"Failed to delete flows: {ex}")

        meter_del = {
            "dpid": self.dpid,
            "meter_id": self.meter_id,
        }
        try:
            self._post("/stats/meterentry/delete", meter_del)
        except Exception as ex:
            errors.append(f"Failed to delete meter: {ex}")

        if errors:
            return {
                "status": "cleanup_failed",
                "errors": errors,
                "cookie": f"0x{self.cookie:x}",
                "meter_id": self.meter_id,
            }

        return {"status": "ryu_rules_deleted", "cookie": f"0x{self.cookie:x}", "meter_id": self.meter_id}

    def query_status(self) -> Dict[str, Any]:
        """Queries flow and meter stats from Ryu."""
        try:
            flows = self._get(f"/stats/flow/{self.dpid}")
            meters = self._get(f"/stats/meter/{self.dpid}")
            return {"dpid": self.dpid, "flows": flows, "meters": meters}
        except Exception as ex:
            return {"dpid": self.dpid, "error": str(ex)}

    def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw.strip() else {}

    def _get(self, path: str) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw.strip() else {}
