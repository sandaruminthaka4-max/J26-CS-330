#!/usr/bin/env python3
"""IoMT Telemetry Contract & Schema Definition (Version 2.0).

Shared contract between:
- Experiment Runners (Producer)
- Telemetry Event Streamer / Logs
- Dashboard API Server
- Replay Reader
- Web Frontend

Invariants:
1. Missing, invalid, stale, or non-finite measurements must NEVER become zero values.
2. A QoS PASS must never be issued from an invalid or stale observation.
3. Original timestamps are preserved in replay.
4. ICMP RTT is explicitly labeled as round-trip time, not UDP one-way delay.
5. ICMP sent count and loss remain null without verified per-probe send accounting.
6. Delay thresholds remain unconfigured unless supervisor-approved.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Optional, Tuple


SCHEMA_VERSION = "2.0"
QOS_THROUGHPUT_MIN_KBPS = 90.0
QOS_LOSS_MAX_PERCENT = 1.0


@dataclass
class TelemetryTimestamps:
    basis: str = "unix_utc"  # "unix_utc" or "mono_relative"
    window_start: Optional[float] = None
    window_end: Optional[float] = None
    duration_seconds: Optional[float] = None
    published_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class TelemetryFreshness:
    status: str = "waiting"  # "fresh", "stale", "unavailable", "waiting", "recorded"
    age_seconds: Optional[float] = None
    last_received_at: Optional[str] = None


@dataclass
class TrafficMetrics:
    sensor_throughput_kbps: Optional[float] = None
    sensor_packet_loss_percent: Optional[float] = None
    sensor_packets_received: Optional[int] = None
    sensor_packets_lost: Optional[int] = None
    icmp_rtt_avg_ms: Optional[float] = None  # Round-trip time
    icmp_rtt_min_ms: Optional[float] = None
    icmp_rtt_max_ms: Optional[float] = None
    icmp_rtt_model: str = "reply_arrival_half_open"
    icmp_sent_packets: Optional[int] = None  # null without verified send accounting
    icmp_packet_loss_percent: Optional[float] = None  # null without verified send accounting


@dataclass
class MeasurementValidity:
    measurement_valid: bool = False
    invalidation_reasons: List[str] = field(default_factory=list)
    rtt_valid: bool = False
    rtt_invalidation_reasons: List[str] = field(default_factory=list)
    is_transition_window: bool = False
    transition_type: Optional[str] = None
    eligible_for_evaluation: bool = False


@dataclass
class QoSOutcome:
    status: str = "UNAVAILABLE"  # "PASS", "FAIL", "NOT_EVALUATED", "UNAVAILABLE"
    passed: Optional[bool] = None  # None if invalid, stale, or unavailable
    throughput_threshold_kbps: float = QOS_THROUGHPUT_MIN_KBPS
    loss_threshold_percent: float = QOS_LOSS_MAX_PERCENT
    delay_threshold_ms: Optional[float] = None  # Explicitly unconfigured


@dataclass
class SecurityAlert:
    alert_id: str
    attack_type: str
    source_ip: str
    target_ip: str
    target_port: Optional[int] = None
    severity: str = "high"
    affected_service: str = "ECG_Monitoring"
    criticality: str = "critical"
    alert_source: str = "standardized_rest"  # "standardized_rest", "testbed_dummy", "synthetic_demo"
    reasoning: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class MitigationState:
    recommended_action: str = "none"  # "rate_limit", "block", "none"
    executed_action: str = "none"
    rate_limit_kbps: Optional[int] = None
    rule_cookie: Optional[str] = None
    meter_id: Optional[int] = None
    enforcement_engine: str = "direct_ovs_of13"  # "direct_ovs_of13", "ryu_pending", "synthetic_demo"
    enforcement_latency_ms: Optional[float] = None
    enforcement_status: str = "none"  # "active", "cleared", "failed", "none"


@dataclass
class LifecycleState:
    stage: str = "normal_monitoring"
    post_threat_stable_windows_observed: int = 0
    cleanup_verified: bool = False
    cleanup_details: Optional[Dict[str, Any]] = None


@dataclass
class DiagnosticState:
    execution_error: Optional[str] = None
    receiver_errors: List[str] = field(default_factory=list)
    process_status: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TelemetryEnvelope:
    schema_version: str = SCHEMA_VERSION
    mode: str = "DEMO"  # "LIVE", "REPLAY", "DEMO"
    provenance: str = "synthetic_simulation"  # "live_kernel_telemetry", "recorded_benchmark", "synthetic_simulation"
    run_id: str = "unassigned"
    scenario: str = "adaptive"  # "baseline", "static_block", "adaptive", "smoke_1_repeat"
    event_id: str = "evt_0"
    window_index: Optional[int] = None
    max_windows: int = 6
    timestamps: TelemetryTimestamps = field(default_factory=TelemetryTimestamps)
    freshness: TelemetryFreshness = field(default_factory=TelemetryFreshness)
    metrics: TrafficMetrics = field(default_factory=TrafficMetrics)
    validity: MeasurementValidity = field(default_factory=MeasurementValidity)
    qos: QoSOutcome = field(default_factory=QoSOutcome)
    security_alert: Optional[SecurityAlert] = None
    mitigation: MitigationState = field(default_factory=MitigationState)
    lifecycle: LifecycleState = field(default_factory=LifecycleState)
    diagnostics: DiagnosticState = field(default_factory=DiagnosticState)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes envelope to dictionary with legacy field aliases for frontend compatibility."""
        data = asdict(self)
        # Flattened top-level aliases for direct frontend and legacy consumers:
        data["sensor_throughput_kbps"] = self.metrics.sensor_throughput_kbps
        data["sensor_packet_loss_percent"] = self.metrics.sensor_packet_loss_percent
        data["icmp_rtt_avg_ms"] = self.metrics.icmp_rtt_avg_ms
        data["icmp_reply_rtt_avg_ms"] = self.metrics.icmp_rtt_avg_ms  # Both aliases identical
        data["icmp_rtt_model"] = self.metrics.icmp_rtt_model
        data["qos_satisfied"] = self.qos.passed
        data["data_freshness"] = self.freshness.status
        data["mitigation_action"] = self.mitigation.executed_action
        data["rate_limit_kbps"] = self.mitigation.rate_limit_kbps
        data["rule_cookie"] = self.mitigation.rule_cookie
        data["lifecycle_stage"] = self.lifecycle.stage
        data["latest_alert"] = asdict(self.security_alert) if self.security_alert else None
        return data


def create_waiting_envelope(mode: str = "LIVE", run_id: str = "none") -> TelemetryEnvelope:
    """Returns an envelope representing waiting/unavailable telemetry."""
    return TelemetryEnvelope(
        schema_version=SCHEMA_VERSION,
        mode=mode,
        provenance="live_kernel_telemetry" if mode == "LIVE" else "recorded_benchmark",
        run_id=run_id,
        scenario="adaptive",
        event_id=f"wait_{int(datetime.now(timezone.utc).timestamp())}",
        window_index=None,
        freshness=TelemetryFreshness(status="waiting"),
        metrics=TrafficMetrics(),  # All metrics explicitly None
        validity=MeasurementValidity(measurement_valid=False, invalidation_reasons=["waiting_for_telemetry"]),
        qos=QoSOutcome(status="UNAVAILABLE", passed=None),
        mitigation=MitigationState(executed_action="none"),
        lifecycle=LifecycleState(stage="waiting_for_telemetry"),
    )


def validate_telemetry_dict(data: Any) -> Tuple[bool, Optional[str], Optional[TelemetryEnvelope]]:
    """Validates and parses a telemetry envelope dictionary.
    
    Rejects unsupported schema versions and malformed types.
    """
    if not isinstance(data, dict):
        return False, "Telemetry data must be a JSON object", None

    schema_ver = data.get("schema_version", "1.0")
    if schema_ver not in ("2.0", "1.0"):
        return False, f"Unsupported schema_version '{schema_ver}'", None

    try:
        # If legacy flat dictionary, normalize into 2.0 structure
        if "metrics" not in data:
            tp = data.get("sensor_throughput_kbps")
            loss = data.get("sensor_packet_loss_percent")
            rtt = data.get("icmp_rtt_avg_ms")
            if rtt is None:
                rtt = data.get("icmp_reply_rtt_avg_ms")

            # Validate finite numbers
            tp = float(tp) if tp is not None and math.isfinite(float(tp)) else None
            loss = float(loss) if loss is not None and math.isfinite(float(loss)) else None
            rtt = float(rtt) if rtt is not None and math.isfinite(float(rtt)) else None

            is_valid = (tp is not None and loss is not None)
            qos_passed = None
            if is_valid and data.get("data_freshness") == "fresh":
                qos_passed = bool(tp >= QOS_THROUGHPUT_MIN_KBPS and loss <= QOS_LOSS_MAX_PERCENT)

            alert_obj = None
            if data.get("latest_alert"):
                a = data["latest_alert"]
                alert_obj = SecurityAlert(
                    alert_id=str(a.get("alert_id", "ALT-0")),
                    attack_type=str(a.get("attack_type", "Unknown")),
                    source_ip=str(a.get("source_ip", "0.0.0.0")),
                    target_ip=str(a.get("target_ip", "0.0.0.0")),
                    severity=str(a.get("severity", "high")),
                    affected_service=str(a.get("affected_service", "ECG_Monitoring")),
                    reasoning=a.get("reasoning"),
                )

            env = TelemetryEnvelope(
                schema_version=SCHEMA_VERSION,
                mode=str(data.get("mode", "DEMO")),
                provenance=str(data.get("provenance", "synthetic_simulation")),
                run_id=str(data.get("run_id", "demo")),
                scenario=str(data.get("scenario", "adaptive")),
                event_id=str(data.get("event_id", "evt_legacy")),
                window_index=data.get("window_index"),
                freshness=TelemetryFreshness(status=str(data.get("data_freshness", "waiting"))),
                metrics=TrafficMetrics(
                    sensor_throughput_kbps=tp,
                    sensor_packet_loss_percent=loss,
                    icmp_rtt_avg_ms=rtt,
                ),
                validity=MeasurementValidity(measurement_valid=is_valid),
                qos=QoSOutcome(
                    status="PASS" if qos_passed is True else ("FAIL" if qos_passed is False else "UNAVAILABLE"),
                    passed=qos_passed,
                ),
                security_alert=alert_obj,
                mitigation=MitigationState(
                    executed_action=str(data.get("mitigation_action", "none")),
                    rate_limit_kbps=data.get("rate_limit_kbps"),
                    rule_cookie=data.get("rule_cookie"),
                ),
                lifecycle=LifecycleState(stage=str(data.get("lifecycle_stage", "normal_monitoring"))),
            )
            return True, None, env

        # Fully structured v2.0 envelope
        m_dict = data.get("metrics", {})
        tp = m_dict.get("sensor_throughput_kbps")
        loss = m_dict.get("sensor_packet_loss_percent")
        rtt = m_dict.get("icmp_rtt_avg_ms")
        if rtt is None:
            rtt = m_dict.get("icmp_reply_rtt_avg_ms")

        tp = float(tp) if tp is not None and math.isfinite(float(tp)) else None
        loss = float(loss) if loss is not None and math.isfinite(float(loss)) else None
        rtt = float(rtt) if rtt is not None and math.isfinite(float(rtt)) else None

        freshness_status = data.get("freshness", {}).get("status", "waiting")
        meas_valid = bool(data.get("validity", {}).get("measurement_valid", False)) and (tp is not None and loss is not None)

        qos_passed = None
        if meas_valid and freshness_status == "fresh":
            qos_passed = bool(tp >= QOS_THROUGHPUT_MIN_KBPS and loss <= QOS_LOSS_MAX_PERCENT)

        alert_obj = None
        if data.get("security_alert"):
            a = data["security_alert"]
            alert_obj = SecurityAlert(
                alert_id=str(a.get("alert_id", "ALT-0")),
                attack_type=str(a.get("attack_type", "Unknown")),
                source_ip=str(a.get("source_ip", "0.0.0.0")),
                target_ip=str(a.get("target_ip", "0.0.0.0")),
                severity=str(a.get("severity", "high")),
                affected_service=str(a.get("affected_service", "ECG_Monitoring")),
                reasoning=a.get("reasoning"),
            )

        mit_dict = data.get("mitigation", {})
        env = TelemetryEnvelope(
            schema_version=SCHEMA_VERSION,
            mode=str(data.get("mode", "DEMO")),
            provenance=str(data.get("provenance", "synthetic_simulation")),
            run_id=str(data.get("run_id", "unknown")),
            scenario=str(data.get("scenario", "adaptive")),
            event_id=str(data.get("event_id", "evt_v2")),
            window_index=data.get("window_index"),
            freshness=TelemetryFreshness(
                status=freshness_status,
                age_seconds=data.get("freshness", {}).get("age_seconds"),
            ),
            metrics=TrafficMetrics(
                sensor_throughput_kbps=tp,
                sensor_packet_loss_percent=loss,
                icmp_rtt_avg_ms=rtt,
                icmp_sent_packets=None,
                icmp_packet_loss_percent=None,
            ),
            validity=MeasurementValidity(
                measurement_valid=meas_valid,
                invalidation_reasons=data.get("validity", {}).get("invalidation_reasons", []),
                is_transition_window=bool(data.get("validity", {}).get("is_transition_window", False)),
                transition_type=data.get("validity", {}).get("transition_type"),
            ),
            qos=QoSOutcome(
                status="PASS" if qos_passed is True else ("FAIL" if qos_passed is False else "UNAVAILABLE"),
                passed=qos_passed,
            ),
            security_alert=alert_obj,
            mitigation=MitigationState(
                recommended_action=str(mit_dict.get("recommended_action", "none")),
                executed_action=str(mit_dict.get("executed_action", "none")),
                rate_limit_kbps=mit_dict.get("rate_limit_kbps"),
                rule_cookie=mit_dict.get("rule_cookie"),
                meter_id=mit_dict.get("meter_id"),
                enforcement_engine=str(mit_dict.get("enforcement_engine", "direct_ovs_of13")),
                enforcement_latency_ms=mit_dict.get("enforcement_latency_ms"),
            ),
            lifecycle=LifecycleState(
                stage=str(data.get("lifecycle", {}).get("stage", "normal_monitoring")),
                post_threat_stable_windows_observed=int(data.get("lifecycle", {}).get("post_threat_stable_windows_observed", 0)),
                cleanup_verified=bool(data.get("lifecycle", {}).get("cleanup_verified", False)),
            ),
            diagnostics=DiagnosticState(
                execution_error=data.get("diagnostics", {}).get("execution_error"),
                receiver_errors=data.get("diagnostics", {}).get("receiver_errors", []),
            ),
        )
        return True, None, env
    except Exception as ex:
        return False, f"Failed to parse telemetry envelope: {ex}", None
