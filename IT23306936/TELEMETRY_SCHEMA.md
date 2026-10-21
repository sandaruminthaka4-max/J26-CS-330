# IoMT Adaptive SDN Mitigation — Telemetry Contract & Schema (v2.0)
**Project J26-CS-330 — Student IT23306936 (H.M.S.H. Wijerathna)**  
*Component: Safety-Constrained Adaptive SDN Mitigation and Monitoring for IoMT Networks*

---

## 1. Overview & Provenance

This document specifies the authoritative, versioned Telemetry Contract (v2.0) governing communication across:
1. **Experiment Producers:** `comparison_runner.py`, `controlled_lifecycle_test.py`, `periodic_delay_live_check.py`.
2. **Streaming Event Pipeline:** Append-only JSONL event stream (`logs/live_telemetry_stream.jsonl`).
3. **Dashboard Server:** Unprivileged Flask REST API and Server-Sent Events (SSE) `/api/stream`.
4. **Historical & Replay Parsers:** Benchmark runs and sequential replay reader.
5. **Web Frontend:** Telemetry state renderer, 2D/3D topology, and canvas time-series charts.

### Invariant Rules
- **No Zero Substitution:** Missing, invalid, stale, or non-finite measurements (NaN / Inf) must **NEVER** be converted to healthy `0` values. They must remain `null` in JSON and render as breaks/gaps on charts.
- **Fail-Closed QoS:** A QoS `PASS` is **strictly prohibited** if the observation is stale, incomplete, or invalid.
- **Timestamp Integrity:** Original timestamps and observation durations are preserved during replay.
- **Latency Accounting:** Delay is explicitly labeled as **ICMP Round-Trip Time (RTT)** under a half-open reply-arrival model. It is **never** presented as UDP one-way sensor latency.
- **Probe Accounting:** ICMP sent count and packet loss percent remain `null` unless verified per-probe send timestamps exist.
- **Unconfigured Thresholds:** Delay thresholds remain unconfigured per approved proposal requirements.

---

## 2. Complete JSON Schema Specification (v2.0)

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "IoMTTelemetryEnvelope",
  "type": "object",
  "required": [
    "schema_version",
    "mode",
    "provenance",
    "run_id",
    "scenario",
    "event_id",
    "timestamps",
    "freshness",
    "metrics",
    "validity",
    "qos",
    "mitigation",
    "lifecycle",
    "diagnostics"
  ],
  "properties": {
    "schema_version": { "type": "string", "enum": ["2.0"] },
    "mode": { "type": "string", "enum": ["LIVE", "REPLAY", "DEMO"] },
    "provenance": {
      "type": "string",
      "enum": ["live_kernel_telemetry", "recorded_benchmark", "synthetic_simulation"]
    },
    "run_id": { "type": "string" },
    "scenario": {
      "type": "string",
      "enum": ["baseline", "static_block", "adaptive", "smoke_1_repeat"]
    },
    "event_id": { "type": "string" },
    "window_index": { "type": ["integer", "null"], "minimum": 1, "maximum": 8 },
    "max_windows": { "type": "integer", "default": 6 },
    "timestamps": {
      "type": "object",
      "properties": {
        "basis": { "type": "string", "enum": ["unix_utc", "mono_relative"] },
        "window_start": { "type": ["number", "null"] },
        "window_end": { "type": ["number", "null"] },
        "duration_seconds": { "type": ["number", "null"] },
        "published_at": { "type": "string", "format": "date-time" }
      }
    },
    "freshness": {
      "type": "object",
      "properties": {
        "status": { "type": "string", "enum": ["fresh", "stale", "unavailable", "waiting", "recorded"] },
        "age_seconds": { "type": ["number", "null"] },
        "last_received_at": { "type": ["string", "null"] }
      }
    },
    "metrics": {
      "type": "object",
      "properties": {
        "sensor_throughput_kbps": { "type": ["number", "null"] },
        "sensor_packet_loss_percent": { "type": ["number", "null"], "minimum": 0.0, "maximum": 100.0 },
        "sensor_packets_received": { "type": ["integer", "null"] },
        "sensor_packets_lost": { "type": ["integer", "null"] },
        "icmp_rtt_avg_ms": { "type": ["number", "null"] },
        "icmp_rtt_min_ms": { "type": ["number", "null"] },
        "icmp_rtt_max_ms": { "type": ["number", "null"] },
        "icmp_rtt_model": { "type": "string", "enum": ["reply_arrival_half_open"] },
        "icmp_sent_packets": { "type": "null" },
        "icmp_packet_loss_percent": { "type": "null" }
      }
    },
    "validity": {
      "type": "object",
      "properties": {
        "measurement_valid": { "type": "boolean" },
        "invalidation_reasons": { "type": "array", "items": { "type": "string" } },
        "rtt_valid": { "type": "boolean" },
        "rtt_invalidation_reasons": { "type": "array", "items": { "type": "string" } },
        "is_transition_window": { "type": "boolean" },
        "transition_type": { "type": ["string", "null"], "enum": ["initial_enforcement_transition", "rate_adjustment_transition", null] },
        "eligible_for_evaluation": { "type": "boolean" }
      }
    },
    "qos": {
      "type": "object",
      "properties": {
        "status": { "type": "string", "enum": ["PASS", "FAIL", "NOT_EVALUATED", "UNAVAILABLE"] },
        "passed": { "type": ["boolean", "null"] },
        "throughput_threshold_kbps": { "type": "number", "default": 90.0 },
        "loss_threshold_percent": { "type": "number", "default": 1.0 },
        "delay_threshold_ms": { "type": "null" }
      }
    },
    "security_alert": {
      "type": ["object", "null"],
      "properties": {
        "alert_id": { "type": "string" },
        "attack_type": { "type": "string", "enum": ["DoS_Flooding", "Reconnaissance", "MITM", "Unknown"] },
        "source_ip": { "type": "string" },
        "target_ip": { "type": "string" },
        "target_port": { "type": ["integer", "null"] },
        "severity": { "type": "string", "enum": ["low", "medium", "high", "critical"] },
        "affected_service": { "type": "string" },
        "criticality": { "type": "string", "enum": ["critical", "noncritical"] },
        "alert_source": { "type": "string" },
        "reasoning": { "type": ["string", "null"] },
        "timestamp": { "type": "string" }
      }
    },
    "mitigation": {
      "type": "object",
      "properties": {
        "recommended_action": { "type": "string", "enum": ["rate_limit", "block", "none"] },
        "executed_action": { "type": "string", "enum": ["rate_limit", "block", "none"] },
        "rate_limit_kbps": { "type": ["integer", "null"] },
        "rule_cookie": { "type": ["string", "null"] },
        "meter_id": { "type": ["integer", "null"] },
        "enforcement_engine": { "type": "string" },
        "enforcement_latency_ms": { "type": ["number", "null"] },
        "enforcement_status": { "type": "string", "enum": ["active", "cleared", "failed", "none"] }
      }
    },
    "lifecycle": {
      "type": "object",
      "properties": {
        "stage": {
          "type": "string",
          "enum": [
            "normal_monitoring",
            "initial_enforcement",
            "transition_hold",
            "evaluating_reassessment",
            "adjusted_transition",
            "post_adjustment_stable_1",
            "post_threat_stable_1",
            "post_threat_stable_2",
            "rule_lifecycle_cleaned",
            "waiting_for_telemetry"
          ]
        },
        "post_threat_stable_windows_observed": { "type": "integer", "minimum": 0, "maximum": 2 },
        "cleanup_verified": { "type": "boolean" },
        "cleanup_details": { "type": ["object", "null"] }
      }
    },
    "diagnostics": {
      "type": "object",
      "properties": {
        "execution_error": { "type": ["string", "null"] },
        "receiver_errors": { "type": "array", "items": { "type": "string" } },
        "process_status": { "type": "object" }
      }
    }
  }
}
```

---

## 3. Top-Level Field Aliases for Direct Frontend Compatibility

To ensure seamless integration with lightweight frontend clients while preserving strict schema normalization, the following top-level aliases are serialized alongside structured nested objects:

| Top-Level Alias | Mapped Source | Null / Unavailable Semantics |
|:---|:---|:---|
| `sensor_throughput_kbps` | `metrics.sensor_throughput_kbps` | `null` when window incomplete or stale |
| `sensor_packet_loss_percent` | `metrics.sensor_packet_loss_percent` | `null` when window incomplete or stale |
| `icmp_rtt_avg_ms` | `metrics.icmp_rtt_avg_ms` | `null` when reader error or no replies |
| `icmp_reply_rtt_avg_ms` | `metrics.icmp_rtt_avg_ms` | Identical alias to eliminate frontend field mismatch |
| `qos_satisfied` | `qos.passed` | `null` when invalid or stale; never `True` |
| `data_freshness` | `freshness.status` | `"fresh"`, `"stale"`, `"unavailable"`, `"waiting"` |
| `mitigation_action` | `mitigation.executed_action` | `"none"`, `"rate_limit"`, `"block"` |
| `rate_limit_kbps` | `mitigation.rate_limit_kbps` | `null` when not rate-limited |
| `rule_cookie` | `mitigation.rule_cookie` | Hex string (e.g. `"0x4a2e1"`) or `null` |
| `lifecycle_stage` | `lifecycle.stage` | Current state machine stage string |
| `latest_alert` | `security_alert` (as dict) | `null` if no active incident |
