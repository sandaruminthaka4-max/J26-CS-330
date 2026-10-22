# IoMT Mitigation Component — Requirements & Status Matrix (Rev 5)
**Project J26 CS 330 — H.M.S.H. Wijerathna IT23306936**  
*"Safety Constrained Adaptive SDN Mitigation and Monitoring for IoMT Networks"*  
*Proposal Document Reference: `HMSH_Wijerathna_IT23306936_Proposal_with_Appendices.docx`*  
*Updated: 2026-10-21 (Stage 2 Hardening, Dashboard Integrity & Telemetry Contract)*  

---

## 1. Functional Requirements Traceability Matrix (FR1–FR10)

Derived directly from Proposal Section 5.2 (Table 5 / Table 7) and Section 3 (Methodology):

| ID | Exact Proposal Requirement | Proposal Ref | Implementation Module | Evidence Available | Missing Work | Acceptance Test | Status |
|:---|:---|:---|:---|:---|:---|:---|:---|
| **FR1** | Receive DoS/flooding, reconnaissance and MITM alerts through a standardized REST API. | Sec 5.2 (Table 7), Sec 3.4 (Table 1), p. 19 | `alert_api_v2.py` (`POST /alert`), `controller_detector_interfaces.py` | Unit tests (`test_three_attack_types`, `test_valid_alert_accepted` passing); Localhost HTTP integration test verified | External detector token authentication | `pytest -k test_three_attack_types` | ✅ **Implemented & Offline-Tested** |
| **FR2** | Validate required alert fields before mitigation. | Sec 5.2 (Table 7), Sec 3.4 (Table 1), p. 19 | `alert_validation_v2.py` (`validate_alert`), `controller_detector_interfaces.py` | 18 validation tests passing; 400, 413, 415 handlers verified; duplicate guard hardened | — | `pytest -k TestAlertAPIFlask` | ✅ **Implemented & Offline-Tested** |
| **FR3** | Determine the affected service and its configured criticality. | Sec 3.3, Sec 5.2 (Table 7), p. 15 | `configs/services_v2.json`, `alert_api_v2.py` | `test_service_copy` passing; critical service registry (ECG, infusion) verified in all testbed runs | — | `pytest -k test_service_copy` | ✅ **Implemented & Offline-Tested** |
| **FR4** | Collect current QoS and relevant SDN statistics. | Sec 3.5, Sec 4.2, Sec 5.2 (Table 7), pp. 17-19 | `receiver_callback_monitor.py`, `qos_window_v2.py`, `delay_reader_v2.py`, `telemetry_contract.py` | 5-interval 2s windows (10s rolling); `PeriodicDelayMonitor` aggregates ICMP RTT per window; 163 unit/behavioral/dashboard tests passing | Live concurrent telemetry verification on VM | `pytest -k TestPeriodicDelayMonitor` | ⏳ **Offline-Tested (Live VM Pending)** |
| **FR5** | Select a mitigation action according to security and QoS rules. | Sec 3.4, Sec 5.2 (Table 7), pp. 15-17 | `mitigation_policy_v2.py` (`choose_action`) | 13 policy unit tests passing; degraded-QoS recovery heuristic and safety constraints verified | — | `pytest -k TestMitigationPolicy` | ✅ **Implemented & Offline-Tested** |
| **FR6** | Support rate limiting, rerouting and blocking; OpenFlow enforcement. | Sec 3.4, Sec 4.2, Sec 5.2 (Table 7), pp. 16, 19 | `ovs_enforcement_v2.py` (`OVSEnforcer`), `controller_detector_interfaces.py` (`RyuEnforcementAdapter`) | 27.4 ms HTTP latency verified; meter drop-band verified; `hard_timeout=300s` configured; direct OVS interim verified | Ryu controller live evaluation pending supervisor alignment | `pytest -k TestOVSEnforcer` | ⚠️ **Open Proposal Req (Direct OVS Verified)** |
| **FR7** | Monitor post-mitigation attack status, delay, packet loss and throughput. | Sec 3.5, Sec 3.7 (Table 2), Sec 5.2 (Table 7), pp. 17-19 | `qos_window_v2.py`, `delay_reader_v2.py`, `comparison_runner.py` | Throughput/loss windowing verified; `PeriodicDelayMonitor` tracks RTT min/avg/max per window; reply-only RTT reported honestly while loss is null without verified send timestamps | Live execution on VM | `pytest -k TestDelayReader` | ⏳ **Offline-Tested (Live VM Pending)** |
| **FR8** | Reassess the selected mitigation after a predefined monitoring interval and revise the action when required. | Sec 3.5, Sec 5.2 (Table 7), p. 17 | `comparison_runner.py` (Window 3 evaluation), `periodic_adjustment_live_demo.py` | Fixed adaptive protocol: W3 single adjustment decision; synthetic mock branch verified; fail-closed window validator verified | 1-repeat live smoke run on VM | `pytest -k test_w3_invalid_measurement` | ⏳ **Offline-Tested (Live VM Pending)** |
| **FR9** | Remove temporary rules when the threat has ended and conditions are stable. | Sec 3.5, Sec 5.2 (Table 7), p. 17 | `rule_lifecycle_v2.py` (`CleanupGate`), `controlled_lifecycle_test.py` | 163 tests passing; Live run `lifecycle_demo_20261013_010335` verified W6 removal; canary flow/meter isolation verified | Execute `controlled_lifecycle_test.py --live` on VM | `pytest -k TestCleanupGate` | ⏳ **Offline-Tested (Live VM Pending)** |
| **FR10** | Log alerts, selected actions, OpenFlow changes and measured QoS values. | Sec 4.2, Sec 5.2 (Table 7), pp. 18-19 | `api_events.jsonl`, `window_decisions.jsonl`, `run_summary.json`, `comparison_runner.py`, `logs/live_telemetry_stream.jsonl` | Correlated alert + recommendation + OVS cookie + lifecycle verdict recorded in all summaries, CSV exports, and dashboard stream | Centralized dashboard viewer | `pytest -k test_dashboard_integrity` | ✅ **Implemented & Offline-Tested** |

---

## 2. Non-Functional Requirements Traceability Matrix (NFR1–NFR6)

Derived directly from Proposal Section 5.3 (Table 6 / Table 8):

| Area | Proposal Requirement | Implementation Mechanism | Verified Evidence | Status |
|:---|:---|:---|:---|:---|
| **NFR1: Performance** | Mitigation latency must be measured for each evaluated scenario. | Measured timestamp difference ($t_{\text{after}} - t_{\text{before}}$) recorded in `enforcement_evidence` on all runs. | 27.4 ms to 39.5 ms recorded in live OVS runs; 0.5 ms mock. | ✅ **Verified** |
| **NFR2: Security** | Malformed or incomplete alerts must be rejected, and all control actions must be logged. | Flask schema validator (`alert_validation_v2.py`), token-authenticated dashboard control endpoints, path traversal guards. | 18 validation unit tests + 10 dashboard security tests passing. | ✅ **Verified** |
| **NFR3: Reliability** | Core mitigation function must remain testable even if another group component is unavailable. | Decoupled architecture with `--mock` synthetic generators, standalone dummy alert receivers, and fail-closed validation. | All 163 unit and regression tests run independently of external ML components. | ✅ **Verified** |
| **NFR4: Usability** | System must provide clear status or log output showing attack type, selected action and measured QoS. | Hardened Web Dashboard (`dashboard_server.py`) with LIVE, REPLAY, and DEMO modes, sequential replay, and 3D/2D topology. | Web UI displays topology, real-time metrics, policy timeline, gap-accurate charts, and raw evidence links. | ✅ **Implemented** |
| **NFR5: Scalability** | New detector types should use the same API without redesigning the mitigation core. | Generic schema supporting `attack_type` enum (`DoS_Flooding`, `Reconnaissance`, `MITM`, `Unknown`) via `DetectorAlertInterface`. | Tested with DoS, Recon, and MITM payloads identically. | ✅ **Verified** |
| **NFR6: Reproducibility** | Core prototype must run from documented open-source software and testbed configuration. | Mininet, Open vSwitch, Python standard libraries, Flask, iperf3. Full step-by-step transfer and execution in `RUNBOOK.md`. | Verified reproducible with fixed random seed (42) and Latin-square schedule. | ✅ **Verified** |

---

## 3. Component Responsibility Boundaries

Per Proposal Section 4.3 (Table 3 / Table 5), responsibilities across the group are strictly partitioned:

```
+---------------------------------------------------------------------------------------------------+
|                                  GROUP J26-CS-330 ARCHITECTURE                                    |
+---------------------------------------------------------------------------------------------------+
|  [IT23326354 - Maneth]     [IT23285224 - Bandara]     [IT23368248 - Minthaka]                     |
|  DoS / Flooding Detector   Reconnaissance Detector    MITM Anomaly Detector                       |
|  (Flow Statistical Anal.)  (Port/Host Scan Anal.)     (Protocol Anomaly Anal.)                    |
+----------------------------+--------------------------+-------------------------------------------+
                             |  Standardized REST/JSON Alerts (Proposal Table 1)
                             v
+---------------------------------------------------------------------------------------------------+
|  [IT23306936 - H.M.S.H. Wijerathna] (THIS INDIVIDUAL COMPONENT)                                   |
|  Safety-Constrained Adaptive SDN Mitigation and Monitoring for IoMT Networks                      |
|                                                                                                   |
|  1. REST Alert Receiver & Schema Validation (HTTP 201/400/409/413/415)                            |
|  2. Service Criticality Registry (configs/services_v2.json)                                       |
|  3. Safety-Constrained Policy Engine (Rate Limit vs Block vs Reroute)                             |
|  4. OpenFlow Enforcement (OVSEnforcer Direct OVS / RyuEnforcementAdapter Open Interface)          |
|  5. Periodic QoS Telemetry Windowing (5 x 2s intervals = 10s rolling QoS)                         |
|  6. Periodic ICMP Delay Monitor (Half-open reply arrival windowing)                               |
|  7. Fixed Adaptive Schedule & Bounded Reassessment (Window 3 evaluation)                          |
|  8. Rule Lifecycle Cleanup Gate (2 post-threat stable windows before rule eviction)               |
|  9. Web Dashboard (LIVE, REPLAY, DEMO modes; 3D/2D Topology; Audit Evidence Export; Schema v2.0)  |
+---------------------------------------------------------------------------------------------------+
```

- **Sole Responsibility (IT23306936):** Alert ingestion, validation, duplicate suppression, criticality lookup, mitigation decision engine, OpenFlow rule installation/removal, periodic QoS and RTT telemetry, post-mitigation reassessment, rule cleanup gate, auditable logging, and dashboard.
- **Shared Responsibility:** Standardized REST alert contract (`alert_id`, `attack_type`, `source_ip`, `target_ip`, `severity`, `affected_service`, `timestamp`), and 3-host Mininet testbed topology.
- **External Components (Other Members):** Machine learning detection pipelines (CICIoMT2024 / CICIoT2023 dataset preprocessing, feature engineering, and model training).

---

## 4. SDN Controller & Ryu Compatibility Architecture

### 4.1 Proposal Requirement Status
The project proposal explicitly specifies an SDN architecture using the Ryu OpenFlow Controller.
- **Ryu integration remains an OPEN proposal requirement.**
- Direct OVS OpenFlow 1.3 is verified and serves as the active empirical data-plane testbed engine (27–39 ms latency).
- Neither OS-Ken nor Direct OVS shall be unilaterally substituted in proposal documents without supervisor alignment.

### 4.2 Technical Compatibility Status
1. **Python Version Incompatibility:**
   - Ryu 4.34 relies on `collections.Callable` (removed in Python 3.10), `imp` and `asyncore` (removed in Python 3.12), and Eventlet greenlet threading issues in Python 3.13.
2. **Architecture Pattern: Abstract `EnforcementAdapter`**:
   - `EnforcementAdapter` defines standard methods: `apply(plan)`, `cleanup()`, `query_status()`.
   - `OVSEnforcer` serves as the verified empirical direct-OVS engine for testbed experiments.
   - `RyuEnforcementAdapter` implements the complete REST flow/meter specification, hardened with explicit flow scoping, critical-service protections, protocol-specific matching, and explicit cleanup error propagation.

---

## 5. Telemetry Contract (Schema v2.0)

Documented in full in [`TELEMETRY_SCHEMA.md`](file:///C:/IoMT_Backup/extracted/iomt-research/TELEMETRY_SCHEMA.md).
- Versioned schema: `"2.0"`
- Modes: `LIVE`, `REPLAY`, `DEMO`
- Provenance: `live_kernel_telemetry`, `recorded_benchmark`, `synthetic_simulation`
- Fails closed: Missing or non-finite values remain `null`; never convert to zero.
- Replay: Preserves original timestamps, window definitions, and event sequencing.
- Delay: Labeled strictly as ICMP RTT (`reply_arrival_half_open`).
