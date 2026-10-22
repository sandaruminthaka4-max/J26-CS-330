# Research Project Individual Logbook
**Project Title:** Lightweight SDN-Based Intrusion Detection System for IoMT Networks  
**Project Code:** J26-CS-330  
**Student Name:** H.M.S.H. Wijerathna  
**Student ID:** IT23306936  
**Individual Component:** Safety Constrained Adaptive SDN Mitigation and Monitoring for IoMT Networks  

---

## Log Entries & Development Milestones

### Entry 1 — Architecture Formulation & Alert Receiver Verification
* **Date:** 2026-10-10 (Phase 1)
* **Tasks Completed:**
  - Formulated the architecture for REST-driven SDN mitigation decoupled from detection engine.
  - Implemented service criticality registry (`configs/services_v2.json`) defining protected ECG streams and non-critical background traffic.
  - Developed REST alert receiver and payload validation engine (`alert_api_v2.py`, `alert_validation_v2.py`) covering DoS, reconnaissance, and MITM alert schemas.
  - Verified duplicate alert protection and request validation with 18 unit tests.
* **Key Decisions / Technical Notes:**
  - Enforced structured validation (HTTP 400, 413, 415 handlers) to prevent malformed or oversized alert payloads from destabilizing mitigation state.

---

### Entry 2 — OpenFlow 1.3 Meter Enforcement & Diagnostic Baselines
* **Date:** 2026-10-11 (Phase 2)
* **Tasks Completed:**
  - Implemented OpenFlow 1.3 meter rate-limiting and selective dropping via Open vSwitch (`ovs_enforcement_v2.py`).
  - Evaluated static drop rules vs. adaptive rate-limiting under high offered load (5000 Kbit/s).
  - Built diagnostic comparison runner (`ovs_diagnostic_comparison_demo.py`) capturing meter drops, kernel queue counters, and receiver packet delivery.
  - Established matched UDP packet accounting to verify flow isolation between sensor telemetry and background traffic.
* **Key Decisions / Technical Notes:**
  - Discovered that static port blocking drops both attacking and valid traffic; verified that OpenFlow meters provide QoS survival for critical flows without blanket denial-of-service.

---

### Entry 3 — Periodic Telemetry Windowing & Delay Tracking Integration
* **Date:** 2026-10-12 (Phase 3)
* **Tasks Completed:**
  - Integrated rolling QoS statistics collection (`qos_window_v2.py`) aggregating 5 intervals of 2-second windows (10s rolling evaluation).
  - Developed ICMP RTT delay reader (`delay_reader_v2.py`) to monitor latency alongside throughput and packet loss.
  - Integrated iperf3 3.18 generator for stable offered load generation and verified pacing stability.
  - Verified bounded dynamic reassessment branch (`iperf_adjustment_branch_demo.py`) triggering secondary mitigation if sensor loss exceeds 1%.
* **Key Decisions / Technical Notes:**
  - Decoupled high-frequency packet sampling from mitigation policy assessment to avoid CPU starvation and measurement jitter on the SDN switch.

---

### Entry 4 — Dynamic Reassessment & Rule Lifecycle Cleanup Gate
* **Date:** 2026-10-13 (Phase 4 — Milestone Verification)
* **Tasks Completed:**
  - Implemented formal state machine and cleanup gate (`rule_lifecycle_v2.py`) requiring 2 consecutive stable post-threat windows before rule removal.
  - Implemented transition overlap detection to invalidate windows overlapping threat cessation.
  - Verified complete removal of owned flows and meters on live test runs while preserving default switch policies.
  - Updated default flow rule hard timeout to `hard_timeout=300s` to decouple explicit algorithmic cleanup from OpenFlow timeout expiry.
* **Key Decisions / Technical Notes:**
  - Canary flow and meter validation confirmed that the cleanup gate only removes rules matching the specific incident cookie, preventing interference with other active security rules.

---

### Entry 5 — Controlled Mininet Testbed Suite & Requirements Traceability
* **Date:** 2026-10-13 (Phase 5 — Testbed & Matrix)
* **Tasks Completed:**
  - Built automated controlled test runner (`controlled_lifecycle_test.py`) with isolated Mininet topology (`topology_profile.py`).
  - Automated 107 passing unit tests covering alert parsing, context stores, policy decisions, and lifecycle cleanup gates.
  - Finalized functional requirements matrix (`requirements_matrix.md`) mapping FR1 through FR10 to verified implementation modules.
  - Created structured JSONL logging pipeline (`api_events.jsonl`, `window_decisions.jsonl`) for end-to-end incident auditability.
* **Key Decisions / Technical Notes:**
  - Documented realistic constraints and boundaries (e.g., interim direct OVS execution vs. controller adapter) in the project matrix for proposal compliance.

---

### Entry 6 — Rigorous Counterbalanced Evaluation & Latin-Square Schedule
* **Date:** 2026-10-18 (Phase 6 — Comparative Evaluation)
* **Tasks Completed:**
  - Built comprehensive counterbalanced comparison runner (`comparison_runner.py`) using full 6-permutation Latin-square block scheduling.
  - Evaluated three mitigation scenarios (Baseline unmitigated, Static OpenFlow drop, and Adaptive OVS meter rate limiting) on 3-host Mininet topology.
  - Standardized evaluation around strict Window 6 (50s-60s) with 5 contiguous 2-second receiver intervals.
  - Generated and verified baseline benchmark results (`results/qos_review.json`).
* **Key Decisions / Technical Notes:**
  - Discarded transition windows from final QoS statistics to prevent bias during policy enactment and rate adjustments.

---

### Entry 7 — Telemetry Contract Formalization & Inter-Component Interfaces
* **Date:** 2026-10-21 (Phase 7 — Integration Architecture)
* **Tasks Completed:**
  - Defined strict multi-component schema contract (`telemetry_contract.py` and `TELEMETRY_SCHEMA.md`).
  - Implemented formal `TelemetryEnvelope` with data freshness states (`waiting`, `fresh`, `stale`).
  - Enforced fail-closed telemetry semantics: invalid or missing sensor metrics remain strictly `null`/`None` rather than falling back to zero.
  - Developed `controller_detector_interfaces.py` unifying REST and RPC interfaces between Component 1 (Detection) and Component 2 (Mitigation).
* **Key Decisions / Technical Notes:**
  - Standardized RTT field names across reader and API to eliminate naming divergence and dashboard parsing regressions.

---

### Entry 8 — Real-Time Interactive SDN Mitigation Dashboard
* **Date:** 2026-10-21 (Phase 8 — Visualization & Control UI)
* **Tasks Completed:**
  - Developed full-stack Flask dashboard server (`dashboard_server.py`) with secure endpoint authentication and SSE live telemetry streaming.
  - Created hospital-grade Web UI (`templates/index.html`, `static/css/dashboard.css`, `static/js/dashboard.js`) with responsive dark mode and threat alert cards.
  - Integrated 3D Three.js network topology visualizer (`static/js/topology_3d.js`) showing active switches, flows, and rate limiting status.
  - Built emergency manual kill-switch and instant mitigation rule override controls.
* **Key Decisions / Technical Notes:**
  - Enforced strict path traversal protection in historical run discoverers and implemented automatic background process reaping on server shutdown.

---

### Entry 9 — Acceptance Verification, Operator Runbook & Release Readiness
* **Date:** 2026-10-22 (Phase 9 — Verification & Final Documentation)
* **Tasks Completed:**
  - Authored comprehensive 10-point regression and acceptance test suite (`tests/test_dashboard_integrity.py`).
  - Verified mode switching (DEMO <-> LIVE), authentication token enforcement, and experiment lock synchronization.
  - Completed detailed operator runbook (`RUNBOOK.md`) covering deployment, topology bringup, testbed execution, and troubleshooting.
  - Prepared final individual submission package for GitHub repository integration under branch `IT23306936`.
* **Key Decisions / Technical Notes:**
  - Successfully verified end-to-end integration between detector event schemas and SDN enforcement pipelines with zero test failures.
