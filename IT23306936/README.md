# Safety Constrained Adaptive SDN Mitigation and Monitoring for IoMT Networks
### Component 2 — J26-CS-330 | Individual Research Component
**Student Name:** H.M.S.H. Wijerathna  
**Student ID:** IT23306936  
**Specialization:** Computer Systems & Network Engineering (CSNE)  
**Supervisor / Module:** Research Project (J26-CS-330)

---

## 1. Project Overview

Medical Internet of Things (IoMT) environments demand stringent Quality of Service (QoS), where delays or packet loss in telemetry streams (such as real-time ECG and vitals) directly endanger patient safety. Traditional denial-of-service (DoS) mitigations—such as static port blocking or blanket IP blacklisting—often induce collateral damage by dropping critical clinical flows alongside malicious traffic.

This individual component implements a **Safety-Constrained, Adaptive Software-Defined Networking (SDN) Mitigation and Monitoring System** tailored for IoMT networks:
1. **Decoupled REST Alert Receiver**: Ingests threat detection events from the upstream ML detection pipeline with strict RFC schema validation.
2. **Service Criticality Registry**: Classifies clinical telemetry (ECG UDP 5202) as strictly protected while marking bulk background and attacker traffic as throttlable.
3. **OpenFlow 1.3 Meter Enforcement**: Applies dynamic meter bands via Open vSwitch (OVS) rather than crude port shutdown, allowing IoMT sensors to maintain near-zero packet loss during volumetric attacks.
4. **Rolling QoS Windowing & RTT Tracking**: Collects rolling 10-second QoS windows with ICMP RTT latency measurement to continuously evaluate telemetry health.
5. **Adaptive Reassessment Engine**: Dynamically scales rate limits down if sensor packet loss exceeds safety thresholds (>1%).
6. **Post-Threat Rule Lifecycle Gate**: Requires consecutive stable observation windows before safely retiring mitigation rules, guarding against intermittent attack bursts.
7. **Real-Time Interactive Dashboard**: Full-featured web UI with 3D topology visualizer, live SSE telemetry streaming, discrimination matrix, and emergency manual kill-switch.

---

## 2. Directory Structure

```
IT23306936/
├── configs/
│   └── services_v2.json                 ← Service criticality registry & QoS constraints
├── static/                              ← Web dashboard static assets
│   ├── css/
│   │   └── dashboard.css                ← Modern dark-mode clinical dashboard styling
│   ├── js/
│   │   ├── dashboard.js                 ← SSE event streaming & interactive UI controller
│   │   └── topology_3d.js               ← 3D Three.js hospital SDN topology visualizer
│   └── img/                             ← Illustrative architectural & network diagrams
├── templates/
│   └── index.html                       ← Dashboard UI layout with live telemetry gauges
├── tests/
│   ├── test_units.py                    ← 107 passing unit tests (parsing, policy, lifecycle)
│   └── test_dashboard_integrity.py      ← 10 regression/acceptance tests for dashboard API
├── results/                             ← Curated benchmark evaluations and test run logs
│   ├── qos_review.json                  ← Baseline vs. static vs. adaptive benchmark review
│   ├── static_comparison.json           ← Diagnostic comparison dataset
│   └── sensor_check_udp.json            ← Matched UDP flow accounting records
├── alert_api_v2.py                      ← REST alert receiver API (Flask)
├── alert_validation_v2.py               ← Alert schema parsing and HTTP validation
├── ovs_enforcement_v2.py                ← OpenFlow 1.3 meter configuration and OVS rules
├── mitigation_policy_v2.py              ← Safety-constrained adaptive mitigation policy engine
├── rule_lifecycle_v2.py                 ← Post-threat cleanup state machine and canary validation
├── delay_reader_v2.py                   ← ICMP RTT ping delay monitoring daemon
├── qos_window_v2.py                     ← Rolling 10s window aggregation (2s intervals)
├── comparison_runner.py                 ← Counterbalanced 6-permutation Latin-square evaluation runner
├── controlled_lifecycle_test.py         ← Automated Mininet controlled lifecycle verification suite
├── topology_profile.py                  ← 3-host Mininet topology definition (Sensor, Edge, Attacker)
├── controller_detector_interfaces.py    ← Unified inter-component interface definitions
├── telemetry_contract.py                ← Telemetry envelope definitions and schema contracts
├── dashboard_server.py                  ← Real-time telemetry dashboard server
├── TELEMETRY_SCHEMA.md                  ← Formal JSON schema specification
├── requirements_matrix.md               ← Requirements traceability matrix (FR1 - FR10)
├── RUNBOOK.md                           ← Step-by-step operator deployment guide
├── LOGBOOK_IT23306936.md                ← Comprehensive research logbook (Milestones 1 - 9)
├── requirements.txt                     ← Python dependencies
└── README.md                            ← Component documentation
```

---

## 3. Quick Start & Setup

### Prerequisites
* Python 3.9+
* Open vSwitch (OVS) and Mininet (for live network emulation on Linux)
* Modern web browser (Chrome, Edge, Firefox)

### Installation
```bash
cd IT23306936
pip install -r requirements.txt
```

### Running Unit Tests
Execute the full automated test suite (117+ tests):
```bash
pytest tests/ -v
```

---

## 4. Running the System

### A. Launch the Real-Time Mitigation Dashboard
```bash
python dashboard_server.py
```
Open your browser and navigate to:
```
http://localhost:5000
```
* **Demo Mode**: Simulates realistic multi-stage DoS/MITM attacks and displays adaptive meter responses in real time.
* **Live Mode**: Binds to local Mininet/OVS testbed and streams genuine kernel/switch telemetry.
* **3D Visualizer**: Inspect switches, flows, packet loss, and rate-limiting bands dynamically.

### B. Launch Alert Receiver & Mitigation API
```bash
python alert_api_v2.py
```
Receives structured alert events on `http://localhost:5001/api/v2/alerts`:
```bash
curl -X POST http://localhost:5001/api/v2/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "ALT-20261022-001",
    "threat_type": "DoS_Flooding",
    "source_ip": "10.0.0.3",
    "target_ip": "10.0.0.2",
    "target_port": 5201,
    "confidence": 0.95,
    "timestamp": "2026-10-22T09:00:00Z"
  }'
```

### C. Run Controlled Mininet Lifecycle Testbed
On a Linux testbed with Mininet and OVS installed:
```bash
sudo python controlled_lifecycle_test.py
```

### D. Run Counterbalanced Latin-Square Comparison Evaluation
```bash
sudo python comparison_runner.py
```

---

## 5. Experimental Results & Performance Summary

In controlled evaluations under 5 Mbit/s adversarial background load competing with 100 Kbit/s clinical ECG telemetry:

| Metric | Unmitigated Baseline | Static Port Drop | Adaptive OVS Meter (Ours) |
|---|---|---|---|
| **Critical Telemetry Loss** | 68.4% | 100.0% (collateral drop) | **0.0%** (zero drop) |
| **Critical Flow Throughput** | 31.6 Kbit/s | 0.0 Kbit/s | **100.0 Kbit/s** (guaranteed) |
| **Background Load Allowed** | 5000 Kbit/s | 0 Kbit/s | **1000 Kbit/s** (rate-limited) |
| **ICMP RTT Latency** | 42.8 ms (jitter spike) | N/A (unreachable) | **3.4 ms** (stable) |
| **Rule Cleanup Time** | N/A | Manual intervention | **< 4.0s** (automated gate) |

---

## 6. Requirements Traceability

| ID | Requirement | Implementation Module | Verification Test |
|---|---|---|---|
| **FR1** | Service Criticality Classification | `configs/services_v2.json` | `tests/test_units.py::test_service_registry` |
| **FR2** | REST Alert Ingestion & Validation | `alert_api_v2.py`, `alert_validation_v2.py` | `tests/test_units.py::test_alert_validation` |
| **FR3** | OpenFlow 1.3 Meter Rate-Limiting | `ovs_enforcement_v2.py` | `tests/test_units.py::test_ovs_meter_commands` |
| **FR4** | Flow Isolation & Matched Accounting | `ovs_diagnostic_comparison_demo.py` | `results/sensor_check_udp.json` |
| **FR5** | Rolling QoS Telemetry Windowing | `qos_window_v2.py` | `tests/test_units.py::test_qos_window_aggregation` |
| **FR6** | ICMP RTT Latency Monitoring | `delay_reader_v2.py` | `tests/test_units.py::test_delay_reader` |
| **FR7** | Bounded Adaptive Reassessment | `mitigation_policy_v2.py` | `tests/test_units.py::test_adaptive_policy` |
| **FR8** | Post-Threat Cleanup Gate & Canaries | `rule_lifecycle_v2.py` | `tests/test_units.py::test_rule_lifecycle_gate` |
| **FR9** | Automated Mininet Testbed Suite | `controlled_lifecycle_test.py` | `results/qos_review.json` |
| **FR10**| Real-Time Operator Dashboard & UI | `dashboard_server.py`, `static/`, `templates/`| `tests/test_dashboard_integrity.py` |

---

## 7. Research Attribution & Authorship

* **Author:** H.M.S.H. Wijerathna (IT23306936)
* **Project Code:** J26-CS-330
* **Research Title:** Lightweight SDN-Based Intrusion Detection System for IoMT Networks
* **Component 1 (ML Detection):** S. Minthaka (IT23368248)
* **Component 2 (SDN Mitigation & Monitoring):** H.M.S.H. Wijerathna (IT23306936)
