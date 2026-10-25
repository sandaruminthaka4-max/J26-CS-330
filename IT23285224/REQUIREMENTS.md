# Requirements Specification & Traceability Matrix

**Project Title:** Lightweight SDN Intrusion Detection & Zero-Touch Mitigation System for IoMT Networks  
**Individual Research Component:** Multi-Class Reconnaissance Attack Detection for IoMT Networks  
**Project ID:** J26-CS-330  
**Student:** Bandara B.R.K.Y (IT23285224)  
**Institution:** Sri Lanka Institute of Information Technology (SLIIT)  
**Primary Dataset:** CICIoMT2024  

---

## 1. Executive Summary & Problem Context

The Internet of Medical Things (IoMT) deploys connected telemetry monitors, infusion pumps, vital signs monitors, and diagnostic devices in hospital environments. While enabling real-time clinical care, IoMT ecosystems present acute vulnerabilities due to lightweight firmware, legacy communication protocols, and constrained computing budgets. 

Adversarial intrusion campaigns in IoMT environments almost universally initiate with an active network **reconnaissance** phase. Reconnaissance allows adversaries to map active medical node IP addresses, enumerate open listening ports, fingerprint operating systems, and probe known vulnerabilities without triggering volume-based flood detectors (such as DoS/DDoS alarms).

Conventional Network Intrusion Detection Systems (NIDS) exhibit severe limitations in this domain:
1. **Coarse-Grained Labeling:** Reconnaissance is lumped into a monolithic binary class or single "Scan" label, preventing the SDN controller from selecting proportionate, risk-calibrated mitigation actions.
2. **Domain Mismatch:** Existing lightweight IDS models are predominantly trained and evaluated on generic IoT datasets (e.g., CIC-IoT 2023, BoT-IoT) whose traffic profiles do not reflect medical telemetry characteristics or IoMT multi-protocol dynamics.
3. **Superficial "Lightweight" Claims:** Prior work claims lightweight properties purely by reducing feature counts without profiling end-to-end inference latency (P50/P95), serialized model footprint, CPU overhead, or RAM footprint.
4. **Data Leakage & Inflated Metrics:** Preprocessing fitted across entire datasets before splitting, inclusion of capture-specific flow identifiers (IPs/ports/timestamps/session tags), and flow replication across train/test splits inflate reported F1-scores.
5. **Decoupled Alerting:** Most academic detectors produce disconnected offline evaluation metrics without structured, confidence-aware API payloads consumable by automated SDN control planes.

This component establishes an academically rigorous, lightweight, multi-class reconnaissance detector targeting the five key classes:
- **Benign IoMT**
- **Ping Sweep**
- **Port Scan**
- **OS Scan**
- **Vulnerability Scan** (`Recon VulScan`)

---

## 2. Research Objectives

### 2.1 Main Objective
To design, implement, and rigorously evaluate a lightweight, multi-class reconnaissance attack detection system for IoMT networks using the CICIoMT2024 benchmark dataset. The system distinguishes benign clinical traffic from four distinct reconnaissance attack vectors (Ping Sweep, Port Scan, OS Scan, Vulnerability Scan), operates on a strictly validated, reduced-feature representation, profiles real computational costs on commodity hardware, and exposes a real-time, confidence-aware REST API designed for integration with an SDN zero-touch mitigation controller.

### 2.2 Specific Objectives (SO)
- **SO1:** Extract, validate, and audit the benign and reconnaissance subsets of CICIoMT2024, producing an immutable dataset manifest and formal data dictionary.
- **SO2:** Conduct a comprehensive data audit identifying missing values, infinite values, duplicate flows, and identifier-based data leakage hazards.
- **SO3:** Formulate and benchmark feature selection strategies (Mutual Information, Chi-Square, Embedded Tree Importance, and Recursive Feature Elimination) exclusively fitted within cross-validation folds.
- **SO4:** Train and compare six supervised classifiers: Decision Tree (DT), Logistic Regression (LR), Linear Support Vector Machine (Linear SVM), Random Forest (RF), eXtreme Gradient Boosting (XGBoost), and Light Gradient Boosting Machine (LightGBM).
- **SO5:** Establish a Pareto Deployment Scorecard balancing Macro-F1, minimum per-class recall, median/P95 inference latency, serialized model storage size, and runtime CPU/RAM utilization.
- **SO6:** Implement baseline comparisons: Full-Feature Multi-Class (Baseline A), Reduced-Feature Multi-Class (Baseline B), Binary Benign vs. Reconnaissance (Baseline C), and Hierarchical Two-Stage Classification (Baseline D).
- **SO7:** Package the complete preprocessing, imputation, scaling, and feature-selection pipeline into an atomic, reproducible artifact.
- **SO8:** Develop a production-grade, asynchronous REST Prediction API (FastAPI) featuring health checks, model metadata endpoints, single/batch prediction, confidence scoring, rule-based severity calculation, and SQLite alert persistence.
- **SO9:** Construct an SDN mitigation integration adapter with webhook dispatch, exponential backoff retries, idempotent alert dispatch, and a standalone mock mitigation controller.
- **SO10:** Validate end-to-end integration latency and pipeline fidelity through automated test suites and live simulated attack scenarios.

---

## 3. Detailed Requirements

### 3.1 Functional Requirements (FR)

| Req ID | Requirement Statement | Verification Method |
| :--- | :--- | :--- |
| **FR1** | The system shall ingest network flow feature vectors conforming to the official 46-column CICIoMT2024 schema in both single-record and batch JSON payloads. | Automated Unit & Integration Tests |
| **FR2** | The system shall encapsulate all data validation, missing/infinite value handling, normalization, scaling, and feature selection within an atomic pipeline object fitted strictly on training partitions. | Pipeline Serialization & Leakage Audit Tests |
| **FR3** | The system shall classify input flows into exactly one of five target classes: `Benign`, `Ping Sweep`, `Port Scan`, `OS Scan`, or `Vulnerability Scan`. | Multi-Class Confusion Matrix & Unit Tests |
| **FR4** | The classifier shall output calibrated class probabilities and an overall prediction confidence score $[0.0, 1.0]$ for every evaluated flow. | Probability Calibration & Calibration Curve Tests |
| **FR5** | The REST service shall provide endpoints for single prediction (`POST /predict`), batch prediction (`POST /predict/batch`), health status (`GET /health`), model info (`GET /model/info`), feature metadata (`GET /features`), alerts retrieval (`GET /alerts`), and system metrics (`GET /metrics`). | FastAPI TestClient Suite & OpenAPI Inspection |
| **FR6** | The system shall calculate risk severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) using a deterministic, documented rule engine combining predicted scan subtype, probability confidence, and target criticality context. | Severity Matrix Decision Unit Tests |
| **FR7** | The system shall persist every detected reconnaissance event with timestamp, unique alert ID, flow identifier, predicted subtype, confidence score, assigned severity, and delivery status in a persistent local store (SQLite) with an abstracted repository interface. | SQLite Persistence & Repository Unit Tests |
| **FR8** | The system shall provide an SDN Webhook Dispatcher capable of posting structured JSON alert payloads to external mitigation controllers with configurable timeouts, retries, and duplicate suppression. | Integration Tests with Mock Mitigation Server |
| **FR9** | The system shall deliver a standalone Mock Mitigation Receiver capable of acknowledging alert webhooks, recording end-to-end latency, and logging simulated OpenFlow action decisions. | End-to-End Mock Controller Tests |

### 3.2 Non-Functional Requirements (NFR)

| Req ID | Requirement Statement | Evaluation Metric / Bound |
| :--- | :--- | :--- |
| **NFR1** | **Inference Latency:** Model inference latency shall be optimized for real-time SDN control, aiming for median latency $< 10$ ms and batch latency $< 100$ ms on commodity x86 CPU hardware. | Benchmarking Script (`psutil`, `time.perf_counter`) |
| **NFR2** | **Detection Reliability:** False positive rate (FPR) on benign IoMT flows must remain low to prevent medical device disconnects; minimum per-class recall across minority scan subtypes (Ping Sweep, VulScan) must exceed 0.80 where supported by dataset distribution. | Per-Class Classification Report & Confusion Matrix |
| **NFR3** | **Lightweight Footprint:** The selected feature count shall be reduced by $\ge 50\%$ from the full 45 feature set, serialized model size shall not exceed 50 MB, and runtime resident memory (RSS) shall remain below 500 MB. | Size Audits & Memory Profiling Logs |
| **NFR4** | **Data Isolation & Patient Safety:** The system shall process solely layer-3/4 flow statistical metadata. No Protected Health Information (PHI) or medical payload data shall be stored or transmitted. | Schema Review & Privacy Verification |
| **NFR5** | **Reproducibility:** All preprocessing, feature selection, data splits, and model training routines shall utilize fixed random seeds (default: 42) and configuration files to ensure deterministic academic reproduction. | Cross-seed Stability Tests |
| **NFR6** | **Production Modularity:** Codebase must be organized into high-cohesion, low-coupling modules with type annotations, docstrings, and comprehensive test coverage. | Pytest Suite & Static Analysis |

---

## 4. Requirements Traceability Matrix (RTM)

| Proposal Requirement | Implementation Module / File | Automated Verification Test | Status |
| :--- | :--- | :--- | :--- |
| **Dataset Ingestion & Schema Audit** | `src/data/loader.py`, `src/data/schema.py` | `tests/test_data_loader.py` | Defined |
| **Leakage-Free Preprocessing Pipeline** | `src/features/preprocessor.py` | `tests/test_preprocessor.py` | Defined |
| **Feature Selection (MI, Chi2, RFE, Tree)** | `src/features/selector.py` | `tests/test_feature_selector.py` | Defined |
| **Multi-Class Classifier Implementations** | `src/models/classifiers.py`, `src/models/trainer.py` | `tests/test_models.py` | Defined |
| **Baseline Models (Full, Reduced, Binary, Hierarchical)** | `src/models/baselines.py` | `tests/test_baselines.py` | Defined |
| **Academic Metrics & Profiling** | `src/evaluation/metrics.py`, `src/evaluation/profiler.py` | `tests/test_evaluation.py` | Defined |
| **REST Prediction Service** | `src/api/app.py`, `src/api/routes.py`, `src/api/schemas.py` | `tests/test_api.py` | Defined |
| **Confidence & Severity Rule Engine** | `src/alerts/engine.py` | `tests/test_alerts.py` | Defined |
| **Alert Database Persistence** | `src/alerts/repository.py` | `tests/test_repository.py` | Defined |
| **SDN Webhook Adapter & Mock Receiver** | `src/integration/sdn_client.py`, `src/integration/mock_controller.py` | `tests/test_integration.py` | Defined |
| **Lightweight Demonstration Dashboard** | `src/dashboard/` (FastAPI static + vanilla modern UI) | Manual Viva Walkthrough / Browser Subagent | Defined |

---

## 5. System Boundary & Team Responsibilities

```
+---------------------------------------------------------------------------------------------------+
|                         SHARED SDN IoMT ENVIRONMENT & DATASET (CICIoMT2024)                      |
+---------------------------------------------------------------------------------------------------+
|               IoMT Medical Device Network & SDN OpenFlow Switch (Edge Data Plane)                 |
+---------------------------------------------------------------------------------------------------+
                                                |
                                                | Network Flow Telemetry (JSON)
                                                v
                                +-------------------------------+
                                |  Author: Bandara B.R.K.Y      |
                                |  Student ID: IT23285224       |
                                |  Multi-Class Reconnaissance   |
                                |  Detection Service (REST API) |
                                +-------------------------------+
                                                |
                                                | High-Severity Webhook Alert
                                                v
                                +-------------------------------+
                                | SDN Zero-Touch Mitigation     |
                                | OpenFlow FlowMod Controller   |
                                | (Automated Rule Enforcement)  |
                                +-------------------------------+
```

*Note: The individual researcher's responsibility encompasses the complete multi-class reconnaissance model engineering, streaming dataset ingestion, leakage-free preprocessing, consensus feature selection, efficiency benchmarking, REST API development, confidence-aware severity calculation, alert dispatching, and zero-touch SDN mitigation integration.*
