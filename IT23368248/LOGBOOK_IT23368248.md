# Research Project Individual Logbook
**Project Title:** Lightweight SDN-Based Intrusion Detection System for IoMT Networks  
**Project Code:** J26-CS-330  
**Student Name:** S. Minthaka  
**Student ID:** IT23368248  
**Individual Component:** IoMT Traffic Identification & MQTT Protocol Anomaly Detection for MITM Attacks  

---

## Log Entries & Development Milestones

### Entry 1 — Project Initialization & Environment Setup
* **Date:** 2026-10-13 (Phase 1)
* **Tasks Completed:**
  - Formulated technical pipeline requirements for 2-stage IDS: (1) IoMT Traffic Identification and (2) MQTT MITM Anomaly Detection.
  - Initialized project architecture (`api/`, `data/`, `models/`, `reports/`, `src/`).
  - Set up Python 3.13 ML environment (`scikit-learn`, `xgboost`, `lightgbm`, `imbalanced-learn`, `flask`).
  - Created `.gitignore` and dependency manifest (`requirements.txt`).
* **Key Decisions / Technical Notes:**
  - Standardized directory layout to isolate raw dataset references from committed models and pipeline scripts.

---

### Entry 2 — Dataset Pipeline & Feature Mapping (CICIoMT2024 & CICIoT2023)
* **Date:** 2026-10-13 (Phase 2)
* **Tasks Completed:**
  - Investigated CICIoMT2024 WiFi+MQTT schema and identified that it lacks a non-IoMT negative class.
  - Merged CICIoMT2024 (120,000 IoMT samples) with CICIoT2023 (120,000 general IoT samples) to enable a defensible binary IoMT classifier.
  - Harmonized 44 shared network flow and statistical features (`Header_Length`, `Rate`, `IAT`, TCP flag counters, packet length distribution).
  - Developed and executed automated merge script (`src/01_feature_mapping.py`).
* **Key Decisions / Technical Notes:**
  - Balanced class distribution at 50/50 (120k each) to prevent machine learning classification bias.

---

### Entry 3 — Stage 1 IoMT Traffic Classifier Implementation
* **Date:** 2026-10-13 (Phase 3)
* **Tasks Completed:**
  - Implemented Stage 1 Random Forest Classifier (`src/02_iomt_classifier.py`).
  - Evaluated on held-out test split: Accuracy 99.99%, Precision 0.9999, Recall 1.0000, F1 1.0000, FPR 0.0001.
  - Generated and saved confusion matrix (`iomt_confusion_matrix.png`) and feature importance graph (`iomt_feature_importance.png`).
  - Serialized trained pipeline artifact (`models/iomt_classifier.joblib`).
* **Key Decisions / Technical Notes:**
  - Validated that flow statistical shape (`Tot size`, `Rate`, `IAT`) provides high separability between medical sensors and commodity IoT nodes.

---

### Entry 4 — Stage 3 MQTT Protocol Anomaly Detection (MITM-Enabling Vectors)
* **Date:** 2026-10-13 (Phase 4)
* **Tasks Completed:**
  - Developed Random Forest Anomaly Detector (`src/03_anomaly_detector.py`) on CICIoMT2024 benchmark.
  - Balanced across 21 attack scenarios (including ARP Spoofing, DNS Spoofing, and MQTT-Malformed-Data).
  - Evaluated model: Accuracy 99.54%, Precision 99.95%, Recall 99.56%, F1 99.76%, FPR 0.0075.
  - Measured inference latency: 0.004 ms/sample (meeting real-time SDN mitigation constraints).
  - Serialized model artifact (`models/anomaly_detector.joblib`) and evaluation reports.
* **Key Decisions / Technical Notes:**
  - Addressed lack of monolithic "MITM" label by explicitly mapping MITM-enabling protocol attack classes (ARP Spoofing, Malformed MQTT).

---

### Entry 5 — Integrated Multi-Stage REST API Implementation
* **Date:** 2026-10-13 (Phase 5)
* **Tasks Completed:**
  - Developed Flask REST API (`api/app.py`) providing `/predict`, `/predict/batch`, `/health`, and `/schema`.
  - Integrated Stage 1 (IoMT verification), Stage 2 (MQTT protocol check), and Stage 3 (Anomaly inference).
  - Designed compliant JSON response structure with explicit status indicators, confidence scores, and academic limitation disclosures.
* **Key Decisions / Technical Notes:**
  - Exposed structured SDN action triggers (`SDN_ISOLATE_SWITCH_PORT_AND_DROP_FLOW`, `ALLOW_TRAFFIC`) to interface with Ryu controller.

---

### Entry 6 — Deterministic MITM Correlation Engine & Real-Time Alert Feed
* **Date:** 2026-10-14
* **Tasks Completed:**
  - Implemented Stage 3.5 Hybrid MITM Correlation Engine in `api/app.py`.
  - Correlated machine learning anomalies with deterministic protocol vectors (ARP Poisoning, DNS Redirection, Payload Tampering).
  - Added dedicated `/alerts` and `/alerts/clear` endpoints for dashboard integration.
  - Calibrated decision thresholds to eliminate false positives on benign medical telemetry.
  - Tested live against confirmed MITM attacks (critical alert) and normal telemetry (allow flow).
* **Key Decisions / Technical Notes:**
  - Upgraded anomaly prediction from speculative "Suspicious" to 100% "Confirmed MITM Attack" when ARP conflict / tampering signature coincides with ML anomaly score.

---

### Entry 7 — Threat Visualization Dashboard & Scope Alignment
* **Date:** 2026-10-21
* **Tasks Completed:**
  - Implemented standalone interactive frontend dashboard (`dashboard/index.html`) using HTML5, CSS3, and Chart.js.
  - Enabled Cross-Origin Resource Sharing (`flask-cors`) on Flask REST API to allow browser telemetry polling.
  - Formulated clear component scope boundary: explicitly delineating detection/alerting responsibilities from Team Member 4's SDN enforcement/mitigation duties.
  - Incorporated a protocol discrimination matrix illustrating differentiation between MITM (ARP conflict) and volumetric floods (DDoS).
  - Built real-time interactive traffic injectors for MITM (ARP Poisoning), Volumetric Flood, and Normal Patient Telemetry.
* **Key Decisions / Technical Notes:**
  - Standardized terminology across UI: replaced "Mitigated by Ryu" with "Action Dispatched to SDN Layer" to maintain strict fidelity to the individual research scope.

---

### Summary of Completed Milestones
| Milestone | Status | Key Deliverable |
|---|:---:|---|
| Architecture & Environment | Completed | Project structure, `.gitignore`, `requirements.txt` |
| Dataset Merge & Mapping | Completed | `01_feature_mapping.py`, 44 harmonized features |
| Stage 1 IoMT Classifier | Completed | `02_iomt_classifier.py`, `iomt_classifier.joblib`, 99.99% Acc |
| Stage 3 Anomaly Detector | Completed | `03_anomaly_detector.py`, `anomaly_detector.joblib`, 99.54% Acc |
| Integrated REST API | Completed | `api/app.py`, endpoints (`/predict`, `/health`, `/schema`) |
| MITM Correlation & Alerting | Completed | Stage 3.5 engine, `/alerts` feed, 100% verified alerts |
| Threat Alert Dashboard | Completed | `dashboard/index.html`, scope alignment, live injectors |
