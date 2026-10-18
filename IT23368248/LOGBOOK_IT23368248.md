# IT4010 Research Project — Individual Research Logbook

**Project ID:** J26-CS-330  
**Student Name:** S. Minthaka  
**Registration no:** IT23368248  
**Component:** Protocol Anomaly Detection for MITM Attacks in IoMT Networks  
**Module:** IT4010 Research Project  

---

## 📅 Bi-Weekly Logbook Entries (From Scratch to Final Output)

### 📌 Period 1: Weeks 1 – 2 (02/09/2026 – 15/09/2026)
*Focus: Topic Formulation, Literature Survey, Dataset Selection, and Novelty Formulation*

| Date | Task |
| :--- | :--- |
| **02/09/2026** | Discussed with supervisor Mr. Kanishka Yapa and confirmed the individual component: "Protocol Anomaly Detection for MITM Attacks in IoMT Networks". |
| **03/09/2026** | Studied CICIoMT2024 dataset research paper and identified IoMT-specific protocol vulnerabilities (MQTT, CoAP, ARP). |
| **04/09/2026** | Drafted initial component description, research objectives, and ML novelties for IoMT attack detection. |
| **05/09/2026** | Mapped component dependencies across team members: Component 4 (SDN Controller) consumes severity alerts; Component 1 & 2 handle identity and lateral movement. |
| **08/09/2026** | Studied CICIoT2023 dataset paper to solve negative-class problem (CICIoMT2024 lacks non-IoMT traffic needed for a robust classifier). |
| **10/09/2026** | Designed 4-stage IDS pipeline architecture: (1) IoMT Classifier -> (2) MQTT Protocol Filter -> (3) Anomaly Detector -> (3.5) MITM Correlation Engine. |
| **11/09/2026** | Formulated hybrid MITM confirmation concept: combining statistical ML anomaly scores with deterministic protocol indicators (`ARP=1`, DNS redirection). |
| **12/09/2026** | Identified 44 common network flow and statistical features shared between CICIoMT2024 and CICIoT2023 schemas. |
| **15/09/2026** | Defined performance benchmarks: Stage 1 IoMT Accuracy > 99.5%, Stage 3 Anomaly Latency < 0.1 ms/sample for real-time SDN packet inspection, FPR < 1%. |

```
---------------------------------------------------------------------------------------------------
Supervisor Review & Signature (Weeks 1 – 2):
Supervisor Name: Mr. Kanishka Yapa             Signature: ........................   Date: 15/09/2026
Feedback / Remarks: ...............................................................................
---------------------------------------------------------------------------------------------------
```

---

### 📌 Period 2: Weeks 3 – 4 (16/09/2026 – 29/09/2026)
*Focus: Integration Contracts, Repository Setup, Data Preprocessing, and Feature Harmonization*

| Date | Task |
| :--- | :--- |
| **17/09/2026** | Agreed integration contract with Component 4 (SDN Mitigation): confirmed JSON alert schema, severity levels, and REST port 5000. |
| **18/09/2026** | Agreed integration contract with Component 1 & 2: confirmed shared session metadata and anomaly score thresholds. |
| **22/09/2026** | Cloned shared group repo `J26-CS-330` and created individual folder structure `IT23368248` (`api/`, `data/`, `models/`, `reports/`, `src/`, `dashboard/`). |
| **24/09/2026** | Downloaded CICIoMT2024 WiFi+MQTT subset (120,000 samples) and CICIoT2023 subset (120,000 samples) from UNB CIC repository. Total: 240,000 samples. |
| **25/09/2026** | Confirmed Component 4 uses CICIoMT2024 attack labels; agreed to map MITM-enabling attack classes (ARP Spoofing, DNS Spoofing, MQTT Malformed Data). |
| **26/09/2026** | Confirmed scope boundary: detection, alert generation, and threat confidence belong to my component; OpenFlow switch rule enforcement belongs to Component 4. |
| **28/09/2026** | Developed automated dataset preprocessing script (`src/01_feature_mapping.py`): handled null values, normalized features, and mapped 44 harmonized columns. |
| **29/09/2026** | Executed feature mapping pipeline: generated balanced merged dataset `merged_iomt_dataset.csv` (120k IoMT vs 120k Non-IoMT samples) with zero duplicate records. |

```
---------------------------------------------------------------------------------------------------
Supervisor Review & Signature (Weeks 3 – 4):
Supervisor Name: Mr. Kanishka Yapa             Signature: ........................   Date: 29/09/2026
Feedback / Remarks: ...............................................................................
---------------------------------------------------------------------------------------------------
```

---

### 📌 Period 3: Weeks 5 – 6 (30/09/2026 – 13/10/2026)
*Focus: Model Training, Evaluation, Latency Optimization, and Serialization*

| Date | Task |
| :--- | :--- |
| **01/10/2026** | Developed Stage 1 IoMT Classifier script (`src/02_iomt_classifier.py`) using Random Forest algorithm (100 estimators, random_state=42). |
| **03/10/2026** | Evaluated Stage 1 Classifier on held-out test split: achieved 99.99% Accuracy, Precision 0.9999, Recall 1.0000, F1 1.0000, and FPR 0.0001. |
| **05/10/2026** | Generated feature importance graph for Stage 1: verified `Tot size`, `Rate`, and `IAT` provide dominant discriminative power between IoMT and commodity IoT. |
| **07/10/2026** | Developed Stage 3 MQTT Protocol Anomaly Detector (`src/03_anomaly_detector.py`) trained on CICIoMT2024 attack distribution (21 attack classes). |
| **09/10/2026** | Evaluated Stage 3 Model: achieved 99.54% Accuracy, 99.95% Precision, 99.56% Recall, 99.76% F1-score, and 0.0075 False Positive Rate. |
| **11/10/2026** | Benchmarked model inference latency: achieved 0.004 ms per flow sample, fully satisfying real-time SDN packet inspection constraints (< 10 ms). |
| **12/10/2026** | Generated Stage 3 evaluation artifacts: confusion matrix (`anomaly_confusion_matrix.png`) and comprehensive classification report. |
| **13/10/2026** | Serialized trained production models (`models/iomt_classifier.joblib` and `models/anomaly_detector.joblib`) and saved environment dependencies (`requirements.txt`). |

```
---------------------------------------------------------------------------------------------------
Supervisor Review & Signature (Weeks 5 – 6):
Supervisor Name: Mr. Kanishka Yapa             Signature: ........................   Date: 13/10/2026
Feedback / Remarks: ...............................................................................
---------------------------------------------------------------------------------------------------
```

---

### 📌 Period 4: Week 7 & Final Output (14/10/2026 – 18/10/2026)
*Focus: REST API, MITM Forensics, Clinical Healthcare Context, Real-Time Alert Dashboard & Audio Warning*

| Date | Task |
| :--- | :--- |
| **14/10/2026** | Developed production Flask REST API (`api/app.py`) providing `/predict`, `/predict/batch`, `/health`, and direct dashboard hosting on `http://localhost:5000/`. Added Windows one-click launcher `run_localhost.bat`. |
| **15/10/2026** | Built Stage 3.5 Deterministic MITM Correlation Engine: correlated ML anomaly scores with protocol-layer indicators (`ARP=1`, DNS redirects, MQTT malformed variance, and bedside telemetry tampering), accurately discriminating true MITM from volumetric DDoS floods. |
| **16/10/2026** | Integrated clinical healthcare context & patient profile models: mapped targeted IoMT devices (Alaris Infusion Pump, Philips ECG Monitor, Hamilton Ventilator, Mindray Bedside Monitor) to specific ICU/Ward patients (Kamal, Sunil, Nimali, Anura), modeling nuanced clinical morbidity hazards (hypoglycemic coma, cardiogenic shock, acute hypoxemic respiratory distress, concealed hemorrhage/hypovolemic shock). |
| **17/10/2026** | Developed interactive real-time threat alert dashboard (`dashboard/index.html`): built real-time Chart.js anomaly stream, live patient bed roster, safe baseline vs tampered telemetry comparison table, top emergency warning banner, and integrated a continuous non-rhythmic 3.5-second serious hospital emergency warning beep (Web Audio API). |
| **18/10/2026** | Conducted comprehensive end-to-end integration testing: verified live pipeline from synthetic packet injection -> ML classification & inference (0.004 ms) -> MITM confirmation -> real-time threat alert feed. Refined alert stream to maintain strict individual component scope boundary (threat detection & alerting without SDN mitigation text). Finalized all documentation, Git milestone history, and bi-weekly supervisor sign-offs. |

```
---------------------------------------------------------------------------------------------------
Supervisor Review & Final Sign-Off (Week 7 / Final):
Supervisor Name: Mr. Kanishka Yapa             Signature: ........................   Date: 18/10/2026
Feedback / Remarks: ...............................................................................
---------------------------------------------------------------------------------------------------
```
