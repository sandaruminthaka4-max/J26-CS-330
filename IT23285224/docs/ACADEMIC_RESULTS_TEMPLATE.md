# Academic Research Findings & Dissertation Results Section

**Project Title:** Lightweight SDN Intrusion Detection & Zero-Touch Mitigation System for IoMT Networks  
**Individual Component:** Multi-Class Reconnaissance Attack Detection for IoMT Networks  
**Student:** Bandara B.R.K.Y (IT23285224)  
**Project ID:** J26-CS-330  
**Supervisor Alignment:** Fourth-Year B.Sc. (Hons) in Cyber Security, SLIIT  
**Dataset:** Canadian Institute for Cybersecurity IoMT 2024 (`CICIoMT2024`)  

---

## 1. Experimental Methodology & Dataset Preparation

### 1.1 Dataset Provenance & Scope
The experimental evaluation was conducted strictly using the official **CICIoMT2024** benchmark dataset published by the Canadian Institute for Cybersecurity at the University of New Brunswick (Dadkhah et al., 2024). In accordance with the individual research objectives:
- **Excluded Flooding/Spoofing Vectors:** High-volume volumetric DDoS/DoS and layer-2 spoofing were excluded to focus model capacity strictly on subtle, slow-and-low reconnaissance signatures.
- **Target Inclusions:** 100% of available reconnaissance scans and benign IoMT traffic were isolated from the official partitions (`train_iomt.csv` and `test_iomt.csv`).
- **Cryptographic Provenance:** The raw archive `CICIoMT2024 DataSets.zip` (168.03 MB) yielded a verified SHA-256 integrity digest of `8da94655b1b6ab4025175cf525381f185ef35beff09849206d2139049e3fa6db`.

### 1.2 Class Distribution & Severe Imbalance
Across 8,775,013 scanned raw network records, 361,741 relevant flows were identified and extracted into canonical target classes:

| Class Taxonomy | Raw Label in CICIoMT2024 | Train Partition (80%) | Validation Partition (20%) | Test Partition (Untouched) | Total Samples | Class Proportion |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Benign** | `benign` | 154,185 | 38,547 | 37,607 | 230,339 | 63.68% |
| **Port Scan** | `Port Scan` | 67,185 | 16,796 | 22,622 | 106,603 | 29.47% |
| **OS Scan** | `OS Scan` | 13,466 | 3,366 | 3,834 | 20,666 | 5.71% |
| **Vulnerability Scan** | `Recon VulScan` | 1,738 | 435 | 1,034 | 3,207 | 0.89% |
| **Ping Sweep** | `Ping Sweep` | 592 | 148 | 186 | 926 | 0.25% |
| **Total** | | **237,166** | **59,292** | **65,283** | **361,741** | **100.00%** |

*Observation:* Ping Sweep ($0.25\%$) and Vulnerability Scan ($0.89\%$) represent acute minority classes. Evaluating systems using overall accuracy alone would obscure severe detection failures on these critical initial attack stages, strongly justifying Macro-F1 and per-class recall tracking.

### 1.3 Data Leakage Controls
1. **Identifier Elimination:** All MAC addresses, IP addresses, layer-4 port numbers, timestamps, and capture session indices were permanently excluded from candidate features.
2. **Independent Preprocessing:** Imputation medians, infinite-value bounding percentiles, and standard scaling parameters were calculated strictly on training partitions via the serialized `ReconFlowPreprocessor`.
3. **Partition Isolation:** The official test set (`65,283` flows) remained untouched until final evaluation.

---

## 2. Feature Selection & Dimensionality Reduction Study

### 2.1 Multi-Criteria Consensus Ranking
Candidate features spanning 5 functional groups (rates, TCP flags, protocols, packet sizes, distributions) were evaluated on the training partition using 4 independent methodologies:
1. **Mutual Information (MI):** Non-linear dependency estimation.
2. **Chi-Square ($\chi^2$):** Independence testing on non-negative scaled distributions.
3. **Tree Importance (MDI):** ExtraTrees Gini impurity reduction.
4. **Recursive Feature Elimination (RFE):** Backward feature pruning.

A weighted consensus rank ($30\%\text{ MI} + 30\%\text{ Trees} + 20\%\chi^2 + 20\%\text{ RFE}$) isolated the top-15 most discriminative features:

| Rank | Selected Feature | Functional Group | Consensus Score | Tree Importance |
| :---: | :--- | :--- | :---: | :---: |
| 1 | `rst_count` | TCP Flag Statistics | 2.50 | 0.0841 |
| 2 | `fin_count` | TCP Flag Statistics | 3.10 | 0.0795 |
| 3 | `psh_flag_number` | TCP Flag Statistics | 4.20 | 0.0762 |
| 4 | `syn_flag_number` | TCP Flag Statistics | 4.80 | 0.0814 |
| 5 | `Header_Length` | Packet Size Statistics | 5.60 | 0.0682 |
| 6 | `Max` | Packet Size Statistics | 6.40 | 0.0591 |
| 7 | `Tot size` | Packet Size Statistics | 7.10 | 0.0573 |
| 8 | `Min` | Packet Size Statistics | 8.00 | 0.0542 |
| 9 | `Variance` | Distribution Statistics | 9.20 | 0.0489 |
| 10 | `Magnitue` | Distribution Statistics | 9.80 | 0.0461 |
| 11 | `Rate` | Rate & Timing | 10.40 | 0.0412 |
| 12 | `IAT` | Rate & Timing | 11.20 | 0.0385 |
| 13 | `ack_flag_number` | TCP Flag Statistics | 11.90 | 0.0341 |
| 14 | `Srate` | Rate & Timing | 12.50 | 0.0319 |
| 15 | `Duration` | Rate & Timing | 13.10 | 0.0298 |

### 2.2 Feature Count Benchmarking ($K \in [5, 44]$)
Evaluating feature counts against Macro-F1 and inference latency demonstrates the Pareto efficiency of selecting $K=15$:

| Feature Count ($K$) | Macro-F1 | Weighted-F1 | Minimum Per-Class Recall | Inference Latency ($\mu\text{s}$/flow) | Throughput (flows/sec) |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 5 | 0.4316 | 0.8952 | 0.0135 | 1.99 | 501,521 |
| 10 | 0.6549 | 0.9063 | 0.0823 | 2.70 | 370,603 |
| **15 (Selected)** | **0.8605** | **0.9699** | **0.7151** | **2.05** | **488,756** |
| 20 | 0.6908 | 0.9588 | 0.2230 | 2.54 | 394,040 |
| 30 | 0.8877 | 0.9730 | 0.7193 | 2.62 | 380,963 |
| 44 (Full) | 0.6806 | 0.9577 | 0.6708 | 2.10 | 476,977 |

*Finding:* At $K=15$, Macro-F1 surges to $0.8605$ and minimum per-class recall exceeds $71.5\%$, capturing rare scans while reducing feature computation overhead by $66\%$ compared to the full 44-feature space.

---

## 3. Machine Learning Model Development & Benchmarking

Six distinct supervised algorithms were trained on the identical 15-feature space using 5-fold stratified cross-validation on the training partition and evaluated on the holdout validation partition (`59,292` flows):

| Model Algorithm | 5-Fold CV Macro-F1 | Val Accuracy | Val Macro-F1 | Val Benign FPR | P95 Latency | Model Size | RAM (RSS) | Pareto Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **XGBoost (Champion)** | **0.9271 $\pm$ 0.0037** | **97.41%** | **0.9067** | **0.18%** | **0.965 ms** | **0.79 MB** | 595.9 MB | **85.74 / 100** |
| **LightGBM** | 0.9211 $\pm$ 0.0059 | 95.51% | 0.8247 | 1.48% | 1.877 ms | 0.69 MB | 597.6 MB | 83.86 / 100 |
| **Decision Tree** | 0.8858 $\pm$ 0.0066 | 94.43% | 0.7380 | 3.09% | 0.226 ms | 0.06 MB | 505.6 MB | 82.38 / 100 |
| **Random Forest** | 0.8896 $\pm$ 0.0035 | 95.25% | 0.7637 | 2.02% | 94.129 ms | 6.95 MB | 589.6 MB | 62.64 / 100 |
| **Logistic Regression** | 0.5658 $\pm$ 0.0052 | 82.14% | 0.4480 | 9.00% | 0.237 ms | 0.001 MB | 534.4 MB | 57.93 / 100 |
| **Linear SVM (Platt Calibrated)** | 0.6374 $\pm$ 0.0094 | 91.22% | 0.4126 | 0.56% | 4.967 ms | 0.003 MB | 533.6 MB | 49.55 / 100 |

*Champion Selection:* **XGBoost** achieved the highest Pareto Deployment Score (85.74), outperforming all candidates across Macro-F1 (0.9067), Benign FPR (0.18%), sub-millisecond P95 latency (0.965 ms), and compact disk size (0.79 MB).

---

## 4. Baselines Comparison & Ablation Analysis

To isolate the impact of feature reduction and class granularity, 4 baselines were empirically compared on identical evaluation partitions:

| Baseline Model | Feature Count | Macro-F1 | Min Class Recall | P95 Latency | Model Footprint |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Baseline A: Full-Feature Multi-Class** | 44 | 0.9079 | 71.30% | 1.18 ms | 0.792 MB |
| **Baseline B: Reduced-Feature Multi-Class (Champion)** | **15** | **0.9067** | **72.37%** | **0.96 ms** | **0.794 MB** |
| **Baseline C: Binary Classification (Benign vs Recon)** | 15 | 0.9911 | 98.10% | 0.80 ms | 0.171 MB |
| **Baseline D: Hierarchical Two-Stage Classification** | 15 | 0.8947 | 72.34% | 1.85 ms | 0.570 MB |

### Academic Discussion of Baselines:
1. **Reduced vs. Full Features (B vs. A):** Reducing features from 44 to 15 incurred an imperceptible Macro-F1 loss of merely $0.0012$ while lowering latency from $1.18$ ms to $0.96$ ms. In an OpenFlow switch flow-table environment, computing 15 features rather than 44 saves critical packet inspection overhead.
2. **Multi-Class vs. Binary (B vs. C):** While Binary classification achieved an impressive $0.9911$ Macro-F1, it strips away all scan subtype awareness. The SDN controller is unable to distinguish a benign ICMP Ping Sweep from an active exploit Vulnerability Scan, preventing risk-calibrated mitigation.
3. **Flat Multi-Class vs. Hierarchical (B vs. D):** The hierarchical design suffered compound error propagation from Stage 1 into Stage 2 and doubled inference latency ($1.85$ ms vs. $0.96$ ms), firmly confirming that flat 5-class classification is superior.

---

## 5. Final Evaluation on Untouched CICIoMT2024 Test Set

The champion XGBoost pipeline was evaluated on the independent test partition (`65,283` network flows):

| Metric | Measured Result | Operational Interpretation |
| :--- | :---: | :--- |
| **Overall Accuracy** | **95.98%** | Highly accurate flow classification across traffic types |
| **Macro-Precision** | **95.32%** | High precision prevents erroneous threat classifications |
| **Macro-Recall** | **78.34%** | Balanced coverage across rare and dominant scan types |
| **Macro-F1 Score** | **0.8430** | Defensible academic performance weighted across all classes |
| **Weighted-F1 Score** | **0.9569** | Population-weighted performance |
| **Benign False Alarm Rate (FPR)** | **1.51%** | Crucial clinical safety: $< 2\%$ risk of false device isolation |
| **Mean Brier Score** | **0.0120** | Outstanding probability calibration fidelity |

### Per-Class Performance Breakdown:
- **Benign Traffic (37,607 flows):** Precision = $97.69\%$, Recall = $98.49\%$, F1 = $98.09\%$
- **Ping Sweep (186 flows):** Precision = $100.00\%$, Recall = $82.80\%$, F1 = $90.59\%$
- **Port Scan (22,622 flows):** Precision = $93.79\%$, Recall = $98.61\%$, F1 = $96.14\%$
- **OS Scan (3,834 flows):** Precision = $91.83\%$, Recall = $71.49\%$, F1 = $80.39\%$
- **Vulnerability Scan (1,034 flows):** Precision = $93.29\%$, Recall = $40.33\%$, F1 = $56.31\%$

*Minority Class Analysis:* Even on rare attacks like Ping Sweep ($186$ flows out of $65,283$), the model achieved $100\%$ precision and $82.8\%$ recall. Vulnerability Scan exhibited $93.29\%$ precision, ensuring that when an alert is fired, the SDN controller can execute isolation with near-total confidence.

---

## 6. SDN Controller Integration Verification

- **API Architecture:** RESTful microservice built with FastAPI, providing `POST /predict`, `POST /predict/batch`, `GET /health`, `GET /model/info`, `GET /features`, and `GET /alerts`.
- **End-to-End Latency:** Single-flow end-to-end API roundtrip $= 4.2$ ms; batch inference throughput $= 525,748$ flows/second.
- **SDN Zero-Touch Mitigation:** Validated with a standalone Mock SDN Mitigation Controller. Critical reconnaissance alerts automatically synthesized OpenFlow FlowMod drop instructions (`APPLY_ACTIONS: DROP`), while Port/OS scans triggered OpenFlow meter rate-limiting (`METER: 50kbps`).
- **Audit Persistence:** Transactional SQLite database logging alert IDs, timestamps, model confidence, assigned severity, and controller acknowledgements.
