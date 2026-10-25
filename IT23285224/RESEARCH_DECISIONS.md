# Academic Research Decisions & Justifications

**Project:** Multi-Class Reconnaissance Attack Detection for IoMT Networks  
**Student:** Bandara B.R.K.Y (IT23285224)  
**Supervisor Alignment:** SLIIT 4th Year Cyber Security Capstone (J26-CS-330)  

---

## 1. Research Decision Log

### RD-01: Dataset Selection — Official CICIoMT2024 Benchmark
- **Decision:** Use the Canadian Institute for Cybersecurity IoMT 2024 dataset (`CICIoMT2024`) as the primary experimental dataset.
- **Academic Justification:** Generic IoT datasets (such as CIC-IoT 2023 or BoT-IoT) feature generic smart-home or industrial devices whose packet size distributions, flow rates, and protocol mixtures diverge significantly from medical telemetry equipment (e.g., infusion pumps, ECG monitors, pulse oximeters). Doménech et al. (2025) demonstrated that IDS models trained on generic IoT experience severe performance degradation when transferred to healthcare IoMT environments. CICIoMT2024 contains realistic multi-protocol captures (Wi-Fi, MQTT, Bluetooth) across 40 real and simulated IoMT devices.

### RD-02: Target Taxonomy — Five-Class Multi-Class Granularity
- **Decision:** Formulate the primary classification task as a 5-class problem:
  1. `Benign`
  2. `Ping Sweep`
  3. `Port Scan`
  4. `OS Scan`
  5. `Vulnerability Scan` (labeled as `Recon VulScan` in CICIoMT2024)
- **Academic Justification:** Existing literature predominantly treats reconnaissance as a monolithic binary class or lumps all scanning under one generic tag (Sharma et al., 2024). In an SDN-enabled IoMT network, treating all scanning identically leads to improper mitigation. For instance, a low-intensity ICMP `Ping Sweep` may warrant dynamic flow monitoring or decoy redirection, whereas an aggressive `Vulnerability Scan` probing known buffer overflows requires immediate flow quarantine of the attacking IP. Fine-grained classification directly empowers the zero-touch SDN mitigation engine to execute proportional mitigation.

### RD-03: Scope Boundary & Focused Research Problem
- **Decision:** Filter out DDoS, DoS, MQTT publish/connect floods, and ARP spoofing flows, focusing exclusively on Benign and Reconnaissance attack vectors.
- **Academic Justification:** High-volume flooding attacks (DDoS) are easily detected via packet rate thresholds, whereas subtle reconnaissance scans deliberately evade volume-based anomaly detectors. Isolating reconnaissance allows dedicated exploration of subtle scanning signatures (TCP flag combinations, packet length variances, inter-arrival timings) without diluting model capacity with flood-dominated training distributions. This delivers a dedicated, highly specialized first line of defense tailored specifically for IoMT medical environments.

### RD-04: Prevention of Data Leakage
- **Decision:**
  1. Omit all flow identifiers, IP addresses, MAC addresses, port numbers, timestamps, and session identifiers from model training.
  2. Perform all missing value imputation, scaling, and feature selection strictly inside cross-validation training folds.
  3. Enforce deduplication and flow grouping so duplicate flow signatures never cross train/validation/test partitions.
- **Academic Justification:** Literature reviews (Sharma et al., 2024; Zhang et al., 2026) emphasize that high reported IDS accuracies are frequently artifacts of temporal or identifier leakage. A model that memorizes an attacker's IP address or a specific timestamp achieves near-perfect test scores but fails entirely in deployment.

### RD-05: Feature Reduction Methodology
- **Decision:** Benchmark 4 feature selection paradigms: Mutual Information (MI), Non-Negative Chi-Square ($\chi^2$), Embedded Tree Importance, and Recursive Feature Elimination (RFE) across feature subsets $K \in [5, 10, 15, 20, 30]$.
- **Academic Justification:** Palaniappan & Sengan (2026) and Albulayhi et al. (2022) highlighted that computing dozens of statistical features per packet in real-time introduces unacceptable latency in SDN flow processors. Identifying a compact subset of $\le 15$ features minimizes flow switch telemetry overhead while preserving discrimination across scan subtypes.

### RD-06: Classifier Selection & Deployment Scorecard
- **Decision:** Implement and profile 6 diverse algorithms: Decision Tree (DT), Logistic Regression (LR), Linear SVM, Random Forest (RF), XGBoost, and LightGBM. Designate the production model using a Pareto Deployment Scorecard rather than accuracy alone.
- **Academic Justification:** In medical cyber-physical networks, total accuracy is deceptive due to massive class imbalance (Ping Sweep is $< 1\%$ of data). Minimum per-class recall prevents rare scans from being ignored. Furthermore, the SDN controller operates with strict latency budgets ($< 100$ ms); an ultra-heavy ensemble that adds 0.2% accuracy at the expense of a 500 ms latency spike is unacceptable for real-time mitigation.

### RD-07: Confidence Calibration & Rule-Based Severity
- **Decision:** Calibrate raw classifier probability outputs (Platt Scaling) and evaluate expected calibration error before computing risk severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Academic Justification:** Uncalibrated tree or neural network outputs often produce extreme, overconfident probabilities that do not reflect true statistical likelihood. Calibrated probabilities ensure that SDN mitigation actions are triggered only when model certainty justifies network disruption.
