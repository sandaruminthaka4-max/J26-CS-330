# Implementation Plan & Roadmap

**Project:** Multi-Class Reconnaissance Attack Detection for IoMT Networks (CICIoMT2024)  
**Author:** Bandara B.R.K.Y (IT23285224)  
**Supervisor Alignment:** SLIIT 4th Year Cyber Security Capstone (J26-CS-330)  

---

## 1. Phase Breakdown & Execution Milestones

### Phase 1: Research Analysis & Project Planning
- [x] Read and deconstruct research proposal `IT23285224 Proposal Report (2).pdf`.
- [x] Inspect raw archive `CICIoMT2024 DataSets.zip` and verify dataset schema and class distributions.
- [x] Formulate `REQUIREMENTS.md` and Requirements Traceability Matrix.
- [x] Formulate `ARCHITECTURE.md` with component boundaries and Mermaid diagrams.
- [x] Formulate `IMPLEMENTATION_PLAN.md` with explicit phase deliverables.
- [x] Formulate `RESEARCH_DECISIONS.md` documenting academic justifications.
- [x] Initialize `DEVELOPMENT_LOG.md` for live progress tracking.

### Phase 2: Project Structure & Environment Setup
- [ ] Establish directory structure matching specification (`data/`, `src/`, `scripts/`, `configs/`, `models/`, `results/`, `tests/`, `docs/`).
- [ ] Configure `requirements.txt`, `pyproject.toml`, `.env.example`, and `.gitignore`.
- [ ] Verify environment dependencies and provide cross-platform startup instructions (Windows PowerShell / Linux Bash).

### Phase 3: CICIoMT2024 Dataset Ingestion & Extraction
- [ ] Create chunked extraction script for `train_iomt.csv` and `test_iomt.csv`.
- [ ] Filter strictly relevant traffic: `benign`, `Port Scan`, `OS Scan`, `Recon VulScan`, `Ping Sweep`.
- [ ] Establish formal label mapping to 5 canonical target classes:
  - `benign` $\to$ `Benign`
  - `Ping Sweep` $\to$ `Ping Sweep`
  - `Port Scan` $\to$ `Port Scan`
  - `OS Scan` $\to$ `OS Scan`
  - `Recon VulScan` $\to$ `Vulnerability Scan`
- [ ] Generate `data/dataset_manifest.json` with source files, record counts, and SHA-256 hashes.

### Phase 4: Data Preprocessing & Leakage Control
- [ ] Handle missing and `inf` values using median imputation fit exclusively on training sets.
- [ ] Identify and drop constant or zero-variance features.
- [ ] Implement strict data leakage controls: guarantee flow identifiers or duplicates do not cross train/val/test splits.
- [ ] Compute class distributions and generate initial exploration figures.
- [ ] Export sanitized training, validation, and test partitions to `data/processed/`.

### Phase 5: Feature Engineering & Selection Study
- [ ] Evaluate candidate feature groups: rates/timings, TCP flags, protocol indicators, packet size statistics, distribution stats.
- [ ] Implement and evaluate 4 feature selection algorithms:
  - Mutual Information (MI)
  - Non-negative Chi-Square ($\chi^2$)
  - Embedded Tree Importance (Random Forest Gini/Gain)
  - Recursive Feature Elimination (RFE)
- [ ] Benchmark feature subsets at $K \in [5, 10, 15, 20, 30]$ against Macro-F1 and inference latency.
- [ ] Export final selected feature set manifest to `configs/selected_features.json`.

### Phase 6: Machine Learning Model Development & Tuning
- [ ] Implement 6 candidate classifiers:
  1. Decision Tree (DT)
  2. Logistic Regression (LR)
  3. Linear Support Vector Machine (Linear SVM)
  4. Random Forest (RF)
  5. XGBoost
  6. LightGBM
- [ ] Execute 5-fold stratified cross-validation on the training partition.
- [ ] Implement class imbalance remediation (class weighting `balanced` and calibrated focal weighting).
- [ ] Calibrate probability outputs via Platt Scaling / Isotonic Regression.

### Phase 7: Baseline Implementations & Comparative Studies
- [ ] Implement Baseline A: Full-Feature Multi-Class Model (all 45 features).
- [ ] Implement Baseline B: Reduced-Feature Multi-Class Model (Top-$K$ selected features).
- [ ] Implement Baseline C: Binary Benign vs. Reconnaissance Classifier.
- [ ] Implement Baseline D: Hierarchical Classifier (Stage 1: Benign vs Recon $\to$ Stage 2: 4 Subtypes).
- [ ] Compare detection fidelity, computational latency, and model footprint.

### Phase 8: Deployment Scorecard & Comprehensive Evaluation
- [ ] Evaluate on untouched test partition:
  - Accuracy, Precision, Recall, F1, Macro-F1, Weighted-F1, FPR.
  - Per-class metrics and confusion matrix breakdown.
- [ ] Profile lightweight deployment metrics:
  - Serialized model size on disk (MB).
  - Single-instance and batch inference latency (Median, P95).
  - Peak CPU utilization and resident set memory (RSS MB).
  - Prediction throughput (flows/second).
- [ ] Select champion model via multi-criteria Pareto Deployment Scorecard.
- [ ] Save packaged pipeline artifact (`models/champion_pipeline.joblib`).

### Phase 9: REST Prediction API Development
- [ ] Build FastAPI microservice with asynchronous endpoints:
  - `GET /health`
  - `GET /model/info`
  - `GET /features`
  - `POST /predict`
  - `POST /predict/batch`
  - `GET /alerts`
  - `GET /alerts/{alert_id}`
  - `GET /metrics`
- [ ] Enforce Pydantic validation and feature order checks.
- [ ] Implement structured JSON logging and API key authentication for protected operations.

### Phase 10: Confidence-Aware Alerting System
- [ ] Build risk calculation engine combining predicted subtype, calibrated confidence, and device criticality.
- [ ] Establish alert states: `CONFIRMED`, `LOW_CONFIDENCE`, `PENDING_REVIEW`, `MITIGATION_ELIGIBLE`.
- [ ] Persist alerts in local SQLite database with repository abstraction.

### Phase 11: SDN Mitigation Integration & Mock Controller
- [ ] Implement SDN Webhook Dispatcher with retry policy and duplicate suppression.
- [ ] Develop standalone Mock Mitigation Controller simulating OpenFlow flow-mod logic and quarantine rule generation.
- [ ] Conduct end-to-end integration tests: Ingestion $\to$ Inference $\to$ Severity $\to$ Webhook Dispatch $\to$ Mock Controller ACK.

### Phase 12: Demonstration Dashboard
- [ ] Build interactive, lightweight web dashboard interface for live viva demonstration.
- [ ] Display model status, interactive single/batch test flows, live alerts, and performance metrics.

### Phase 13: Comprehensive Automated Testing & Quality Assurance
- [ ] Write unit, integration, and end-to-end tests across all modules.
- [ ] Verify reproducible execution with `pytest`.

### Phase 14: Reproducible Experiment Automation
- [ ] Provide CLI scripts for complete pipeline reproduction: extraction, preprocessing, selection, training, evaluation, and API launch.

### Phase 15: Academic Research Outputs
- [ ] Generate publication-grade figures (confusion matrices, ROC curves, feature importance, latency vs F1 trade-offs) and LaTeX/Markdown tables.
- [ ] Document research limitations, ablation studies, and defense talking points.

### Phase 16: Complete System Documentation
- [ ] Comprehensive `README.md` with architecture diagrams, setup commands, API examples, and Viva walkthrough.

### Phase 17: Final Verification & Implementation Report
- [ ] Verify all automated tests pass.
- [ ] Generate `FINAL_IMPLEMENTATION_REPORT.md`.
