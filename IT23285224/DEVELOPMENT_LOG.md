# Development Activity & Audit Log

**Project:** Lightweight SDN Intrusion Detection & Zero-Touch Mitigation System for IoMT Networks  
**Component:** Multi-Class Reconnaissance Attack Detection  
**Author:** Bandara B.R.K.Y (IT23285224)  

---

## Log Entries

### Entry 001 — Initial Analysis & Workspace Deconstruction
- **Timestamp:** 2026-10-17T08:20:00+05:30
- **Activity:** Extracted and parsed project proposal `IT23285224 Proposal Report (2).pdf` (36 pages) and verified dataset archive `CICIoMT2024 DataSets.zip`.
- **Findings:**
  - Raw archive contains `train_iomt.csv` (1.7 GB, 7,160,831 rows) and `test_iomt.csv` (377 MB, 1,614,182 rows).
  - Exact 46-feature schema verified.
  - Class distribution verified:
    - Benign: 192,732 (train) + 37,607 (test) = 230,339 flows
    - Port Scan: 83,981 (train) + 22,622 (test) = 106,603 flows
    - OS Scan: 16,832 (train) + 3,834 (test) = 20,666 flows
    - Recon VulScan: 2,173 (train) + 1,034 (test) = 3,207 flows
    - Ping Sweep: 740 (train) + 186 (test) = 926 flows
  - The four reconnaissance subtypes and benign traffic total 361,741 relevant flows.
  - Severe class imbalance observed for `Ping Sweep` and `Recon VulScan`, validating the proposal's emphasis on macro-F1 and cost-sensitive evaluation.

### Entry 002 — Phase 1 Planning Artifacts Generated
- **Timestamp:** 2026-10-17T08:26:00+05:30
- **Activity:** Completed requirements deconstruction, system architecture specification, implementation plan, and research decisions.
- **Artifacts:**
  - `REQUIREMENTS.md` (Traceability Matrix, FRs, NFRs)
  - `ARCHITECTURE.md` (Component decomposition, Mermaid diagrams, API flows)
  - `IMPLEMENTATION_PLAN.md` (17-phase execution roadmap)
  - `RESEARCH_DECISIONS.md` (Academic justifications RD-01 through RD-07)
  - `DEVELOPMENT_LOG.md` (Chronological progress tracking)

### Entry 003 — Dataset Extraction & Preprocessing (Phases 2-4)
- **Timestamp:** 2026-10-17T08:34:00+05:30
- **Activity:** Executed streaming extraction of CICIoMT2024 archive; computed SHA-256 digest `8da94655b1b6ab4025175cf525381f185ef35beff09849206d2139049e3fa6db`.
- **Findings:**
  - `data/dataset_manifest.json` generated.
  - Data leakage audit identified `Drate` as a constant feature (zero variance). Preprocessor fitted strictly on training data automatically dropped `Drate`.
  - Partitions exported: Train (`237,166`), Validation (`59,292`), and untouched Test (`65,283`).
  - Generated `results/figures/class_distribution.png` and `results/tables/class_distribution.csv`.

### Entry 004 — Feature Selection Study (Phase 5)
- **Timestamp:** 2026-10-17T08:37:00+05:30
- **Activity:** Implemented Mutual Information, Chi-Square, Tree Importance (MDI), and RFE.
- **Findings:**
  - Weighted consensus ranking identified top-15 discriminative features spanning rates, flags, packet sizes, and distributions.
  - Benchmarked $K \in [5, 10, 15, 20, 30, 44]$. Selecting $K=15$ yielded Macro-F1 = 0.8605, Min-Recall = 0.7151, and Latency = 2.05 us/flow, proving Pareto superiority.
  - Generated `results/figures/feature_importance.png`, `results/figures/feature_count_vs_performance.png`, and `configs/selected_features.json`.

### Entry 005 — Model Benchmarking, Baselines & Test Evaluation (Phases 6-8)
- **Timestamp:** 2026-10-17T08:43:00+05:30
- **Activity:** Trained 6 algorithms with 5-fold CV; evaluated Baselines A, B, C, D; profiled deployment metrics.
- **Findings:**
  - **XGBoost selected as Champion** with Deployment Score of 85.74 / 100.
  - Baseline B (Reduced 15 Features) achieved Macro-F1 = 0.9067 and P95 latency = 0.96 ms, outperforming Full-Feature Baseline A (1.18 ms) with 66% fewer features.
  - Baseline C (Binary) confirmed high F1 (0.9911) but total loss of scan subtype granularity.
  - Baseline D (Hierarchical) exhibited compound stage errors and double latency (1.85 ms).
  - Evaluated on untouched test partition (`65,283` flows):
    - Overall Accuracy: **95.98%**
    - Macro-F1: **0.8430**
    - Benign FPR: **1.51%**
    - Mean Brier Score: **0.0120**
  - Generated `results/figures/confusion_matrix.png`, `results/tables/model_benchmark_comparison.csv`, `results/tables/baselines_comparison.csv`, and `results/tables/final_test_report.json`.

### Entry 006 — API, SDN Webhook, Dashboard & 100% Test Pass (Phases 9-17)
- **Timestamp:** 2026-10-17T09:05:00+05:30
- **Activity:** Built FastAPI microservice, SQLite alert repository, SDN mitigation client, mock controller, and live demonstration dashboard.
- **Findings:**
  - Built interactive Vanilla HTML5/CSS3/JS dashboard at `src/dashboard/` mounted on `/`.
  - Executed automated Pytest suite: **19/19 tests passed** (100% pass rate).
  - Published `README.md`, `ACADEMIC_RESULTS_TEMPLATE.md`, and `FINAL_IMPLEMENTATION_REPORT.md`.
