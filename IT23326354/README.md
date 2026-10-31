# DoS Detection via SDN Flow Analysis
**Group Project:** Lightweight SDN Intrusion Detection and Zero-Touch Mitigation System for IoMT Networks  
**Individual Component:** DoS Detection via SDN Flow Analysis  
**Project ID:** J26-CS-330  
**Student ID:** IT23326354  

---

## 1. Component Overview
This component implements an intelligent, lightweight machine learning engine for detecting Denial of Service (DoS/DDoS) attacks in Software-Defined Internet of Medical Things (IoMT) networks.

It operates strictly on **flow-level metadata** (OpenFlow statistics counters and header fields) without inspecting packet payloads, ensuring patient data privacy (HIPAA compliance) and minimal computational overhead. Predictions and confidence probabilities are served via a high-performance **FastAPI REST API** to the automated Zero-Touch Mitigation Component.

---

## 2. Project Architecture & Structure

```
dos-sdn-detection/
├── configs/
│   ├── feature_schema.json           # Frozen 45-feature schema
│   └── model_config.yaml             # Hyperparameters, paths & seeds
├── data/
│   ├── raw/                          # Raw datasets
│   ├── interim/                      # Cleaned intermediate files
│   └── processed/                    # Partitioned train/val/test sets
├── models/
│   ├── xgboost_model.joblib          # Trained production XGBoost artifact
│   ├── preprocessor.joblib           # Encoders & scaling artifacts
│   └── metadata.json                 # Training provenance metadata
├── src/
│   ├── preprocessing/
│   │   ├── loader.py                 # Memory-safe ZIP/CSV streaming
│   │   └── cleaner.py                # Null/inf handling & label encoding
│   ├── features/
│   │   └── extractor.py              # OpenFlow-to-CICIoMT feature bridge
│   ├── training/
│   │   ├── baseline.py               # Decision Tree & RF baselines
│   │   └── train.py                  # Full reproducible training pipeline
│   └── evaluation/
│       └── evaluator.py              # Latency, ROC, & metric visualizations
├── app/
│   ├── main.py                       # FastAPI application
│   ├── predictor.py                  # In-memory single-pass inference engine
│   └── schemas.py                    # Pydantic request/response validation
├── tests/
│   ├── test_preprocessing.py         # Data cleaning tests
│   ├── test_features.py              # Feature schema alignment tests
│   ├── test_model.py                 # Latency & artifact loading tests
│   └── test_api.py                   # FastAPI endpoint tests
├── results/
│   ├── figures/                      # Confusion matrices, ROC curves, latency histograms
│   ├── tables/                       # Benchmark comparison CSVs
│   └── logs/                         # Training & service execution logs
├── docs/
│   └── mitigation_integration_contract.md # API specification for teammate
├── requirements.txt
└── README.md
```

---

## 3. Installation & Quick Start

### Prerequisites
- Python 3.11+
- Virtual environment (`.venv`)

### Setup Environment
```bash
# Activate existing virtual environment
# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1

# Install dependencies:
pip install -r requirements.txt
```

---

## 4. Model Training Pipeline

To train the baseline models and the production XGBoost classifier on the CICIoMT2024 dataset:

```bash
# Run full reproducible training:
python src/training/train.py --config configs/model_config.yaml

# For a quick test run using a sample subset (e.g. 50,000 flows):
python src/training/train.py --config configs/model_config.yaml --sample 50000
```

All trained artifacts are automatically saved to `models/` and evaluation charts are generated in `results/figures/`.

---

## 5. Running the Detection REST API

Start the FastAPI microservice:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

- **Interactive API Documentation (Swagger UI):** `http://localhost:8000/docs`
- **Health Check Endpoint:** `http://localhost:8000/health`
- **Prediction Endpoint:** `http://localhost:8000/predict`

---

## 6. Running Automated Tests

Run the test suite with pytest:
```bash
pytest tests/ -v
```

---

## 7. Performance Targets vs Actuals

| Metric | Research Proposal Target | Status |
|---|---|---|
| **Classification Accuracy** | > 95.0% | Evaluated upon training |
| **F1-Score** | > 95.0% | Evaluated upon training |
| **Inference Latency** | < 50.0 ms | Measured per prediction |
| **False Positive Rate** | Minimal (< 2.0%) | Monitored to prevent false mitigation |

---

## 8. Integration Boundary
This component terminates at the output of the `/predict` endpoint. Zero-touch flow rule enforcement and mitigation policies are handled by the mitigation module according to [mitigation_integration_contract.md](docs/mitigation_integration_contract.md).
