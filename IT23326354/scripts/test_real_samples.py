import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
from src.preprocessing.loader import load_from_zip
from app.predictor import DoSPredictor

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = PROJECT_ROOT / "models" / "xgboost_model.joblib"
PREPROCESSOR_PATH = PROJECT_ROOT / "models" / "preprocessor.joblib"
SCHEMA_PATH = PROJECT_ROOT / "configs" / "feature_schema.json"

print("Loading test samples directly from dataset...")
# Load a small slice with benign rows
df = load_from_zip(
    PROJECT_ROOT / "data" / "raw" / "CICIoMT2024 DataSets.zip",
    "test_iomt.csv",
    nrows=150000
)

benign_df = df[df["label"].astype(str).str.strip().str.lower() == "benign"]
dos_df = df[df["label"].astype(str).str.strip().str.startswith(("DoS", "DDoS"))]

print(f"Found {len(benign_df)} benign samples and {len(dos_df)} DoS samples in test slice.")

predictor = DoSPredictor(MODEL_PATH, PREPROCESSOR_PATH, SCHEMA_PATH)

if len(benign_df) > 0:
    b_sample = benign_df.iloc[0].to_dict()
    label_actual = b_sample.pop("label")
    res = predictor.predict(b_sample)
    print("\n--- Genuine Benign Test Sample ---")
    print(f"Actual Label     : {label_actual}")
    print(f"Predicted Class  : {res['prediction']}")
    print(f"Is DoS           : {res['is_dos']}")
    print(f"Confidence       : {res['confidence']*100:.2f}%")
    print(f"Inference Latency: {res['inference_latency_ms']:.3f} ms")

if len(dos_df) > 0:
    d_sample = dos_df.iloc[0].to_dict()
    label_actual = d_sample.pop("label")
    res = predictor.predict(d_sample)
    print("\n--- Genuine DoS Test Sample ---")
    print(f"Actual Label     : {label_actual}")
    print(f"Predicted Class  : {res['prediction']}")
    print(f"Is DoS           : {res['is_dos']}")
    print(f"Confidence       : {res['confidence']*100:.2f}%")
    print(f"Inference Latency: {res['inference_latency_ms']:.3f} ms")
