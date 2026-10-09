"""
Stage 3 — MQTT Protocol Anomaly & MITM-Suspicion Detection Training
===================================================================
Trained on CICIoMT2024 (WiFi + MQTT subset).

Evaluates:
  - Normal (Benign traffic)
  - Suspicious (Attacks: ARP_Spoofing, MQTT-Malformed_Data, Floods, etc.)
  - Highlights MITM-enabling attack vectors (ARP Spoofing, MQTT Malformed Data)

Outputs:
  - models/anomaly_detector.joblib
  - reports/anomaly_detector_report.txt
  - reports/figures/anomaly_confusion_matrix.png
  - reports/figures/anomaly_feature_importance.png
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent))

import logging
import time
import warnings

import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, ConfusionMatrixDisplay
)
from sklearn.pipeline import Pipeline

from config import CICIOMT2024_TEST_CSV, MDL_DIR, RPT_DIR, FIG_DIR

warnings.filterwarnings("ignore")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

SHARED_FEATURES = [
    'Header_Length', 'Protocol Type', 'Duration', 'Rate', 'Srate', 'Drate',
    'fin_flag_number', 'syn_flag_number', 'rst_flag_number', 'psh_flag_number',
    'ack_flag_number', 'ece_flag_number', 'cwr_flag_number', 'ack_count',
    'syn_count', 'fin_count', 'rst_count', 'HTTP', 'HTTPS', 'DNS', 'Telnet',
    'SMTP', 'SSH', 'IRC', 'TCP', 'UDP', 'DHCP', 'ARP', 'ICMP', 'IPv', 'LLC',
    'Tot sum', 'Min', 'Max', 'AVG', 'Std', 'Tot size', 'IAT', 'Number',
    'Magnitue', 'Radius', 'Covariance', 'Variance', 'Weight'
]

def load_balanced_iomt_data():
    log.info(f"Loading representative subset from {CICIOMT2024_TEST_CSV.name}...")
    df = pd.read_csv(CICIOMT2024_TEST_CSV, low_memory=False)
    
    # Stratified/balanced sampling across attack types to prevent DDoS dominance
    sampled_frames = []
    for label_name, group in df.groupby("label"):
        n_sample = min(len(group), 8_000) # sample up to 8,000 per class
        sampled_frames.append(group.sample(n=n_sample, random_state=42))
        
    df_sample = pd.concat(sampled_frames, ignore_index=True)
    log.info(f"Sampled {len(df_sample):,} records across {df['label'].nunique()} attack types.")
    
    # Binary Label: 0 = Normal (Benign), 1 = Suspicious (Any anomaly/attack)
    df_sample['anomaly_label'] = df_sample['label'].apply(
        lambda x: 0 if "benign" in str(x).lower() else 1
    )
    
    # Clean features
    for col in SHARED_FEATURES:
        if col in df_sample.columns:
            df_sample[col] = pd.to_numeric(df_sample[col], errors='coerce')
        else:
            df_sample[col] = 0.0
            
    df_sample.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_sample.dropna(subset=SHARED_FEATURES, inplace=True)
    for col in SHARED_FEATURES:
        df_sample[col] = df_sample[col].clip(-1e9, 1e9)
        
    return df_sample

def main():
    log.info("=" * 60)
    log.info("  Stage 3: Training MQTT Anomaly & MITM-Suspicion Detector")
    log.info("=" * 60)
    
    df = load_balanced_iomt_data()
    feature_cols = [c for c in SHARED_FEATURES if c in df.columns]
    
    X = df[feature_cols].values.astype(np.float32)
    y = df['anomaly_label'].values.astype(int)
    
    log.info(f"Normal samples: {(y == 0).sum():,} | Suspicious samples: {(y == 1).sum():,}")
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    
    log.info("Fitting Random Forest Model for Protocol Anomaly Detection...")
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=100,
            max_depth=22,
            min_samples_split=6,
            class_weight="balanced",
            n_jobs=-1,
            random_state=42
        ))
    ])
    
    pipeline.fit(X_train, y_train)
    log.info("Model training finished!")
    
    # Evaluation
    start_time = time.perf_counter()
    y_pred = pipeline.predict(X_test)
    eval_latency = (time.perf_counter() - start_time) * 1000 / len(X_test)
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average="binary")
    rec = recall_score(y_test, y_pred, average="binary")
    f1 = f1_score(y_test, y_pred, average="binary")
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    
    log.info("=" * 60)
    log.info(f"  Accuracy             : {acc:.4f}")
    log.info(f"  Precision            : {prec:.4f}")
    log.info(f"  Recall               : {rec:.4f}")
    log.info(f"  F1-Score             : {f1:.4f}")
    log.info(f"  False Positive Rate  : {fpr:.4f}")
    log.info(f"  Inference Latency    : {eval_latency:.3f} ms / sample")
    log.info("=" * 60)
    
    report_text = f"""============================================================
MQTT ANOMALY & MITM-SUSPICION DETECTOR — EVALUATION REPORT (Stage 3)
Dataset: CICIoMT2024
============================================================
Accuracy             : {acc:.4f}
Precision            : {prec:.4f}
Recall               : {rec:.4f}
F1-Score             : {f1:.4f}
False Positive Rate  : {fpr:.4f}
Inference Latency    : {eval_latency:.3f} ms / sample

Classification Report:
{classification_report(y_test, y_pred, target_names=['Normal', 'Suspicious'])}

Confusion Matrix (Normal, Suspicious):
{cm}

NOTE ON MITM:
'Suspicious' detects MITM-enabling patterns (ARP Spoofing, MQTT Malformed Data)
and other IoMT attacks. Predictions should be interpreted as Suspicious behavior,
not definitive proof of Man-in-the-Middle traffic.
============================================================
"""
    rpt_file = RPT_DIR / "anomaly_detector_report.txt"
    rpt_file.write_text(report_text, encoding="utf-8")
    log.info(f"Saved evaluation report: {rpt_file}")
    
    # Save Confusion Matrix figure
    fig, ax = plt.subplots(figsize=(6, 5))
    ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=['Normal', 'Suspicious']).plot(
        ax=ax, cmap="Reds", colorbar=True
    )
    ax.set_title("Anomaly Detector — Confusion Matrix", fontweight="bold")
    plt.tight_layout()
    cm_path = FIG_DIR / "anomaly_confusion_matrix.png"
    plt.savefig(cm_path, dpi=150)
    plt.close()
    
    # Save Model
    model_obj = {
        "model": pipeline,
        "feature_cols": feature_cols,
        "version": "v1.0.0-stage3-anomaly",
        "dataset": "CICIoMT2024",
        "label_mapping": {0: "Normal", 1: "Suspicious"},
        "inference_latency_ms": round(eval_latency, 3),
        "metrics": {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1, "fpr": fpr}
    }
    model_path = MDL_DIR / "anomaly_detector.joblib"
    joblib.dump(model_obj, model_path)
    log.info(f"Saved model to: {model_path}")
    log.info("Stage 3 Completed Successfully!")

if __name__ == "__main__":
    main()
