"""
Stage 1 — IoMT Traffic Classifier Training
============================================
Binary Classification: IoMT-associated (1) vs Non-IoMT (0)
Trained on merged CICIoMT2024 + CICIoT2023 dataset.
Outputs:
  - models/iomt_classifier.joblib
  - reports/iomt_classifier_report.txt
  - reports/figures/iomt_confusion_matrix.png
  - reports/figures/iomt_feature_importance.png
"""

import logging
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score,
    ConfusionMatrixDisplay
)
from sklearn.pipeline import Pipeline

from config import PROC_DIR, MDL_DIR, RPT_DIR, FIG_DIR

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

def main():
    data_path = PROC_DIR / "merged_iomt_dataset.csv"
    if not data_path.exists():
        log.error("Merged dataset not found! Run 01_feature_mapping.py first.")
        return

    log.info(f"Loading merged dataset from {data_path}...")
    df = pd.read_csv(data_path, low_memory=False)
    
    feature_cols = [c for c in SHARED_FEATURES if c in df.columns]
    X = df[feature_cols].values.astype(np.float32)
    y = df['iomt_label'].values.astype(int)

    log.info(f"Features count: {len(feature_cols)}, Total records: {len(X):,}")
    log.info("Splitting dataset 80/20 train/test...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    log.info("Training IoMT Classifier (Random Forest)...")
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=10,
            class_weight="balanced",
            n_jobs=-1,
            random_state=42
        ))
    ])

    pipeline.fit(X_train, y_train)
    log.info("Training completed!")

    log.info("Evaluating Model...")
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average="binary")
    rec = recall_score(y_test, y_pred, average="binary")
    f1 = f1_score(y_test, y_pred, average="binary")
    roc_auc = roc_auc_score(y_test, y_proba)
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    log.info("=" * 60)
    log.info(f"  Accuracy           : {acc:.4f}")
    log.info(f"  Precision          : {prec:.4f}")
    log.info(f"  Recall             : {rec:.4f}")
    log.info(f"  F1-Score           : {f1:.4f}")
    log.info(f"  False Positive Rate: {fpr:.4f}")
    log.info(f"  ROC-AUC            : {roc_auc:.4f}")
    log.info("=" * 60)

    # Save reports
    report_text = f"""============================================================
IoMT TRAFFIC CLASSIFIER — EVALUATION REPORT (Stage 1)
Datasets: CICIoMT2024 (IoMT=1) + CICIoT2023 (Non-IoMT=0)
============================================================
Accuracy            : {acc:.4f}
Precision           : {prec:.4f}
Recall              : {rec:.4f}
F1-Score            : {f1:.4f}
False Positive Rate : {fpr:.4f}
ROC-AUC             : {roc_auc:.4f}

Detailed Classification Report:
{classification_report(y_test, y_pred, target_names=['Non-IoMT', 'IoMT-associated'])}

Confusion Matrix:
{cm}
============================================================
"""
    rpt_file = RPT_DIR / "iomt_classifier_report.txt"
    rpt_file.write_text(report_text, encoding="utf-8")
    log.info(f"Saved evaluation report: {rpt_file}")

    # Plot Confusion Matrix
    fig, ax = plt.subplots(figsize=(6, 5))
    ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=['Non-IoMT', 'IoMT']).plot(
        ax=ax, cmap="Blues", colorbar=True
    )
    ax.set_title("IoMT Classifier — Confusion Matrix", fontweight="bold")
    plt.tight_layout()
    cm_path = FIG_DIR / "iomt_confusion_matrix.png"
    plt.savefig(cm_path, dpi=150)
    plt.close()

    # Plot Feature Importance
    rf = pipeline.named_steps["clf"]
    importances = rf.feature_importances_
    indices = np.argsort(importances)[::-1][:20]
    fig, ax = plt.subplots(figsize=(10, 6))
    sns.barplot(x=importances[indices], y=[feature_cols[i] for i in indices], ax=ax, palette="viridis")
    ax.set_title("Top 20 Features — IoMT Classifier", fontweight="bold")
    plt.tight_layout()
    fi_path = FIG_DIR / "iomt_feature_importance.png"
    plt.savefig(fi_path, dpi=150)
    plt.close()

    # Save model
    model_obj = {
        "model": pipeline,
        "feature_cols": feature_cols,
        "version": "v1.0.0-stage1-iomt",
        "dataset": "CICIoMT2024 + CICIoT2023",
        "metrics": {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1, "fpr": fpr}
    }
    model_path = MDL_DIR / "iomt_classifier.joblib"
    joblib.dump(model_obj, model_path)
    log.info(f"Saved model to: {model_path}")

if __name__ == "__main__":
    main()
