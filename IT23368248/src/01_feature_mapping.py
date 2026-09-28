"""
Stage 1 — Feature Mapping & Dataset Merge (Production D Drive Pipeline)
========================================================================
Reads directly from configured D: drive paths.
Matches verified schemas of CICIoMT2024 and CICIoT2023.

Outputs:
  data/processed/merged_iomt_dataset.csv
"""

import sys
import logging
import warnings
from pathlib import Path
import numpy as np
import pandas as pd

from config import (
    CICIOMT2024_TRAIN_CSV,
    CICIOMT2024_TEST_CSV,
    CICIOT2023_DIR,
    PROC_DIR,
    MAX_RECORDS_PER_CLASS,
)

warnings.filterwarnings("ignore")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# Verified shared numerical features present in both datasets
SHARED_FEATURES = [
    'Header_Length', 'Protocol Type', 'Duration', 'Rate', 'Srate', 'Drate',
    'fin_flag_number', 'syn_flag_number', 'rst_flag_number', 'psh_flag_number',
    'ack_flag_number', 'ece_flag_number', 'cwr_flag_number', 'ack_count',
    'syn_count', 'fin_count', 'rst_count', 'HTTP', 'HTTPS', 'DNS', 'Telnet',
    'SMTP', 'SSH', 'IRC', 'TCP', 'UDP', 'DHCP', 'ARP', 'ICMP', 'IPv', 'LLC',
    'Tot sum', 'Min', 'Max', 'AVG', 'Std', 'Tot size', 'IAT', 'Number',
    'Magnitue', 'Radius', 'Covariance', 'Variance', 'Weight'
]

def load_and_prep_iomt(sample_size=150_000):
    log.info("Loading CICIoMT2024 (Train + Test samples)...")
    # Read sample from train and test to represent IoMT
    df_train = pd.read_csv(CICIOMT2024_TRAIN_CSV, nrows=int(sample_size * 0.75), low_memory=False)
    df_test = pd.read_csv(CICIOMT2024_TEST_CSV, nrows=int(sample_size * 0.25), low_memory=False)
    df_iomt = pd.concat([df_train, df_test], ignore_index=True)
    
    df_iomt['attack_label_original'] = df_iomt['label'].astype(str).str.strip()
    df_iomt['iomt_label'] = 1  # 1 = IoMT
    df_iomt['dataset_source'] = "CICIoMT2024"
    
    keep_cols = [c for c in SHARED_FEATURES if c in df_iomt.columns] + ['attack_label_original', 'iomt_label', 'dataset_source']
    df_iomt = df_iomt[keep_cols]
    log.info(f"CICIoMT2024 loaded: {len(df_iomt):,} records")
    return df_iomt

def load_and_prep_iot(target_size=150_000):
    log.info("Loading CICIoT2023 (Non-IoMT Class from part CSVs)...")
    part_files = sorted(list(CICIOT2023_DIR.glob("*.csv")))
    
    # Read across initial parts to get representative distributed non-IoMT traffic
    rows_per_part = 10_000
    frames = []
    total = 0
    
    for p in part_files:
        if total >= target_size:
            break
        try:
            chunk = pd.read_csv(p, nrows=rows_per_part, low_memory=False)
            frames.append(chunk)
            total += len(chunk)
        except Exception as e:
            log.warning(f"Error reading {p.name}: {e}")
            
    df_iot = pd.concat(frames, ignore_index=True)
    df_iot['attack_label_original'] = df_iot['label'].astype(str).str.strip()
    df_iot['iomt_label'] = 0  # 0 = Non-IoMT
    df_iot['dataset_source'] = "CICIoT2023"
    
    keep_cols = [c for c in SHARED_FEATURES if c in df_iot.columns] + ['attack_label_original', 'iomt_label', 'dataset_source']
    df_iot = df_iot[keep_cols]
    log.info(f"CICIoT2023 loaded: {len(df_iot):,} records")
    return df_iot

def clean_data(df):
    log.info("Cleaning and converting numerics...")
    for col in SHARED_FEATURES:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
        else:
            df[col] = 0.0
            
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(subset=SHARED_FEATURES, inplace=True)
    for col in SHARED_FEATURES:
        df[col] = df[col].clip(-1e9, 1e9)
    return df

def main():
    log.info("=" * 60)
    log.info("  Starting Stage 1: Feature Mapping & Merging")
    log.info("=" * 60)
    
    df_iomt = load_and_prep_iomt(sample_size=120_000)
    df_iot  = load_and_prep_iot(target_size=120_000)
    
    log.info("Combining datasets...")
    df_merged = pd.concat([df_iomt, df_iot], ignore_index=True)
    df_merged = clean_data(df_merged)
    
    # Shuffle
    df_merged = df_merged.sample(frac=1.0, random_state=42).reset_index(drop=True)
    
    out_file = PROC_DIR / "merged_iomt_dataset.csv"
    log.info(f"Saving merged dataset to {out_file}...")
    df_merged.to_csv(out_file, index=False)
    
    log.info("=" * 60)
    log.info("  Merge Complete!")
    log.info(f"  Total records: {len(df_merged):,}")
    log.info(f"  IoMT (1): {(df_merged['iomt_label'] == 1).sum():,}")
    log.info(f"  Non-IoMT (0): {(df_merged['iomt_label'] == 0).sum():,}")
    log.info(f"  Saved path: {out_file}")
    log.info("=" * 60)

if __name__ == "__main__":
    main()
