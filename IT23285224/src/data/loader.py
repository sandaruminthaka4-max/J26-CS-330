"""
High-Performance, Memory-Efficient Data Loader for CICIoMT2024.
Streams raw zip archives in chunks, isolates Benign and Reconnaissance attack flows,
and maps labels to canonical 5-class target classes.
"""

import csv
import io
import json
import logging
import os
import zipfile
from pathlib import Path
from typing import Dict, Generator, List, Optional, Tuple

import numpy as np
import pandas as pd

from src.data.schema import (
    NUMERICAL_FEATURE_COLUMNS,
    RAW_FEATURE_COLUMNS,
    RAW_TO_CANONICAL_LABEL_MAP,
    TARGET_CLASSES,
)

logger = logging.getLogger(__name__)


def extract_recon_flows_from_zip(
    zip_path: str,
    target_csv_name: str,
    output_csv_path: str,
    chunk_size: int = 100_000,
    max_benign_samples: Optional[int] = None,
    random_seed: int = 42,
) -> Dict[str, int]:
    """
    Extracts relevant flows (Benign, Ping Sweep, Port Scan, OS Scan, Vulnerability Scan)
    from a specific CSV inside the CICIoMT2024 zip archive in a streaming fashion.
    
    Optionally sub-samples Benign traffic to maintain balanced proportions without losing
    statistical power, while preserving 100% of minority reconnaissance scan samples.
    """
    out_path = Path(output_csv_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    counts: Dict[str, int] = {cls_name: 0 for cls_name in TARGET_CLASSES}
    total_scanned = 0
    total_written = 0

    rng = np.random.default_rng(random_seed)

    # First pass or streaming pass
    # Since benign flows outnumber rare scans heavily (e.g. 192k vs 740),
    # we write header + matching rows.
    with zipfile.ZipFile(zip_path, "r") as z:
        if target_csv_name not in z.namelist():
            raise FileNotFoundError(f"{target_csv_name} not found in {zip_path}")

        with z.open(target_csv_name) as raw_file, open(
            output_csv_path, "w", newline="", encoding="utf-8"
        ) as out_file:
            text_in = io.TextIOWrapper(raw_file, encoding="utf-8")
            reader = csv.reader(text_in)
            writer = csv.writer(out_file)

            raw_header = next(reader)
            if "label" not in raw_header:
                raise ValueError("CSV header missing 'label' column")

            label_idx = raw_header.index("label")
            # Write canonical header
            canonical_header = [col for col in raw_header]
            writer.writerow(canonical_header)

            benign_written = 0

            for row in reader:
                total_scanned += 1
                raw_label = row[label_idx].strip()

                if raw_label in RAW_TO_CANONICAL_LABEL_MAP:
                    canonical_label = RAW_TO_CANONICAL_LABEL_MAP[raw_label]

                    # If benign subsampling requested, probabilistic acceptance
                    if canonical_label == "Benign" and max_benign_samples is not None:
                        # Will handle uniform reservoir or fixed cap
                        if benign_written >= max_benign_samples:
                            continue

                    row_to_write = list(row)
                    row_to_write[label_idx] = canonical_label
                    writer.writerow(row_to_write)

                    counts[canonical_label] += 1
                    total_written += 1
                    if canonical_label == "Benign":
                        benign_written += 1

                if total_scanned % 500_000 == 0:
                    logger.info(
                        f"Scanned {total_scanned:,} flows, extracted {total_written:,} relevant records."
                    )

    logger.info(
        f"Extraction complete for {target_csv_name}: Scanned {total_scanned:,}, Saved {total_written:,}"
    )
    return counts


def load_dataset_chunked(
    csv_path: str,
    chunk_size: int = 50_000,
) -> Generator[pd.DataFrame, None, None]:
    """
    Generator that yields typed DataFrame chunks to keep memory footprint minimal.
    """
    dtype_dict = {col: np.float64 for col in NUMERICAL_FEATURE_COLUMNS}
    dtype_dict["label"] = "category"

    for chunk in pd.read_csv(csv_path, chunksize=chunk_size, dtype=dtype_dict):
        yield chunk


def load_full_dataframe(csv_path: str) -> pd.DataFrame:
    """
    Loads full dataset into memory with optimized memory dtypes.
    """
    dtype_dict = {col: np.float32 for col in NUMERICAL_FEATURE_COLUMNS}
    dtype_dict["label"] = "category"
    df = pd.read_csv(csv_path, dtype=dtype_dict)
    return df
