"""
Executable Dataset Extraction Script.
Extracts 100% of Reconnaissance scan attacks and Benign IoMT flows from CICIoMT2024 archive.
"""

import logging
import os
import sys
import time

# Ensure project root in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.data.loader import extract_recon_flows_from_zip
from src.data.manifest import create_dataset_manifest

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ExtractDataset")


def main():
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    zip_path = os.path.join(root_dir, "CICIoMT2024 DataSets.zip")
    data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
    interim_dir = os.path.join(data_dir, "interim")
    manifest_path = os.path.join(data_dir, "dataset_manifest.json")

    logger.info(f"Checking raw archive at: {zip_path}")
    if not os.path.exists(zip_path):
        logger.error(f"Archive not found at {zip_path}")
        sys.exit(1)

    t0 = time.time()
    logger.info("Step 1: Generating Dataset Manifest with SHA-256 hash...")
    manifest = create_dataset_manifest(
        raw_archive_path=zip_path,
        output_manifest_path=manifest_path,
        extra_metadata={"extracted_by": "Bandara B.R.K.Y (IT23285224)"},
    )
    logger.info(f"Manifest written. Archive size: {manifest['archive_size_mb']} MB, SHA-256: {manifest['archive_sha256'][:16]}...")

    logger.info("Step 2: Extracting Reconnaissance flows from test_iomt.csv...")
    test_out = os.path.join(interim_dir, "recon_raw_test.csv")
    test_counts = extract_recon_flows_from_zip(
        zip_path=zip_path,
        target_csv_name="test_iomt.csv",
        output_csv_path=test_out,
    )
    logger.info(f"Extracted Test Counts: {test_counts}")

    logger.info("Step 3: Extracting Reconnaissance flows from train_iomt.csv...")
    train_out = os.path.join(interim_dir, "recon_raw_train.csv")
    train_counts = extract_recon_flows_from_zip(
        zip_path=zip_path,
        target_csv_name="train_iomt.csv",
        output_csv_path=train_out,
    )
    logger.info(f"Extracted Train Counts: {train_counts}")

    elapsed = time.time() - t0
    logger.info(f"Dataset extraction completed in {elapsed:.2f} seconds.")


if __name__ == "__main__":
    main()
