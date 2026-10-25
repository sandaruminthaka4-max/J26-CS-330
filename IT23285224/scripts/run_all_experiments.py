"""
Master Experiment Reproduction Pipeline.
Executes dataset extraction, preprocessing, feature selection, model training,
deployment benchmarking, and automated verification tests in a single command.
"""

import logging
import os
import subprocess
import sys
import time

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - MasterRunner: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("MasterRunner")


def run_stage(command: list[str], stage_name: str) -> None:
    logger.info(f"========== STARTING: {stage_name} ==========")
    t0 = time.time()
    res = subprocess.run(command, cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    elapsed = time.time() - t0
    if res.returncode != 0:
        logger.error(f"STAGE FAILED: {stage_name} (Exit code: {res.returncode})")
        sys.exit(res.returncode)
    logger.info(f"STAGE COMPLETED: {stage_name} in {elapsed:.2f} seconds\n")


def main():
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    python_bin = sys.executable

    logger.info("Initializing Full Reproduction Workflow for CICIoMT2024 Reconnaissance IDS...")
    start_total = time.time()

    # Stage 1: Extraction & Manifest
    run_stage([python_bin, "scripts/extract_dataset.py"], "Stage 1: Dataset Extraction & Manifest Generation")

    # Stage 2: Preprocessing & Audit
    run_stage([python_bin, "scripts/preprocess_data.py"], "Stage 2: Preprocessing, Imputation & Leakage Audit")

    # Stage 3: Feature Selection Study
    run_stage([python_bin, "scripts/run_feature_selection.py"], "Stage 3: Feature Selection & K-Subset Benchmarking")

    # Stage 4: Model Training & Evaluation
    run_stage([python_bin, "scripts/train_models.py"], "Stage 4: 5-Fold CV, Baselines & Deployment Scorecard")

    # Stage 5: Quality Assurance Test Suite
    run_stage([python_bin, "-m", "pytest", "tests", "-v"], "Stage 5: Automated Testing & Verification Suite")

    total_time = time.time() - start_total
    logger.info(f"============================================================")
    logger.info(f"ALL EXPERIMENTS SUCCESSFULLY REPRODUCED IN {total_time/60:.2f} MINUTES")
    logger.info(f"Deployment artifacts saved in 'models/' and 'results/'")
    logger.info(f"============================================================")


if __name__ == "__main__":
    main()
