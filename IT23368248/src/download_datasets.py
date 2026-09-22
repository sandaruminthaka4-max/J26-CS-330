"""
Dataset Download Helper
=======================
CICIoMT2024  : https://www.unb.ca/cic/datasets/iomt-dataset-2024.html
CICIoT2023   : https://www.unb.ca/cic/datasets/iotdataset-2023.html

Kaggle alternatives (faster):
  ciciomt2024  -> search "CICIoMT2024" on kaggle.com
  ciciot2023   -> search "CIC IoT Dataset 2023" on kaggle.com

This script checks whether the CSVs are already present.
If not, it prints exact download instructions.
"""

import os
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
RAW_IOMT  = BASE / "data" / "raw" / "ciciomt2024"
RAW_IOT   = BASE / "data" / "raw" / "ciciot2023"

# ── Expected CSV file patterns ─────────────────────────────────────────────────
# CICIoMT2024 WiFi+MQTT subset
IOMT_EXPECTED = [
    "CIC_IoMT_WiFi_MQTT_train.csv",   # common Kaggle naming
    "CIC_IoMT_WiFi_MQTT_test.csv",
]
# CICIoT2023 (part1 .. part33 OR combined)
IOT_EXPECTED = [
    "CIC_IoT_Dataset_2023_part1.csv",
    "part-00000-of-00001.csv",         # alternative Kaggle naming
    "ciciot2023.csv",
]

def check_presence(folder: Path, patterns: list[str]) -> list[Path]:
    found = []
    if folder.exists():
        for p in folder.iterdir():
            if p.suffix == ".csv":
                found.append(p)
    return found


def main():
    print("=" * 60)
    print("  Dataset Availability Check")
    print("=" * 60)

    iomt_files = check_presence(RAW_IOMT, IOMT_EXPECTED)
    iot_files  = check_presence(RAW_IOT,  IOT_EXPECTED)

    # ── CICIoMT2024 ────────────────────────────────────────────────────────────
    print(f"\n[1] CICIoMT2024  ->  {RAW_IOMT}")
    if iomt_files:
        print(f"    ✅  Found {len(iomt_files)} CSV file(s):")
        for f in iomt_files:
            size_mb = f.stat().st_size / 1e6
            print(f"        • {f.name}  ({size_mb:.1f} MB)")
    else:
        print("    ❌  No CSV files found.")
        print("""
    ▶ Manual Download Steps:
      1. Go to: https://www.kaggle.com/datasets/search?q=CICIoMT2024
         OR: https://zenodo.org/records/10519703
      2. Download the WiFi_and_MQTT CSV files (train + test).
      3. Place them in:
         data/raw/ciciomt2024/
""")

    # ── CICIoT2023 ─────────────────────────────────────────────────────────────
    print(f"\n[2] CICIoT2023   ->  {RAW_IOT}")
    if iot_files:
        print(f"    ✅  Found {len(iot_files)} CSV file(s):")
        for f in iot_files:
            size_mb = f.stat().st_size / 1e6
            print(f"        • {f.name}  ({size_mb:.1f} MB)")
    else:
        print("    ❌  No CSV files found.")
        print("""
    ▶ Manual Download Steps:
      1. Go to: https://www.kaggle.com/datasets/madhavmalhotra/unb-cic-iot-dataset
         OR: https://www.unb.ca/cic/datasets/iotdataset-2023.html
      2. Download any CSV parts (part1..part33 or combined).
      3. Place them in:
         data/raw/ciciot2023/
""")

    both_ready = bool(iomt_files) and bool(iot_files)
    print("=" * 60)
    if both_ready:
        print("  ✅  Both datasets present — ready to run pipeline!")
        print("      Next: python src/01_feature_mapping.py")
    else:
        print("  ⚠️   Download missing datasets above, then re-run this script.")
    print("=" * 60)
    return both_ready


if __name__ == "__main__":
    main()
