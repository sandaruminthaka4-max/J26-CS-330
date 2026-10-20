"""
Dataset Path Configuration
============================
Edit the paths below to match where your datasets are stored.
No need to copy files — scripts will read from these locations directly.
"""

from pathlib import Path

# ── CICIoMT2024 (WiFi + MQTT subset) ─────────────────────────────────────────
# D:\Y4 S1\Research\Datasets IT23368248\CIC IoMT 2024\archive\
CICIOMT2024_DIR = Path(r"D:\Y4 S1\Research\Datasets IT23368248\CIC IoMT 2024\archive")

# Exact file names (from your screenshot)
CICIOMT2024_TRAIN_CSV = CICIOMT2024_DIR / "CIC_IoMT_2024_WiFi_MQTT_train.csv"
CICIOMT2024_TEST_CSV  = CICIOMT2024_DIR / "CIC_IoMT_2024_WiFi_MQTT_test.csv"

# D:\Y4 S1\Research\Datasets IT23368248\CIC IoMT 2023\archive\wataiData\csv\CICIoT2023\
CICIOT2023_DIR = Path(r"D:\Y4 S1\Research\Datasets IT23368248\CIC IoMT 2023\archive\wataiData\csv\CICIoT2023")

# ── Project output directories ────────────────────────────────────────────────
PROJECT_DIR  = Path(__file__).resolve().parent.parent
PROC_DIR     = PROJECT_DIR / "data" / "processed"
MDL_DIR      = PROJECT_DIR / "models"
RPT_DIR      = PROJECT_DIR / "reports"
FIG_DIR      = RPT_DIR / "figures"

# Max rows to load from each part file in CICIoT2023 (None = all rows)
# Set a number (e.g. 50000) to limit memory usage if needed
CICIOT2023_MAX_ROWS_PER_FILE = None

# Max records per class after merging (for class balance)
MAX_RECORDS_PER_CLASS = 200_000

# ── Validation ────────────────────────────────────────────────────────────────
def validate_paths():
    errors = []
    if not CICIOMT2024_TRAIN_CSV.exists():
        errors.append(f"CICIoMT2024 train CSV not found: {CICIOMT2024_TRAIN_CSV}")
    if not CICIOMT2024_TEST_CSV.exists():
        errors.append(f"CICIoMT2024 test CSV not found:  {CICIOMT2024_TEST_CSV}")
    if not CICIOT2023_DIR.exists():
        errors.append(f"CICIoT2023 directory not found:  {CICIOT2023_DIR}")
    else:
        parts = list(CICIOT2023_DIR.glob("*.csv"))
        if not parts:
            errors.append(f"No CSV part files found in:      {CICIOT2023_DIR}")
        else:
            print(f"  CICIoT2023: {len(parts)} part files found")

    if errors:
        print("PATH ERRORS:")
        for e in errors:
            print(f"  ERROR: {e}")
        return False

    print(f"  CICIoMT2024 train: {CICIOMT2024_TRAIN_CSV.name}  "
          f"({CICIOMT2024_TRAIN_CSV.stat().st_size/1e6:.0f} MB)")
    print(f"  CICIoMT2024 test : {CICIOMT2024_TEST_CSV.name}  "
          f"({CICIOMT2024_TEST_CSV.stat().st_size/1e6:.0f} MB)")
    return True


if __name__ == "__main__":
    print("Validating dataset paths ...")
    ok = validate_paths()
    print("All paths OK!" if ok else "Fix the paths above and retry.")
