"""
loader.py — Dataset loading utilities for CICIoMT2024
Project: J26-CS-330 | Component: DoS Detection via SDN Flow Analysis
"""

import io
import logging
import zipfile
from pathlib import Path
from typing import Optional, Union
import pandas as pd

logger = logging.getLogger(__name__)


def load_from_zip(
    zip_path: Union[str, Path],
    filename_in_zip: str,
    nrows: Optional[int] = None,
    usecols: Optional[list] = None,
) -> pd.DataFrame:
    """
    Load a CSV file directly from a ZIP archive into memory without full disk extraction.
    
    Args:
        zip_path: Absolute or relative path to the ZIP archive.
        filename_in_zip: Exact name of the CSV file inside the ZIP.
        nrows: Number of rows to read (useful for rapid testing or memory constraints).
        usecols: List of column names to load.
        
    Returns:
        pd.DataFrame containing the loaded data.
    """
    zip_path = Path(zip_path)
    if not zip_path.exists():
        raise FileNotFoundError(f"ZIP archive not found at: {zip_path}")

    logger.info(f"Opening ZIP file: {zip_path}")
    with zipfile.ZipFile(zip_path, 'r') as z:
        if filename_in_zip not in z.namelist():
            raise KeyError(
                f"File '{filename_in_zip}' not found in archive. Available files: {z.namelist()}"
            )
        
        logger.info(f"Streaming '{filename_in_zip}' from ZIP into pandas DataFrame...")
        with z.open(filename_in_zip) as f:
            df = pd.read_csv(f, nrows=nrows, usecols=usecols, low_memory=False)
            
    logger.info(f"Successfully loaded {len(df):,} rows and {len(df.columns)} columns.")
    return df


def load_csv(
    csv_path: Union[str, Path],
    nrows: Optional[int] = None,
    usecols: Optional[list] = None,
) -> pd.DataFrame:
    """
    Load a standalone CSV file.
    """
    csv_path = Path(csv_path)
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV file not found at: {csv_path}")

    logger.info(f"Loading CSV from: {csv_path}")
    df = pd.read_csv(csv_path, nrows=nrows, usecols=usecols, low_memory=False)
    logger.info(f"Successfully loaded {len(df):,} rows and {len(df.columns)} columns.")
    return df


def get_column_info(df: pd.DataFrame) -> dict:
    """
    Extract summary statistics and metadata of the DataFrame columns.
    """
    summary = {
        "shape": df.shape,
        "columns": list(df.columns),
        "dtypes": df.dtypes.astype(str).to_dict(),
        "missing_counts": df.isnull().sum().to_dict(),
        "memory_mb": round(df.memory_usage(deep=True).sum() / (1024 * 1024), 2),
    }
    return summary
