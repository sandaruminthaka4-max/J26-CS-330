"""
Dataset Manifest and Provenance Tracking for CICIoMT2024.
Computes cryptographic SHA-256 hashes, file statistics, and records extraction metadata.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def compute_sha256(file_path: str, chunk_size: int = 1024 * 1024) -> str:
    """Compute SHA-256 hash of a file efficiently using chunking."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def create_dataset_manifest(
    raw_archive_path: str,
    output_manifest_path: str,
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Generate an immutable JSON manifest documenting raw source files, hashes, and provenance.
    """
    raw_path = Path(raw_archive_path)
    if not raw_path.exists():
        raise FileNotFoundError(f"Raw archive not found at: {raw_archive_path}")

    file_size_bytes = raw_path.stat().st_size
    file_hash = compute_sha256(str(raw_path))

    manifest: Dict[str, Any] = {
        "dataset_name": "CICIoMT2024",
        "official_source": "https://www.unb.ca/cic/datasets/iomt-dataset-2024.html",
        "citation": "Dadkhah et al., 'CICIoMT2024: A benchmark dataset for multi-protocol security assessment in IoMT', Internet of Things, 2024",
        "archive_filename": raw_path.name,
        "archive_size_bytes": file_size_bytes,
        "archive_size_mb": round(file_size_bytes / (1024 * 1024), 2),
        "archive_sha256": file_hash,
        "generation_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "individual_scope": "Multi-Class Reconnaissance Attack Detection (Benign, Ping Sweep, Port Scan, OS Scan, Vulnerability Scan)",
        "excluded_attack_families": [
            "DoS (UDP, SYN, ICMP, TCP, Connect Flood, Publish Flood)",
            "DDoS (UDP, ICMP, TCP, SYN, Publish Flood)",
            "Spoofing (ARP Spoofing)",
            "MQTT Anomalies (Malformed Data)",
        ],
        "metadata": extra_metadata or {},
    }

    out_path = Path(output_manifest_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    return manifest
