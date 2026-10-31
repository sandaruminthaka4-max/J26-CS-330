"""
extractor.py — Feature extraction and schema alignment between CICIoMT2024 and live OpenFlow statistics
Project: J26-CS-330 | Component: DoS Detection via SDN Flow Analysis
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Union
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

DEFAULT_SCHEMA_PATH = Path(__file__).resolve().parent.parent.parent / "configs" / "feature_schema.json"


def get_feature_names(schema_path: Optional[Union[str, Path]] = None) -> List[str]:
    """
    Load the immutable ordered list of feature names from feature_schema.json.
    """
    path = Path(schema_path) if schema_path else DEFAULT_SCHEMA_PATH
    if not path.exists():
        raise FileNotFoundError(f"Feature schema not found at {path}")
    
    with open(path, "r") as f:
        schema = json.load(f)
    return schema["feature_names"]


def extract_features(df: pd.DataFrame, feature_names: List[str]) -> np.ndarray:
    """
    Extract and enforce exact column ordering and data types from a DataFrame.
    """
    validate_feature_order(df, feature_names)
    X = df[feature_names].values.astype(np.float32)
    return X


def validate_feature_order(df: pd.DataFrame, expected_features: List[str]) -> None:
    """
    Ensure all expected features exist in the DataFrame.
    """
    missing = [f for f in expected_features if f not in df.columns]
    if missing:
        raise ValueError(
            f"Missing {len(missing)} required features in input data: {missing[:5]}... "
            f"Expected {len(expected_features)} features."
        )


def features_from_api_input(
    input_dict: Dict[str, Union[int, float]],
    feature_names: List[str],
    protocol_encoder=None,
) -> np.ndarray:
    """
    Convert an incoming API payload or live SDN observation dictionary into
    the exact ordered 1D/2D numpy array required by the XGBoost model.
    Missing fields default to 0.0.
    """
    features = []
    for name in feature_names:
        val = input_dict.get(name, 0.0)
        if val is None:
            val = 0.0
            
        # Handle protocol encoding if required
        if name == "Protocol Type" and protocol_encoder is not None:
            try:
                # If incoming protocol is a string (e.g. 'TCP', 'UDP' or numeric '6', '17')
                str_val = str(val)
                if str_val in protocol_encoder.classes_:
                    val = float(protocol_encoder.transform([str_val])[0])
                else:
                    val = 0.0
            except Exception:
                val = 0.0
                
        features.append(float(val))

    arr = np.array(features, dtype=np.float32).reshape(1, -1)
    return arr


def openflow_to_features(
    flow_stats: Dict[str, Union[int, float]],
    feature_names: List[str],
) -> Dict[str, float]:
    """
    OpenFlow 1.3 to CICIoMT2024 Feature Mapping Bridge.
    
    RESEARCH NOTE & BOUNDARY DOCUMENTATION:
    Standard OpenFlow 1.3 (OFPFlowStatsReply) natively provides:
      - packet_count
      - byte_count
      - duration_sec + duration_nsec
      - match fields: eth_type, ip_proto, tcp_src, tcp_dst, etc.
    
    In contrast, CICIoMT2024 (CICFlowMeter-based) provides comprehensive flow statistics
    (packet rates, sub-flow statistics, window sizes, packet length variance, etc.).
    
    This function bridges the two by calculating live rates where possible:
      - Duration = duration_sec + (duration_nsec / 1e9)
      - Rate = packet_count / Duration (if Duration > 0)
      - Srate / Drate approximations from packet counts
      - Protocol flags mapped from match fields
      - Features unavailable from raw OFPFlowStats default safely to 0.0.
    """
    out = {name: 0.0 for name in feature_names}

    # Extract base OpenFlow metrics
    packet_count = float(flow_stats.get("packet_count", 0.0))
    byte_count = float(flow_stats.get("byte_count", 0.0))
    dur_sec = float(flow_stats.get("duration_sec", 0.0))
    dur_nsec = float(flow_stats.get("duration_nsec", 0.0))
    duration = dur_sec + (dur_nsec / 1e9)
    ip_proto = flow_stats.get("ip_proto", flow_stats.get("protocol", 0.0))

    out["Duration"] = duration
    out["Number"] = packet_count
    out["Tot sum"] = byte_count
    out["Tot size"] = byte_count

    if duration > 0.0001:
        out["Rate"] = packet_count / duration
        out["Srate"] = packet_count / duration
        out["Drate"] = byte_count / duration

    # Map Protocol Type
    if isinstance(ip_proto, (int, float)):
        out["Protocol Type"] = float(ip_proto)
        if ip_proto == 6:
            out["TCP"] = 1.0
        elif ip_proto == 17:
            out["UDP"] = 1.0
        elif ip_proto == 1:
            out["ICMP"] = 1.0
    elif isinstance(ip_proto, str):
        p_upper = ip_proto.upper()
        if "TCP" in p_upper:
            out["Protocol Type"] = 6.0
            out["TCP"] = 1.0
        elif "UDP" in p_upper:
            out["Protocol Type"] = 17.0
            out["UDP"] = 1.0
        elif "ICMP" in p_upper:
            out["Protocol Type"] = 1.0
            out["ICMP"] = 1.0

    # Map TCP Flags if present in OpenFlow extension or flow match
    tcp_flags = flow_stats.get("tcp_flags", 0)
    if isinstance(tcp_flags, int) and tcp_flags > 0:
        if tcp_flags & 0x02:  # SYN
            out["syn_flag_number"] = 1.0
            out["syn_count"] = 1.0
        if tcp_flags & 0x10:  # ACK
            out["ack_flag_number"] = 1.0
            out["ack_count"] = 1.0
        if tcp_flags & 0x01:  # FIN
            out["fin_flag_number"] = 1.0
            out["fin_count"] = 1.0
        if tcp_flags & 0x04:  # RST
            out["rst_flag_number"] = 1.0
            out["rst_count"] = 1.0

    return out
