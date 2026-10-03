"""
Official Schema and Taxonomy Definition for CICIoMT2024 Reconnaissance Detection.
"""

from typing import Dict, List, Set

# The authoritative 46 columns in raw CICIoMT2024 flows
RAW_FEATURE_COLUMNS: List[str] = [
    "Header_Length",
    "Protocol Type",
    "Duration",
    "Rate",
    "Srate",
    "Drate",
    "fin_flag_number",
    "syn_flag_number",
    "rst_flag_number",
    "psh_flag_number",
    "ack_flag_number",
    "ece_flag_number",
    "cwr_flag_number",
    "ack_count",
    "syn_count",
    "fin_count",
    "rst_count",
    "HTTP",
    "HTTPS",
    "DNS",
    "Telnet",
    "SMTP",
    "SSH",
    "IRC",
    "TCP",
    "UDP",
    "DHCP",
    "ARP",
    "ICMP",
    "IGMP",
    "IPv",
    "LLC",
    "Tot sum",
    "Min",
    "Max",
    "AVG",
    "Std",
    "Tot size",
    "IAT",
    "Number",
    "Magnitue",
    "Radius",
    "Covariance",
    "Variance",
    "Weight",
    "label",
]

# 45 numerical/statistical feature columns (excluding target 'label')
NUMERICAL_FEATURE_COLUMNS: List[str] = [col for col in RAW_FEATURE_COLUMNS if col != "label"]

# Raw label mapping to standardized 5-class multi-class taxonomy
RAW_TO_CANONICAL_LABEL_MAP: Dict[str, str] = {
    "benign": "Benign",
    "Ping Sweep": "Ping Sweep",
    "Port Scan": "Port Scan",
    "OS Scan": "OS Scan",
    "Recon VulScan": "Vulnerability Scan",
}

# The 5 canonical target classes
TARGET_CLASSES: List[str] = [
    "Benign",
    "Ping Sweep",
    "Port Scan",
    "OS Scan",
    "Vulnerability Scan",
]

# Integer encoding for models
CLASS_TO_INT_MAP: Dict[str, int] = {name: idx for idx, name in enumerate(TARGET_CLASSES)}
INT_TO_CLASS_MAP: Dict[int, str] = {idx: name for idx, name in enumerate(TARGET_CLASSES)}

# Binary classification mapping
CANONICAL_TO_BINARY_MAP: Dict[str, str] = {
    "Benign": "Benign",
    "Ping Sweep": "Reconnaissance",
    "Port Scan": "Reconnaissance",
    "OS Scan": "Reconnaissance",
    "Vulnerability Scan": "Reconnaissance",
}

# Feature groups for interpretability and feature selection
FEATURE_GROUPS: Dict[str, List[str]] = {
    "Rate_and_Timing": [
        "Duration",
        "Rate",
        "Srate",
        "Drate",
        "IAT",
        "Number",
    ],
    "TCP_Flags": [
        "fin_flag_number",
        "syn_flag_number",
        "rst_flag_number",
        "psh_flag_number",
        "ack_flag_number",
        "ece_flag_number",
        "cwr_flag_number",
        "ack_count",
        "syn_count",
        "fin_count",
        "rst_count",
    ],
    "Protocol_Indicators": [
        "Protocol Type",
        "HTTP",
        "HTTPS",
        "DNS",
        "Telnet",
        "SMTP",
        "SSH",
        "IRC",
        "TCP",
        "UDP",
        "DHCP",
        "ARP",
        "ICMP",
        "IGMP",
        "IPv",
        "LLC",
    ],
    "Packet_Size_Statistics": [
        "Header_Length",
        "Tot sum",
        "Min",
        "Max",
        "AVG",
        "Std",
        "Tot size",
    ],
    "Distribution_Statistical": [
        "Magnitue",
        "Radius",
        "Covariance",
        "Variance",
        "Weight",
    ],
}
