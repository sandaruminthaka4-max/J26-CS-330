"""
conftest.py — Pytest configuration adding project root to sys.path
Project: J26-CS-330 | Component: DoS Detection via SDN Flow Analysis
"""

import sys
from pathlib import Path

# Add project root directory to sys.path so 'app' and 'src' can be imported anywhere
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
