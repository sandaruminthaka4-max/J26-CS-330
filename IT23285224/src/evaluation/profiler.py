"""
System Profiler & Deployment Scorecard for Lightweight IoMT Intrusion Detection.
Measures latency (P50, P95), throughput, memory footprint, CPU load, and computes Pareto Scorecard.
"""

import gc
import logging
import os
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
import psutil

logger = logging.getLogger(__name__)


class DeploymentProfiler:
    """
    Profiles inference latency, memory footprint, CPU load, and model storage.
    """

    def __init__(self, model: Any, preprocessor: Optional[Any] = None):
        self.model = model
        self.preprocessor = preprocessor

    def measure_model_size_mb(self) -> float:
        """Measure serialized model disk size in Megabytes."""
        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            joblib.dump(self.model, tmp_path, compress=3)
            size_bytes = os.path.getsize(tmp_path)
            return round(size_bytes / (1024 * 1024), 3)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def benchmark_latency(
        self,
        X_test: np.ndarray,
        warmup_runs: int = 50,
        test_samples: int = 1000,
    ) -> Dict[str, float]:
        """
        Profiles single-flow inference latency across individual flow predictions.
        Reports Median (P50), P95, P99 latency in milliseconds, and batch throughput.
        """
        # Warmup
        warmup_batch = X_test[: min(warmup_runs, len(X_test))]
        for _ in range(3):
            _ = self.model.predict(warmup_batch)

        # Single instance profiling
        sample_subset = X_test[: min(test_samples, len(X_test))]
        single_latencies_ms = []

        for row in sample_subset:
            x_single = row.reshape(1, -1)
            t0 = time.perf_counter()
            _ = self.model.predict(x_single)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            single_latencies_ms.append(elapsed_ms)

        single_arr = np.array(single_latencies_ms)
        p50 = float(np.percentile(single_arr, 50))
        p95 = float(np.percentile(single_arr, 95))
        p99 = float(np.percentile(single_arr, 99))
        mean_lat = float(np.mean(single_arr))

        # Batch throughput profiling (10,000 flows or full set)
        batch_eval = X_test[: min(10_000, len(X_test))]
        t_batch_start = time.perf_counter()
        _ = self.model.predict(batch_eval)
        t_batch_total = time.perf_counter() - t_batch_start
        throughput = int(len(batch_eval) / t_batch_total) if t_batch_total > 0 else 0

        return {
            "single_latency_p50_ms": round(p50, 4),
            "single_latency_p95_ms": round(p95, 4),
            "single_latency_p99_ms": round(p99, 4),
            "single_latency_mean_ms": round(mean_lat, 4),
            "batch_throughput_flows_sec": throughput,
        }

    def measure_resource_utilization(
        self,
        X_test: np.ndarray,
        duration_seconds: float = 3.0,
    ) -> Dict[str, float]:
        """
        Measures resident memory (RSS MB) and sustained CPU utilization during inference.
        """
        gc.collect()
        process = psutil.Process(os.getpid())
        ram_before_mb = process.memory_info().rss / (1024 * 1024)

        t_end = time.time() + duration_seconds
        cpu_readings = []

        # Run repeated batch inference
        batch = X_test[: min(5000, len(X_test))]
        while time.time() < t_end:
            _ = self.model.predict(batch)
            cpu_readings.append(process.cpu_percent(interval=0.05))

        ram_after_mb = process.memory_info().rss / (1024 * 1024)
        avg_cpu = float(np.mean(cpu_readings)) if cpu_readings else 0.0

        return {
            "ram_rss_mb": round(ram_after_mb, 2),
            "ram_delta_mb": round(max(0.0, ram_after_mb - ram_before_mb), 2),
            "sustained_cpu_percent": round(avg_cpu, 2),
        }


def compute_deployment_score(
    macro_f1: float,
    min_recall: float,
    latency_p95_ms: float,
    model_size_mb: float,
    ram_mb: float,
    max_latency_target_ms: float = 100.0,
) -> float:
    """
    Computes a composite Pareto Deployment Score in [0, 100].
    Prioritizes:
    - 40% Macro-F1 (detection quality across all classes)
    - 20% Minimum per-class recall (minority attack safety)
    - 20% Latency compliance (target: well under 100 ms)
    - 10% Model compactness (< 10 MB)
    - 10% RAM compactness (< 500 MB)
    """
    # Detection score (0 - 60)
    score_f1 = macro_f1 * 40.0
    score_rec = min_recall * 20.0

    # Latency score (0 - 20)
    if latency_p95_ms <= 1.0:
        score_lat = 20.0
    elif latency_p95_ms <= 10.0:
        score_lat = 18.0
    elif latency_p95_ms <= max_latency_target_ms:
        score_lat = 20.0 * (1.0 - (latency_p95_ms / max_latency_target_ms))
    else:
        score_lat = 0.0

    # Model size score (0 - 10)
    if model_size_mb <= 1.0:
        score_size = 10.0
    elif model_size_mb <= 10.0:
        score_size = 8.0
    elif model_size_mb <= 50.0:
        score_size = 5.0
    else:
        score_size = 2.0

    # RAM score (0 - 10)
    if ram_mb <= 200.0:
        score_ram = 10.0
    elif ram_mb <= 500.0:
        score_ram = 8.0
    else:
        score_ram = 5.0

    total_score = score_f1 + score_rec + score_lat + score_size + score_ram
    return round(float(total_score), 2)
