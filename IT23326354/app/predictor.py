"""
predictor.py — High-performance model predictor loaded once in memory
Project: J26-CS-330 | Component: DoS Detection via SDN Flow Analysis
"""

import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import joblib
import numpy as np

logger = logging.getLogger(__name__)


class DoSPredictor:
    """
    Thread-safe predictor instance loaded once at FastAPI startup.
    Avoids re-instantiating or reading model files per request.
    """
    def __init__(
        self,
        model_path: Union[str, Path],
        preprocessor_path: Union[str, Path],
        schema_path: Union[str, Path],
    ):
        self.model_path = Path(model_path)
        self.preprocessor_path = Path(preprocessor_path)
        self.schema_path = Path(schema_path)

        self.model = None
        self.preprocessor = None
        self.feature_names = []
        self.is_loaded = False
        self.load_error = None

        self._load()

    def _load(self):
        """Load model, preprocessor, and schema."""
        try:
            if not self.schema_path.exists():
                raise FileNotFoundError(f"Feature schema not found at: {self.schema_path}")
            with open(self.schema_path, "r") as f:
                schema_data = json.load(f)
            self.feature_names = schema_data["feature_names"]

            if not self.model_path.exists():
                raise FileNotFoundError(f"Model file not found at: {self.model_path}")
            self.model = joblib.load(self.model_path)

            if not self.preprocessor_path.exists():
                raise FileNotFoundError(f"Preprocessor file not found at: {self.preprocessor_path}")
            self.preprocessor = joblib.load(self.preprocessor_path)

            self.is_loaded = True
            logger.info(f"Loaded XGBoost model from {self.model_path} with {len(self.feature_names)} features.")
        except Exception as e:
            self.is_loaded = False
            self.load_error = str(e)
            logger.error(f"Failed to load predictor artifacts: {e}")

    def predict(self, features_dict: Dict[str, Union[int, float]]) -> Dict[str, Union[str, bool, float]]:
        """
        Execute prediction on incoming flow dictionary.
        Returns:
            dict containing prediction label, is_dos flag, confidence, latency_ms
        """
        if not self.is_loaded:
            raise RuntimeError(f"Predictor model is not loaded: {self.load_error}")

        # Construct feature vector in exact schema order
        vector = []
        protocol_encoder = self.preprocessor.get("protocol_encoder") if self.preprocessor else None

        for name in self.feature_names:
            val = features_dict.get(name, 0.0)
            if val is None:
                val = 0.0
            if name == "Protocol Type" and protocol_encoder is not None:
                try:
                    str_val = str(val)
                    if str_val in protocol_encoder.classes_:
                        val = float(protocol_encoder.transform([str_val])[0])
                    else:
                        val = 0.0
                except Exception:
                    val = 0.0
            vector.append(float(val))

        X = np.array(vector, dtype=np.float32).reshape(1, -1)

        # Isolated timing measurement
        t0 = time.perf_counter()
        probs = self.model.predict_proba(X)[0]
        raw_pred = int(self.model.predict(X)[0])
        t1 = time.perf_counter()

        latency_ms = (t1 - t0) * 1000.0

        # Class 1 = DoS, Class 0 = Normal
        pos_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
        is_dos = bool(raw_pred == 1)
        pred_label = "DoS" if is_dos else "Normal"
        confidence = pos_prob if is_dos else (1.0 - pos_prob)

        return {
            "prediction": pred_label,
            "is_dos": is_dos,
            "confidence": round(confidence, 4),
            "inference_latency_ms": round(latency_ms, 3),
            "model_name": "XGBoost",
        }
