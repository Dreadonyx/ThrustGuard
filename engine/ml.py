"""
engine/ml.py — IsolationForest Anomaly Detection
Eclipse — IoT Trust Scoring Engine

Design:
  - Models are PRE-TRAINED and pickled. Never retrained live.
  - One model per device class (camera, bulb, sensor)
  - Scores a window in <1ms (decision_function on a single vector)
  - Returns None on normal, dict with deduction on anomaly

Feature vector (8 features — fixed order, do not change):
  [bytes, packets, dns_entropy, unique_dest_ips, z_score, ewma_delta, new_ip_flag, spike_delta]
"""

import pickle
import logging
import os
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

# Threshold below which a window is considered anomalous
# IsolationForest.decision_function returns:
#   >  0  → very normal
#   ~  0  → borderline
#   < -0.1 → anomalous (our threshold)
#   < -0.3 → strongly anomalous (dns_tunnel attack lands around -0.43)
ANOMALY_THRESHOLD = -0.1
ML_DEDUCTION = 8  # points deducted from trust score on anomaly

# Maps device_type → pickle path
MODEL_PATHS = {
    "camera": "models/cam_baseline.pkl",
    "bulb":   "models/bulb_baseline.pkl",
    "sensor": "models/sensor_baseline.pkl",
}

# Feature order is FIXED — must match train_models.py exactly
FEATURE_ORDER = [
    "bytes",
    "packets",
    "dns_entropy",
    "unique_dest_ips",
    "z_score",
    "ewma_delta",
    "new_ip_flag",
    "spike_delta",
]


class MLEngine:
    """
    Loads all IsolationForest models at startup.
    Scores any device_window in a single call.

    Usage:
        ml = MLEngine()
        ml.load_models()
        result = ml.score_anomaly(device_window)
    """

    def __init__(self):
        self.models: dict = {}   # device_type → sklearn IsolationForest
        self._loaded = False

    def load_models(self) -> None:
        """
        Load all pickled models. Called once at startup.
        Crashes hard if any model is missing — run train_models.py first.
        """
        for device_type, path in MODEL_PATHS.items():
            if not os.path.exists(path):
                raise FileNotFoundError(
                    f"[MLEngine] Model missing: {path}\n"
                    f"Run: python train_models.py"
                )
            with open(path, "rb") as f:
                self.models[device_type] = pickle.load(f)
            logger.info(f"[MLEngine] Loaded {path}")

        self._loaded = True
        logger.info("[MLEngine] All models loaded.")

    def _extract_feature_vector(self, window: dict) -> np.ndarray:
        """
        Extract fixed 8-feature vector from device_window dict.
        Converts new_ip_flag bool → 0/1 int.
        """
        vec = []
        for feat in FEATURE_ORDER:
            val = window.get(feat, 0)
            if isinstance(val, bool):
                val = int(val)
            vec.append(float(val))
        return np.array(vec).reshape(1, -1)

    def score_anomaly(self, window: dict) -> Optional[dict]:
        """
        Score a device_window against the pre-trained model for its device_type.

        Returns:
            None if normal (decision_function >= ANOMALY_THRESHOLD)
            dict {"reason": str, "deduction": int, "if_score": float} if anomalous
        """
        if not self._loaded:
            logger.warning("[MLEngine] Models not loaded — skipping ML score")
            return None

        device_type = window.get("device_type", "camera")
        model = self.models.get(device_type)
        if model is None:
            logger.warning(f"[MLEngine] No model for device_type={device_type}")
            return None

        features = self._extract_feature_vector(window)
        if_score = float(model.decision_function(features)[0])

        logger.debug(
            f"[MLEngine] {window.get('device_id')} IF score={if_score:.4f} "
            f"(threshold={ANOMALY_THRESHOLD})"
        )

        if if_score < ANOMALY_THRESHOLD:
            severity = "mild" if if_score > -0.25 else "severe"
            return {
                "reason": f"ML anomaly [{severity}] IF score {if_score:.3f} < {ANOMALY_THRESHOLD}",
                "deduction": ML_DEDUCTION,
                "if_score": if_score,
            }

        return None

    def batch_score(self, windows: list[dict]) -> list[Optional[dict]]:
        """
        Score a batch of windows. Used in verify_ml.py and training validation.
        """
        return [self.score_anomaly(w) for w in windows]

    def raw_decision_scores(self, windows: list[dict], device_type: str = "camera") -> np.ndarray:
        """
        Return raw IF decision scores for a list of windows (for analysis/plotting).
        Used in verify_ml.py to show score distributions.
        """
        if not self._loaded:
            raise RuntimeError("Models not loaded")
        model = self.models[device_type]
        matrix = np.array([
            self._extract_feature_vector(w)[0] for w in windows
        ])
        return model.decision_function(matrix)
