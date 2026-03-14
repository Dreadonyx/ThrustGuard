"""
engine/ml.py — IsolationForest Inference
"""

import joblib
from pathlib import Path

MODEL_DIR = Path("models")

class MLEngine:
    def __init__(self):
        self.models = {}

    def load_models(self):
        for p in MODEL_DIR.glob("*.pkl"):
            device_type = p.stem.split("_")[0]
            self.models[device_type] = joblib.load(p)
            print(f"[*] Loaded model for {device_type}")

    def score(self, window: dict) -> dict:
        device_type = window["device_type"]
        if device_type not in self.models:
            return None
            
        model = self.models[device_type]
        
        # Features: [bytes, packets, port_count, dns_entropy, unique_ips, packet_byte_ratio]
        def _get_count(val):
            if isinstance(val, (int, float)): return int(val)
            if hasattr(val, "__len__"): return len(val)
            return 0

        features = [[
            window["bytes"],
            window["packets"],
            _get_count(window.get("ports_used", 0)),
            window["dns_entropy"],
            _get_count(window.get("unique_dest_ips", 0)),
            window["packets"] / max(1, window["bytes"])
        ]]
        
        # decision_function returns negative values for anomalies
        raw_score = float(model.decision_function(features)[0])
        
        if raw_score < -0.1:
            return {
                "type": "ml_anomaly",
                "penalty": -8,
                "raw_score": round(raw_score, 3)
            }
        return None
