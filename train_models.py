"""
train_models.py — Baseline ML Trainer
Trains IsolationForest models using normal traffic logs.
"""

import json
import joblib
import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest

SYNTHETIC_DIR = Path("logs/synthetic")
MODEL_DIR = Path("models")

def train():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    
    for device_type in ["camera", "bulb", "sensor"]:
        log_path = SYNTHETIC_DIR / f"{device_type}_normal.jsonl"
        if not log_path.exists():
            print(f"[!] Warning: {log_path} not found. Skip.")
            continue
            
        print(f"[*] Training model for {device_type}...")
        
        data = []
        with open(log_path) as f:
            for line in f:
                w = json.loads(line)
                # Feature Vector: [bytes, packets, port_count, dns_entropy, unique_ips, packet_byte_ratio]
                data.append([
                    w["bytes"],
                    w["packets"],
                    len(w["ports"]),
                    w["dns_entropy"],
                    len(w["dst_ips"]),
                    w["packets"] / max(1, w["bytes"])
                ])
        
        df = pd.DataFrame(data, columns=["bytes", "packets", "ports", "entropy", "ips", "ratio"])
        
        model = IsolationForest(
            n_estimators=100,
            contamination=0.01,
            random_state=42
        )
        model.fit(df)
        
        model_path = MODEL_DIR / f"{device_type}_baseline.pkl"
        joblib.dump(model, model_path)
        print(f"[+] Model saved: {model_path}")

if __name__ == "__main__":
    train()
