"""
engine/features.py — Feature Enrichment & State Management
Orchestrates scoring and atomic JSON writes.
"""

import os
import json
import time
from pathlib import Path
from datetime import datetime
from engine.policy import PolicyEngine
from engine.drift import DriftEngine
from engine.ml import MLEngine

LIVE_LOG_DIR = Path("logs/live")
EWMA_ALPHA = 0.3

class FeaturePipeline:
    def __init__(self):
        self.policy = PolicyEngine()
        self.drift = DriftEngine()
        self.ml = MLEngine()
        self.ml.load_models()
        self.device_states = {} # id -> stats

    def _get_state(self, device_id: str):
        if device_id not in self.device_states:
            # Seed from history if exists
            state = self._load_last_state(device_id)
            self.device_states[device_id] = state
        return self.device_states[device_id]

    def _load_last_state(self, device_id: str):
        # Realistic Seeds based on data/synthetic.py profiles
        profiles = {
            "camera": {"mean": 1000000, "std": 50000},
            "bulb":   {"mean": 10000,   "std": 2000},
            "sensor": {"mean": 3000,    "std": 1000},
            "unknown": {"mean": 100000, "std": 5000}
        }
        
        # Try to guess type from id if not known
        dev_type = "unknown"
        if "cam" in device_id: dev_type = "camera"
        elif "bulb" in device_id: dev_type = "bulb"
        elif "sensor" in device_id: dev_type = "sensor"

        default_state = {
            "score": 100,
            "prev_bytes": profiles[dev_type]["mean"],
            "ewma": profiles[dev_type]["mean"],
            "mean": profiles[dev_type]["mean"],
            "std": profiles[dev_type]["std"]
        }

        history_path = LIVE_LOG_DIR / f"{device_id}.jsonl"
        if history_path.exists():
            try:
                with open(history_path, "r") as f:
                    lines = f.readlines()
                    if lines:
                        last_line = lines[-1].strip()
                        if not last_line and len(lines) > 1:
                            last_line = lines[-2].strip()
                        
                        if last_line:
                            last = json.loads(last_line)
                            return {
                                "score": last.get("trust_score", 100),
                                "prev_bytes": last["features"].get("bytes", 0),
                                "ewma": last["features"].get("ewma_delta", default_state["mean"]), # Corrected key
                                "mean": default_state["mean"],
                                "std": default_state["std"]
                            }
            except Exception as e:
                print(f"[!] Error loading state: {e}")
        
        return default_state

    def process_window(self, raw_window: dict):
        dev_id = raw_window["device_id"]
        state = self._get_state(dev_id)
        
        # ── 1. Enrichment ───────────────────────────────────────────────────
        bytes_val = raw_window["bytes"]
        
        # Z-Score
        z = abs(bytes_val - state["mean"]) / max(1, state["std"])
        
        # EWMA
        new_ewma = (EWMA_ALPHA * bytes_val) + ((1 - EWMA_ALPHA) * state["ewma"])
        ewma_delta = abs(bytes_val - new_ewma) / max(1, new_ewma)
        state["ewma"] = new_ewma
        
        # Spike
        spike_delta = (bytes_val - state["prev_bytes"]) / max(1, state["prev_bytes"])
        state["prev_bytes"] = bytes_val
        
        enriched = {
            **raw_window,
            "z_score": round(z, 2),
            "ewma_delta": round(ewma_delta, 2),
            "spike_delta": round(spike_delta, 2)
        }

        # ── 2. Scoring ──────────────────────────────────────────────────────
        violations = self.policy.check(enriched)
        signals = self.drift.check(enriched)
        ml_res = self.ml.score(enriched)
        
        penalty_sum = sum(v["penalty"] for v in violations) + sum(s["penalty"] for s in signals)
        if ml_res:
            penalty_sum += ml_res["penalty"]
            
        if penalty_sum == 0:
            state["score"] = min(100, state["score"] + 2)
        else:
            state["score"] = max(0, state["score"] + penalty_sum)
            
        # ── 3. Assembly ─────────────────────────────────────────────────────
        tier = "TRUSTED"
        if state["score"] < 40: tier = "HIGH RISK"
        elif state["score"] < 60: tier = "SUSPICIOUS"
        elif state["score"] < 80: tier = "MONITOR"
        
        output = {
            "timestamp": datetime.now().isoformat(),
            "device_id": dev_id,
            "device_type": raw_window["device_type"],
            "trust_score": state["score"],
            "tier": tier,
            "violations": violations,
            "signals": signals,
            "ml_score": ml_res["raw_score"] if ml_res else 0,
            "features": {
                "bytes": bytes_val,
                "packets": raw_window["packets"],
                "dns_entropy": raw_window["dns_entropy"],
                "z_score": enriched["z_score"],
                "ewma_delta": enriched["ewma_delta"],
                "spike_delta": enriched["spike_delta"]
            },
            "raw_window": raw_window
        }
        
        # ── 4. Storage ──────────────────────────────────────────────────────
        self._write_output(output)

    def _write_output(self, data: dict):
        dev_id = data["device_id"]
        LIVE_LOG_DIR.mkdir(parents=True, exist_ok=True)
        
        # 1. Append to .jsonl
        history_path = LIVE_LOG_DIR / f"{dev_id}.jsonl"
        with open(history_path, "a") as f:
            f.write(json.dumps(data) + "\n")
            
        # 2. Atomic Overwrite latest.json
        self._atomic_write(LIVE_LOG_DIR / f"{dev_id}_latest.json", data)
        
        # 3. Atomic Overwrite _all_latest.json
        all_latest_path = LIVE_LOG_DIR / "_all_latest.json"
        all_latest = {}
        if all_latest_path.exists():
            try:
                with open(all_latest_path) as f:
                    all_latest = json.load(f)
            except: pass
        
        all_latest[dev_id] = data
        self._atomic_write(all_latest_path, all_latest)

    def _atomic_write(self, path: Path, data: dict):
        tmp_path = path.with_suffix(".tmp")
        with open(tmp_path, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, path)
