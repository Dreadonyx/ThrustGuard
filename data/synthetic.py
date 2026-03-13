"""
data/synthetic.py — Training Data Generator
Generates realistic normal IoT traffic logs for behavior modeling.
"""

import json
import random
import time
import os
from pathlib import Path

LOG_DIR = Path("logs/synthetic")

DEVICE_PROFILES = {
    "camera": {
        "bytes_range": (800_000, 1_200_000),
        "packets_range": (100, 150),
        "ports": [443, 80],
        "ips": ["192.168.1.10", "1.1.1.1"],
        "entropy_range": (2.0, 2.5)
    },
    "bulb": {
        "bytes_range": (5_000, 15_000),
        "packets_range": (5, 15),
        "ports": [8883],
        "ips": ["192.168.1.2"],
        "entropy_range": (1.0, 1.5)
    },
    "sensor": {
        "bytes_range": (1_000, 5_000),
        "packets_range": (2, 8),
        "ports": [1883],
        "ips": ["192.168.1.1"],
        "entropy_range": (0.5, 1.0)
    }
}

def generate_window(device_type: str, device_id: str) -> dict:
    profile = DEVICE_PROFILES[device_type]
    
    bytes_val = random.randint(*profile["bytes_range"])
    packets = random.randint(*profile["packets_range"])
    dns_entropy = random.uniform(*profile["entropy_range"])
    
    return {
        "device_id": device_id,
        "device_type": device_type,
        "bytes": bytes_val,
        "packets": packets,
        "ports": profile["ports"],
        "dst_ips": profile["ips"],
        "dns_queries": ["api.iot.com", "pool.ntp.org"],
        "dns_entropy": round(dns_entropy, 2),
        "timestamp": int(time.time())
    }

def run_generator(windows_per_type: int = 200):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    for device_type in DEVICE_PROFILES:
        file_path = LOG_DIR / f"{device_type}_normal.jsonl"
        print(f"[*] Generating {windows_per_type} windows for {device_type} -> {file_path}")
        
        with open(file_path, "w") as f:
            for i in range(windows_per_type):
                window = generate_window(device_type, f"{device_type}-sim")
                # Slightly jitter the timestamp backwards to simulate a time series
                window["timestamp"] -= (windows_per_type - i) * 60
                f.write(json.dumps(window) + "\n")

if __name__ == "__main__":
    run_generator()
