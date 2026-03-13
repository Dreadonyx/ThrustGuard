"""
verify_ml.py — Pre-demo IsolationForest sanity check
Run this before EVERY demo to confirm models are behaving correctly.

Usage:
  python verify_ml.py

Expected output:
  Testing IsolationForest models...
  cam_baseline.pkl  → normal: +0.082 ✅ | attack: -0.431 ✅
  bulb_baseline.pkl → normal: +0.071 ✅ | attack: -0.388 ✅
  sensor_baseline.pkl → normal: +0.065 ✅ | attack: -0.412 ✅
  ✅ All models verified. Safe to demo.
"""

import pickle
import os
import sys
import numpy as np

FEATURE_ORDER = [
    "bytes", "packets", "dns_entropy", "unique_dest_ips",
    "z_score", "ewma_delta", "new_ip_flag", "spike_delta",
]

MODELS = {
    "cam_baseline.pkl":    ("camera",  "models/cam_baseline.pkl"),
    "bulb_baseline.pkl":   ("bulb",    "models/bulb_baseline.pkl"),
    "sensor_baseline.pkl": ("sensor",  "models/sensor_baseline.pkl"),
}

NORMAL_WINDOWS = {
    "camera": {"bytes": 1_000_000, "packets": 120, "dns_entropy": 2.1, "unique_dest_ips": 2, "z_score": 0.8, "ewma_delta": 0.01, "new_ip_flag": 0, "spike_delta": 0.0},
    "bulb":   {"bytes": 50_000,    "packets": 20,  "dns_entropy": 1.2, "unique_dest_ips": 1, "z_score": 0.5, "ewma_delta": 0.005,"new_ip_flag": 0, "spike_delta": 0.0},
    "sensor": {"bytes": 10_000,    "packets": 8,   "dns_entropy": 0.8, "unique_dest_ips": 1, "z_score": 0.3, "ewma_delta": 0.003,"new_ip_flag": 0, "spike_delta": 0.0},
}

ATTACK_WINDOWS = {
    "camera": {"bytes": 9_000_000, "packets": 9000, "dns_entropy": 4.9, "unique_dest_ips": 47, "z_score": 8.4, "ewma_delta": 2.8, "new_ip_flag": 1, "spike_delta": 7.0},
    "bulb":   {"bytes": 800_000,   "packets": 4000, "dns_entropy": 4.2, "unique_dest_ips": 30, "z_score": 7.1, "ewma_delta": 2.1, "new_ip_flag": 1, "spike_delta": 15.0},
    "sensor": {"bytes": 200_000,   "packets": 1500, "dns_entropy": 3.8, "unique_dest_ips": 20, "z_score": 6.5, "ewma_delta": 1.8, "new_ip_flag": 1, "spike_delta": 19.0},
}

THRESHOLD = -0.1


def to_vec(window: dict) -> np.ndarray:
    return np.array([float(window.get(f, 0)) for f in FEATURE_ORDER]).reshape(1, -1)


def main():
    print("Testing IsolationForest models...\n")
    all_ok = True

    for pkl_name, (device_class, path) in MODELS.items():
        if not os.path.exists(path):
            print(f"  ❌ {pkl_name} — NOT FOUND. Run: python train_models.py")
            all_ok = False
            continue

        with open(path, "rb") as f:
            clf = pickle.load(f)

        normal_score = float(clf.decision_function(to_vec(NORMAL_WINDOWS[device_class]))[0])
        attack_score = float(clf.decision_function(to_vec(ATTACK_WINDOWS[device_class]))[0])

        ok_n = normal_score > THRESHOLD
        ok_a = attack_score < THRESHOLD

        icon_n = "✅" if ok_n else "❌"
        icon_a = "✅" if ok_a else "❌"

        print(f"  {pkl_name:<22} → normal: {normal_score:+.3f} {icon_n} | attack: {attack_score:+.3f} {icon_a}")

        if not ok_n:
            print(f"    ⚠ Normal window flagged — model may be overtrained. Retrain.")
        if not ok_a:
            print(f"    ⚠ Attack window not detected. Check ATTACK_PROFILES in train_models.py.")

        if not (ok_n and ok_a):
            all_ok = False

    print()
    if all_ok:
        print("✅ All models verified. Safe to demo.")
    else:
        print("❌ Verification failed. Run: python train_models.py")
        sys.exit(1)


if __name__ == "__main__":
    main()
