"""
train_models.py — Pre-train IsolationForest models for Eclipse
Run ONCE before demo. Never run live during demo.

What this does:
  1. Generates 500 synthetic "normal" windows per device class
     using tight distributions matching real IoT behavior
  2. Trains an IsolationForest on each class (contamination=0.05)
  3. Pickles each model to models/{class}_baseline.pkl
  4. Runs a quick sanity check — if any assertion fails, prints a warning

Usage:
  python train_models.py

Expected output:
  [camera]  Training on 500 normal windows...
  [camera]  Normal score : 0.082  ✅ (> -0.1)
  [camera]  Attack score : -0.431 ✅ (< -0.1)
  [bulb]    ...
  [sensor]  ...
  ✅ All models trained and verified. Safe to demo.
"""

import os
import pickle
import numpy as np
from sklearn.ensemble import IsolationForest

# ─── Normal traffic distributions per device class ───────────────────────────
# KEEP THESE TIGHT. Wide sigmas = poor IF sensitivity.
# These match synthetic.py's camera_normal/bulb_normal/sensor_normal params.

NORMAL_PROFILES = {
    "camera": {
        "bytes":           (1_000_000, 50_000),   # (mean, std)
        "packets":         (120, 5),
        "dns_entropy":     (2.1, 0.1),
        "unique_dest_ips": (2, 0.5),              # clamped to int 1-3
        "z_score":         (0.8, 0.2),
        "ewma_delta":      (0.01, 0.005),
        "new_ip_flag":     0,                     # always 0 during normal
        "spike_delta":     (0.0, 0.05),
    },
    "bulb": {
        "bytes":           (50_000, 5_000),
        "packets":         (20, 3),
        "dns_entropy":     (1.2, 0.1),
        "unique_dest_ips": (1, 0.3),
        "z_score":         (0.5, 0.15),
        "ewma_delta":      (0.005, 0.002),
        "new_ip_flag":     0,
        "spike_delta":     (0.0, 0.02),
    },
    "sensor": {
        "bytes":           (10_000, 1_000),
        "packets":         (8, 2),
        "dns_entropy":     (0.8, 0.1),
        "unique_dest_ips": (1, 0.2),
        "z_score":         (0.3, 0.1),
        "ewma_delta":      (0.003, 0.001),
        "new_ip_flag":     0,
        "spike_delta":     (0.0, 0.01),
    },
}

# ─── Attack fingerprints per class ────────────────────────────────────────────
# These must land FAR outside the normal envelope.
# Used only in the post-training sanity check, not in training data.

ATTACK_PROFILES = {
    "camera": {
        "bytes": 9_000_000, "packets": 9000,
        "dns_entropy": 4.9, "unique_dest_ips": 47,
        "z_score": 8.4, "ewma_delta": 2.8,
        "new_ip_flag": 1, "spike_delta": 7.0,
    },
    "bulb": {
        "bytes": 800_000, "packets": 4000,
        "dns_entropy": 4.2, "unique_dest_ips": 30,
        "z_score": 7.1, "ewma_delta": 2.1,
        "new_ip_flag": 1, "spike_delta": 15.0,
    },
    "sensor": {
        "bytes": 200_000, "packets": 1500,
        "dns_entropy": 3.8, "unique_dest_ips": 20,
        "z_score": 6.5, "ewma_delta": 1.8,
        "new_ip_flag": 1, "spike_delta": 19.0,
    },
}

# ─── Feature order — FIXED. Must match engine/ml.py exactly. ─────────────────
FEATURE_ORDER = [
    "bytes", "packets", "dns_entropy", "unique_dest_ips",
    "z_score", "ewma_delta", "new_ip_flag", "spike_delta",
]

MODEL_OUTPUT_PATHS = {
    "camera": "models/cam_baseline.pkl",
    "bulb":   "models/bulb_baseline.pkl",
    "sensor": "models/sensor_baseline.pkl",
}


def generate_normal_windows(profile: dict, n: int = 500, seed: int = 42) -> np.ndarray:
    """
    Generate N synthetic normal windows from the given profile.
    Returns an ndarray of shape (n, 8).

    For each feature:
      - If value is a tuple (mean, std) → sample Normal(mean, std)
      - If value is a scalar 0 → column of zeros (new_ip_flag)
    """
    rng = np.random.default_rng(seed)
    rows = []
    for _ in range(n):
        row = []
        for feat in FEATURE_ORDER:
            spec = profile[feat]
            if isinstance(spec, tuple):
                mean, std = spec
                val = rng.normal(mean, std)
                # Clamp to reasonable positives
                if feat in ("unique_dest_ips",):
                    val = max(1, round(val))
                elif feat in ("packets",):
                    val = max(1, val)
                elif feat in ("bytes",):
                    val = max(1000, val)
                else:
                    val = max(0.0, val)
            else:
                val = float(spec)
            row.append(val)
        rows.append(row)
    return np.array(rows)


def window_to_vector(window_dict: dict) -> np.ndarray:
    """Convert a window dict → feature vector (1, 8)."""
    vec = []
    for feat in FEATURE_ORDER:
        val = window_dict.get(feat, 0)
        if isinstance(val, bool):
            val = int(val)
        vec.append(float(val))
    return np.array(vec).reshape(1, -1)


def train_and_save(device_class: str, n: int = 500) -> IsolationForest:
    """Train IF on normal windows, save pickle, return model."""
    print(f"\n[{device_class}]  Generating {n} normal windows...")
    profile = NORMAL_PROFILES[device_class]
    X_normal = generate_normal_windows(profile, n=n)

    print(f"[{device_class}]  Training IsolationForest (contamination=0.05)...")
    clf = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_normal)

    # Save pickle
    out_path = MODEL_OUTPUT_PATHS[device_class]
    with open(out_path, "wb") as f:
        pickle.dump(clf, f)
    print(f"[{device_class}]  Saved → {out_path}")

    return clf


def verify_model(clf: IsolationForest, device_class: str) -> bool:
    """
    Quick sanity check:
      - A normal window should score > ANOMALY_THRESHOLD (-0.1)
      - An attack window should score < ANOMALY_THRESHOLD (-0.1)
    Returns True if both assertions pass.
    """
    threshold = -0.1
    normal_profile = NORMAL_PROFILES[device_class]
    attack_profile = ATTACK_PROFILES[device_class]

    # Use mean values for normal window (should score well above threshold)
    normal_window = {
        feat: (spec[0] if isinstance(spec, tuple) else spec)
        for feat, spec in normal_profile.items()
    }
    attack_window = attack_profile.copy()

    normal_score = float(clf.decision_function(window_to_vector(normal_window))[0])
    attack_score = float(clf.decision_function(window_to_vector(attack_window))[0])

    ok_normal = normal_score > threshold
    ok_attack = attack_score < threshold

    status_n = "✅" if ok_normal else "❌"
    status_a = "✅" if ok_attack else "❌"

    print(f"[{device_class}]  Normal score : {normal_score:+.3f}  {status_n} (should be > {threshold})")
    print(f"[{device_class}]  Attack score : {attack_score:+.3f}  {status_a} (should be < {threshold})")

    if not ok_normal:
        print(f"  ⚠ Normal window is being flagged as anomalous — tighten training distributions")
    if not ok_attack:
        print(f"  ⚠ Attack window not detected — check attack profile is outside normal envelope")

    return ok_normal and ok_attack


def main():
    os.makedirs("models", exist_ok=True)

    all_ok = True
    for device_class in ["camera", "bulb", "sensor"]:
        clf = train_and_save(device_class)
        ok = verify_model(clf, device_class)
        if not ok:
            all_ok = False
        print()

    if all_ok:
        print("✅ All models trained and verified. Safe to demo.")
    else:
        print("❌ One or more models failed verification.")
        print("   Check the distributions in NORMAL_PROFILES and ATTACK_PROFILES.")
        exit(1)


if __name__ == "__main__":
    main()
