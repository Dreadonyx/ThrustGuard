"""
data/synthetic.py — Eclipse IoT Traffic Simulator
Generates realistic device_window dicts every 60s per device.
Feeds directly into engine/features.py (no HTTP, direct import).

Devices:
  cam-01    camera   normal baseline  → TRUSTED
  cam-02    camera   attack target    → starts TRUSTED, hit via simulate_attack.py
  bulb-01   bulb     normal baseline  → TRUSTED
  bulb-02   bulb     slight drift     → floats around MONITOR
  sensor-01 sensor   normal baseline  → TRUSTED

All 5 start in CALIBRATING (burn-in). Features module handles suppression.
"""

import time
import math
import random
import threading
import logging
from typing import Callable

logger = logging.getLogger("eclipse.synthetic")

# ─────────────────────────────────────────────
# Device registry
# ─────────────────────────────────────────────

DEVICES = [
    {"device_id": "cam-01",    "device_type": "camera",  "profile": "camera_normal"},
    {"device_id": "cam-02",    "device_type": "camera",  "profile": "camera_normal"},
    {"device_id": "bulb-01",   "device_type": "bulb",    "profile": "bulb_normal"},
    {"device_id": "bulb-02",   "device_type": "bulb",    "profile": "bulb_drift"},
    {"device_id": "sensor-01", "device_type": "sensor",  "profile": "sensor_normal"},
]

WINDOW_INTERVAL = 60  # seconds between windows per device

# ─────────────────────────────────────────────
# Normal distribution parameters
# Tight σ is CRITICAL for IsolationForest sensitivity
# ─────────────────────────────────────────────

PROFILES = {
    "camera_normal": {
        "bytes_mu":           1_000_000,
        "bytes_sigma":        50_000,
        "packets_mu":         120,
        "packets_sigma":      5,
        "dns_entropy_mu":     2.1,
        "dns_entropy_sigma":  0.10,
        "unique_dest_ips":    (1, 3),   # randint range (inclusive)
        "ports":              [443],    # fixed allowed ports
        "new_ip_prob":        0.0,      # probability new_ip_flag = True
    },
    "bulb_normal": {
        "bytes_mu":           50_000,
        "bytes_sigma":        3_000,
        "packets_mu":         30,
        "packets_sigma":      3,
        "dns_entropy_mu":     1.4,
        "dns_entropy_sigma":  0.08,
        "unique_dest_ips":    (1, 2),
        "ports":              [443, 80],
        "new_ip_prob":        0.0,
    },
    "bulb_drift": {
        # Slightly elevated — meant to sit in MONITOR tier during demo
        "bytes_mu":           75_000,
        "bytes_sigma":        8_000,
        "packets_mu":         38,
        "packets_sigma":      5,
        "dns_entropy_mu":     1.8,
        "dns_entropy_sigma":  0.15,
        "unique_dest_ips":    (1, 3),
        "ports":              [443, 80],
        "new_ip_prob":        0.02,
    },
    "sensor_normal": {
        "bytes_mu":           10_000,
        "bytes_sigma":        800,
        "packets_mu":         15,
        "packets_sigma":      2,
        "dns_entropy_mu":     1.2,
        "dns_entropy_sigma":  0.06,
        "unique_dest_ips":    (1, 2),
        "ports":              [443],
        "new_ip_prob":        0.0,
    },
}

# ─────────────────────────────────────────────
# Per-device state (ewma, prev_bytes)
# ─────────────────────────────────────────────

_device_state: dict[str, dict] = {}

def _get_state(device_id: str, initial_bytes: float) -> dict:
    if device_id not in _device_state:
        _device_state[device_id] = {
            "prev_bytes": initial_bytes,
            "ewma":       initial_bytes,
            "baseline_samples": [],
        }
    return _device_state[device_id]


# ─────────────────────────────────────────────
# Feature helpers
# ─────────────────────────────────────────────

def _clamp(val: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, val))

def _gauss(mu: float, sigma: float) -> float:
    return random.gauss(mu, sigma)

def _compute_derived(bytes_val: float, state: dict) -> tuple[float, float, float]:
    """Returns (z_score, ewma_delta, spike_delta)"""
    alpha = 0.3
    prev_bytes = state["prev_bytes"]
    prev_ewma  = state["ewma"]

    samples = state["baseline_samples"]

    # z_score — needs at least 2 samples
    if len(samples) >= 2:
        mu  = sum(samples) / len(samples)
        std = math.sqrt(sum((x - mu) ** 2 for x in samples) / len(samples))
        z   = (bytes_val - mu) / std if std > 0 else 0.0
    else:
        z = 0.0

    # ewma
    new_ewma    = alpha * bytes_val + (1 - alpha) * prev_ewma
    ewma_delta  = abs(bytes_val - new_ewma) / new_ewma if new_ewma > 0 else 0.0

    # spike
    spike_delta = (bytes_val - prev_bytes) / prev_bytes if prev_bytes > 0 else 0.0

    # update state
    state["prev_bytes"] = bytes_val
    state["ewma"]       = new_ewma
    samples.append(bytes_val)
    if len(samples) > 50:      # rolling window cap
        samples.pop(0)

    return (
        round(_clamp(z,           -10.0, 10.0), 4),
        round(_clamp(ewma_delta,    0.0,  5.0), 4),
        round(_clamp(spike_delta,  -1.0, 10.0), 4),
    )


# ─────────────────────────────────────────────
# Window generator
# ─────────────────────────────────────────────

def generate_window(device_id: str, device_type: str, profile_name: str) -> dict:
    """
    Produces one device_window dict matching the shared data contract exactly.
    Matches the shape expected by engine/features.py.
    """
    p = PROFILES[profile_name]

    bytes_val   = max(1, int(_gauss(p["bytes_mu"],        p["bytes_sigma"])))
    packets_val = max(1, int(_gauss(p["packets_mu"],      p["packets_sigma"])))
    entropy_val = round(_clamp(_gauss(p["dns_entropy_mu"], p["dns_entropy_sigma"]), 0.0, 5.0), 4)

    unique_ips  = random.randint(*p["unique_dest_ips"])
    new_ip_flag = random.random() < p["new_ip_prob"]
    ports_used  = list(p["ports"])

    state = _get_state(device_id, bytes_val)
    z_score, ewma_delta, spike_delta = _compute_derived(bytes_val, state)

    window = {
        "device_id":       device_id,
        "device_type":     device_type,
        "timestamp":       int(time.time()),
        "bytes":           bytes_val,
        "packets":         packets_val,
        "unique_dest_ips": unique_ips,
        "dns_entropy":     entropy_val,
        "ports_used":      ports_used,
        "new_ip_flag":     new_ip_flag,
        "ewma_delta":      ewma_delta,
        "z_score":         z_score,
        "spike_delta":     spike_delta,
    }

    logger.debug(
        "[synthetic] %s | bytes=%d | z=%.2f | entropy=%.2f | ports=%s",
        device_id, bytes_val, z_score, entropy_val, ports_used
    )
    return window


# ─────────────────────────────────────────────
# Feed loop — runs in background thread
# ─────────────────────────────────────────────

def run_feed(callback: Callable[[dict], None], interval: int = WINDOW_INTERVAL) -> None:
    """
    Background thread entry point.
    Calls callback(device_window) for each device every `interval` seconds.

    Usage in main.py:
        from data.synthetic import run_feed
        from engine.features import enrich_window
        t = threading.Thread(target=run_feed, args=(enrich_window,), daemon=True)
        t.start()
    """
    logger.info("[synthetic] Feed loop started — %d devices, %ds interval", len(DEVICES), interval)

    # Stagger device windows so they don't all fire at once
    stagger = interval / len(DEVICES)

    while True:
        for i, device in enumerate(DEVICES):
            # Sleep stagger between each device so TUI updates feel live
            time.sleep(stagger)
            try:
                window = generate_window(
                    device["device_id"],
                    device["device_type"],
                    device["profile"],
                )
                callback(window)
            except Exception as exc:  # never crash the feed thread
                logger.error("[synthetic] Error generating window for %s: %s", device["device_id"], exc)


# ─────────────────────────────────────────────
# Standalone smoke test
# python -m data.synthetic
# ─────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    print("=== synthetic.py smoke test — one window per device ===\n")
    for d in DEVICES:
        w = generate_window(d["device_id"], d["device_type"], d["profile"])
        print(f"{w['device_id']:12s}  bytes={w['bytes']:>9,}  z={w['z_score']:+.3f}  "
              f"entropy={w['dns_entropy']:.3f}  ports={w['ports_used']}  "
              f"new_ip={w['new_ip_flag']}")