"""
seed_baseline.py — ThrushGuard Demo Seeder
Run once before demo to skip the 10-minute burn-in period.

What it does:
  - Injects 10 clean windows per device into the features engine
  - Each device transitions from CALIBRATING → ACTIVE immediately
  - Devices boot into TRUSTED with score ~100
  - Also seeds SQLite so TUI shows scores from second 1

Usage:
  python seed_baseline.py                    # seeds all 5 default devices
  python seed_baseline.py --devices cam-01,cam-02
  python seed_baseline.py --fast             # minimal output

Run this AFTER train_models.py and BEFORE python main.py
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

DEFAULT_DEVICES = [
    {"device_id": "cam-01",    "device_type": "camera"},
    {"device_id": "cam-02",    "device_type": "camera"},
    {"device_id": "bulb-01",   "device_type": "bulb"},
    {"device_id": "bulb-02",   "device_type": "bulb"},
    {"device_id": "sensor-01", "device_type": "sensor"},
]

# Normal window values per device type — must pass _is_clean_window
NORMAL_WINDOWS = {
    "camera": {
        "bytes": 1_000_000, "packets": 120,
        "dns_entropy": 2.1,  "unique_dest_ips": 2,
        "ports_used": [443], "new_ip_flag": False,
    },
    "bulb": {
        "bytes": 200_000,   "packets": 40,
        "dns_entropy": 1.8,  "unique_dest_ips": 1,
        "ports_used": [443], "new_ip_flag": False,
    },
    "sensor": {
        "bytes": 50_000,    "packets": 15,
        "dns_entropy": 1.5,  "unique_dest_ips": 1,
        "ports_used": [443], "new_ip_flag": False,
    },
    "thermostat": {
        "bytes": 100_000,   "packets": 20,
        "dns_entropy": 1.6,  "unique_dest_ips": 1,
        "ports_used": [443], "new_ip_flag": False,
    },
    "router": {
        "bytes": 5_000_000, "packets": 800,
        "dns_entropy": 2.5,  "unique_dest_ips": 8,
        "ports_used": [443, 80, 53], "new_ip_flag": True,
    },
    "lock": {
        "bytes": 20_000,    "packets": 8,
        "dns_entropy": 1.2,  "unique_dest_ips": 1,
        "ports_used": [443], "new_ip_flag": False,
    },
    "default": {
        "bytes": 500_000,   "packets": 60,
        "dns_entropy": 2.0,  "unique_dest_ips": 2,
        "ports_used": [443], "new_ip_flag": False,
    },
}

BURN_IN_WINDOWS = 10  # must match engine/features.py


def _make_window(device_id: str, device_type: str, ts: int) -> dict:
    base = NORMAL_WINDOWS.get(device_type, NORMAL_WINDOWS["default"])
    return {
        "device_id":       device_id,
        "device_type":     device_type,
        "timestamp":       ts,
        "bytes":           base["bytes"],
        "packets":         base["packets"],
        "dns_entropy":     base["dns_entropy"],
        "unique_dest_ips": base["unique_dest_ips"],
        "ports_used":      base["ports_used"],
        "new_ip_flag":     base["new_ip_flag"],
        # derived — features.py will recompute, but set sane defaults
        "ewma_delta":  0.01,
        "z_score":     0.5,
        "spike_delta": 0.0,
    }


def seed(devices: list[dict], verbose: bool = True) -> bool:
    """
    Inject BURN_IN_WINDOWS clean windows per device through the real pipeline.
    Returns True if all devices transitioned to ACTIVE.
    """
    # Init DB first
    try:
        from engine.trust import _init_db
        _init_db()
        if verbose:
            print("  ✅ SQLite initialized")
    except Exception as e:
        print(f"  ❌ DB init failed: {e}")
        return False

    # Load ML models
    try:
        from engine.ml import MLEngine
        ml = MLEngine()
        ml.load_models()
        if verbose:
            print("  ✅ ML models loaded")
    except FileNotFoundError:
        print("  ❌ Models not found — run: python train_models.py")
        return False

    # Import pipeline entry point
    try:
        from engine.features import enrich_window, get_device_states
    except Exception as e:
        print(f"  ❌ Engine import failed: {e}")
        return False

    if verbose:
        print(f"\n  Seeding {len(devices)} device(s) with {BURN_IN_WINDOWS} clean windows each...\n")

    now = int(time.time())
    success_count = 0

    for d in devices:
        device_id   = d["device_id"]
        device_type = d["device_type"]
        last_result = None

        for i in range(BURN_IN_WINDOWS + 1):  # +1 ensures state transition fires
            ts = now - (BURN_IN_WINDOWS - i) * 60
            window = _make_window(device_id, device_type, ts)
            try:
                last_result = enrich_window(window)
            except Exception as e:
                if verbose:
                    print(f"  ⚠  {device_id} window {i+1} error: {e}")

        # Check final state
        states = get_device_states()
        state  = states.get(device_id, "CALIBRATING")

        if state == "ACTIVE":
            score = last_result["score"] if last_result else "?"
            if verbose:
                print(f"  ✅  {device_id:<12} [{device_type:<10}]  → ACTIVE  score={score}")
            success_count += 1
        else:
            if verbose:
                print(f"  ⚠   {device_id:<12} [{device_type:<10}]  → still {state}")

    print()
    if success_count == len(devices):
        print(f"  ✅ All {success_count} devices active. Ready to demo.")
        return True
    else:
        print(f"  ⚠  {success_count}/{len(devices)} devices active.")
        return False


def main():
    parser = argparse.ArgumentParser(description="ThrushGuard demo seeder")
    parser.add_argument(
        "--devices",
        help="Comma-separated device specs: cam-01:camera,bulb-01:bulb",
        default=None,
    )
    parser.add_argument("--fast", action="store_true", help="Minimal output")
    args = parser.parse_args()

    print()
    print("  ThrushGuard — Seed Baseline")
    print("  ─────────────────────────────")

    if args.devices:
        devices = []
        for spec in args.devices.split(","):
            spec = spec.strip()
            if ":" in spec:
                did, dtype = spec.split(":", 1)
            else:
                # guess type from id prefix
                did = spec
                dtype = next(
                    (t for t in ["camera", "bulb", "sensor", "thermostat", "router", "lock"]
                     if did.startswith(t[:3])),
                    "default"
                )
            devices.append({"device_id": did.strip(), "device_type": dtype.strip()})
    else:
        devices = DEFAULT_DEVICES

    ok = seed(devices, verbose=not args.fast)
    print()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
