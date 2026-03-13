"""
data/synthetic.py — Synthetic IoT Traffic Generator
Eclipse

Generates realistic per-device traffic windows on a fixed interval.
Each window is passed to a callback (engine/features.py::enrich_window).

5 devices: cam-01, cam-02, bulb-01, bulb-02, sensor-01
Default interval: 60s (override with ECLIPSE_FAST_MODE=1 → 5s)

Device window schema:
  {
    "device_id":       str,
    "device_type":     str,    # "camera" | "bulb" | "sensor"
    "bytes":           int,
    "packets":         int,
    "dns_entropy":     float,
    "ports_used":      list[int],
    "unique_dest_ips": int,
    "new_ip_flag":     bool,
    "timestamp":       int,    # unix timestamp
  }
"""

import logging
import os
import random
import threading
import time
from typing import Callable

logger = logging.getLogger(__name__)

# ── Interval ──────────────────────────────────────────────────────────────────
NORMAL_INTERVAL = 60   # seconds between windows in production
FAST_INTERVAL   = 5    # seconds in ECLIPSE_FAST_MODE=1

# ── Normal traffic profiles (mean, std) ──────────────────────────────────────
# MUST match train_models.py NORMAL_PROFILES exactly.
DEVICE_PROFILES = {
    "camera": {
        "bytes":           (1_000_000, 50_000),
        "packets":         (120, 5),
        "dns_entropy":     (2.1, 0.1),
        "unique_dest_ips": (2, 0.5),
        "ports_used":      [443],
    },
    "bulb": {
        "bytes":           (50_000, 5_000),
        "packets":         (20, 3),
        "dns_entropy":     (1.2, 0.1),
        "unique_dest_ips": (1, 0.3),
        "ports_used":      [443, 80],
    },
    "sensor": {
        "bytes":           (10_000, 1_000),
        "packets":         (8, 2),
        "dns_entropy":     (0.8, 0.1),
        "unique_dest_ips": (1, 0.2),
        "ports_used":      [443],
    },
}

# ── Known devices ─────────────────────────────────────────────────────────────
DEVICES = [
    {"device_id": "cam-01",    "device_type": "camera"},
    {"device_id": "cam-02",    "device_type": "camera"},
    {"device_id": "bulb-01",   "device_type": "bulb"},
    {"device_id": "bulb-02",   "device_type": "bulb"},
    {"device_id": "sensor-01", "device_type": "sensor"},
]


def _gauss(mean: float, std: float, minimum: float = 0.0) -> float:
    """Sample from Normal(mean, std), clamped to minimum."""
    return max(minimum, random.gauss(mean, std))


def _generate_window(device_id: str, device_type: str) -> dict:
    """
    Generate a single synthetic traffic window for a device,
    sampling from its normal profile with slight random noise.
    """
    profile = DEVICE_PROFILES[device_type]

    bytes_mean, bytes_std     = profile["bytes"]
    pkt_mean,   pkt_std       = profile["packets"]
    ent_mean,   ent_std       = profile["dns_entropy"]
    ip_mean,    ip_std        = profile["unique_dest_ips"]

    return {
        "device_id":       device_id,
        "device_type":     device_type,
        "bytes":           int(_gauss(bytes_mean, bytes_std, minimum=1_000)),
        "packets":         max(1, int(_gauss(pkt_mean, pkt_std))),
        "dns_entropy":     round(_gauss(ent_mean, ent_std), 3),
        "ports_used":      list(profile["ports_used"]),  # copy, not reference
        "unique_dest_ips": max(1, int(_gauss(ip_mean, ip_std))),
        "new_ip_flag":     False,   # always False during normal operation
        "timestamp":       int(time.time()),
    }


class SyntheticGenerator:
    """
    Background thread that continuously generates synthetic device windows
    and passes each one to `callback` (which is `features.enrich_window`).

    Usage:
        gen = SyntheticGenerator(callback=enrich_window)
        gen.start()
        ...
        gen.stop()
    """

    def __init__(self, callback: Callable[[dict], None]):
        self._callback = callback
        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        """Start one background thread per device."""
        interval = FAST_INTERVAL if os.environ.get("ECLIPSE_FAST_MODE") == "1" else NORMAL_INTERVAL
        logger.info(f"[Synthetic] Starting {len(DEVICES)} device threads (interval={interval}s)")

        for device in DEVICES:
            t = threading.Thread(
                target=self._device_loop,
                args=(device["device_id"], device["device_type"], interval),
                daemon=True,
                name=f"syn-{device['device_id']}",
            )
            t.start()
            self._threads.append(t)
            logger.info(f"[Synthetic] Started thread for {device['device_id']}")

    def stop(self) -> None:
        """Signal all threads to stop and wait briefly."""
        self._stop_event.set()
        for t in self._threads:
            t.join(timeout=2)
        logger.info("[Synthetic] All device threads stopped.")

    def _device_loop(self, device_id: str, device_type: str, interval: float) -> None:
        """
        Loop for a single device: generate a window, call callback, sleep.
        Stagger first window by a small random offset so all 5 devices
        don't fire at exactly the same time (avoids SQLite write contention).
        """
        # Stagger start: 0s to interval/5 spread across devices
        stagger = random.uniform(0, interval / 5)
        logger.debug(f"[Synthetic] {device_id} staggering {stagger:.1f}s before first window")
        if self._stop_event.wait(timeout=stagger):
            return  # stopped during stagger

        while not self._stop_event.is_set():
            try:
                window = _generate_window(device_id, device_type)
                logger.debug(f"[Synthetic] {device_id} window: bytes={window['bytes']:,} "
                             f"entropy={window['dns_entropy']}")
                self._callback(window)
            except Exception as e:
                logger.error(f"[Synthetic] Error in {device_id} loop: {e}", exc_info=True)

            # Sleep in small chunks so stop() is responsive
            deadline = time.monotonic() + interval
            while time.monotonic() < deadline:
                if self._stop_event.wait(timeout=0.5):
                    return
