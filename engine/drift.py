"""
engine/drift.py — Statistical Drift Detection
Eclipse — IoT Trust Scoring

Three signals, run in sequence on every enriched device_window:
  1. Z-Score     → sudden traffic burst (bytes spike)
  2. EWMA        → slow gradual drift (low-and-slow attacks)
  3. Shannon     → DNS tunneling (high entropy query strings)

Each signal returns a deduction dict or nothing.
All three results are collected into a list and passed to trust.py.

Thresholds (from CONTEXT.md):
  Z-Score > 3.0   → -20 pts
  EWMA delta > 0.3 → -5 pts
  DNS entropy > 3.5 → -15 pts
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ── Thresholds ────────────────────────────────────────────────────────────────
ZSCORE_THRESHOLD  = 3.0
EWMA_THRESHOLD    = 0.3
ENTROPY_THRESHOLD = 3.5

ZSCORE_DEDUCTION  = 20
EWMA_DEDUCTION    = 5
ENTROPY_DEDUCTION = 15


class DriftEngine:

    def check_drift(self, window: dict) -> list[dict]:
        """
        Run all three drift checks on an enriched device_window.

        Args:
            window: enriched device_window dict (z_score, ewma_delta,
                    dns_entropy already computed by features.py)

        Returns:
            List of dicts: [{"reason": str, "deduction": int}, ...]
            Empty list if no signals fired.
        """
        signals = []

        z = self._check_zscore(window)
        if z:
            signals.append(z)

        e = self._check_ewma(window)
        if e:
            signals.append(e)

        h = self._check_entropy(window)
        if h:
            signals.append(h)

        if signals:
            logger.debug(
                f"[Drift] {window.get('device_id')} — {len(signals)} signal(s): "
                + ", ".join(s["reason"] for s in signals)
            )

        return signals

    def _check_zscore(self, window: dict) -> Optional[dict]:
        z = float(window.get("z_score", 0))
        if z > ZSCORE_THRESHOLD:
            return {
                "reason": f"Traffic spike Z={z:.2f} > {ZSCORE_THRESHOLD}",
                "deduction": ZSCORE_DEDUCTION,
            }
        return None

    def _check_ewma(self, window: dict) -> Optional[dict]:
        delta = float(window.get("ewma_delta", 0))
        if delta > EWMA_THRESHOLD:
            return {
                "reason": f"EWMA drift delta={delta:.3f} > {EWMA_THRESHOLD}",
                "deduction": EWMA_DEDUCTION,
            }
        return None

    def _check_entropy(self, window: dict) -> Optional[dict]:
        h = float(window.get("dns_entropy", 0))
        if h > ENTROPY_THRESHOLD:
            return {
                "reason": f"DNS entropy {h:.2f} > {ENTROPY_THRESHOLD} (tunneling suspected)",
                "deduction": ENTROPY_DEDUCTION,
            }
        return None
