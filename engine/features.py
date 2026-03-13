"""
engine/features.py — Feature Extraction & Baseline Management
Eclipse

Responsibilities:
  1. Manage per-device burn-in (CALIBRATING → ACTIVE)
  2. Compute derived features: z_score, ewma_delta, spike_delta
  3. Maintain rolling baseline (in-memory, not SQLite — too fast-changing)
  4. Anti-poisoning: freeze baseline if >3 consecutive anomalies
  5. After burn-in: trigger policy_generator.py
  6. Pass enriched window to the full scoring pipeline

Call flow:
  synthetic.py (or simulate_attack.py)
    → enrich_window(raw_window)
      → compute z_score, ewma, spike_delta
      → call policy.check_policy(enriched)
      → call drift.check_drift(enriched)
      → call ml.score_anomaly(enriched)
      → call trust.calculate_trust(device_id, deductions)
"""

import logging
import time
from collections import defaultdict
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

# ─── Config ───────────────────────────────────────────────────────────────────

BURN_IN_WINDOWS = 10           # windows needed before scoring starts
BURN_IN_CLEAN_THRESHOLD = 8   # must have at least 8/10 clean windows to go ACTIVE
BASELINE_WINDOW_SIZE = 20      # rolling baseline buffer size
EWMA_ALPHA = 0.3               # EWMA decay (0.3 = 30% current, 70% history)
TRIMMED_FRACTION = 0.05        # trim top/bottom 5% from baseline mean
CONSECUTIVE_ANOMALY_FREEZE = 3 # freeze EWMA baseline if this many anomalies in a row

# Device state labels
STATE_CALIBRATING = "CALIBRATING"
STATE_ACTIVE = "ACTIVE"
STATE_NO_POLICY = "NO_POLICY"


class DeviceBaseline:
    """
    Per-device baseline state, maintained in memory.

    Fields:
      state:               CALIBRATING | ACTIVE | NO_POLICY
      buffer:              list of raw window dicts (last N)
      ewma:                current EWMA of bytes
      prev_bytes:          bytes from last window (for spike_delta)
      mean, std:           trimmed mean + std of bytes in buffer
      consecutive_anomaly: counter for anti-poisoning freeze
      ewma_frozen:         if True, EWMA baseline is frozen (anti-poisoning)
    """

    def __init__(self, device_id: str):
        self.device_id = device_id
        self.state = STATE_CALIBRATING
        self.buffer: list[dict] = []
        self.ewma: Optional[float] = None
        self.prev_bytes: Optional[float] = None
        self.mean: float = 0.0
        self.std: float = 1.0
        self.consecutive_anomaly: int = 0
        self.ewma_frozen: bool = False
        self.window_count: int = 0

    def add_to_buffer(self, window: dict):
        self.buffer.append(window)
        if len(self.buffer) > BASELINE_WINDOW_SIZE:
            self.buffer.pop(0)

    def compute_baseline_stats(self):
        """Trimmed mean + std from buffer. Top/bottom TRIMMED_FRACTION excluded."""
        bytes_vals = sorted(w["bytes"] for w in self.buffer)
        trim_n = max(1, int(len(bytes_vals) * TRIMMED_FRACTION))
        trimmed = bytes_vals[trim_n:-trim_n] if len(bytes_vals) > 2 * trim_n else bytes_vals
        self.mean = float(np.mean(trimmed))
        self.std = float(np.std(trimmed)) if len(trimmed) > 1 else 1.0
        if self.std < 1.0:
            self.std = 1.0  # never divide by nearly-zero


# ─── Global state ─────────────────────────────────────────────────────────────
# keyed by device_id
_baselines: dict[str, DeviceBaseline] = defaultdict(lambda: None)
_baselines_lock = __import__("threading").Lock()

# Lazy imports to avoid circular deps
_policy_engine = None
_drift_engine = None
_ml_engine = None
_trust_engine = None
_policy_generator = None


class _TrustEngineShim:
    """
    Thin wrapper so call sites can do `trust_engine.calculate_trust(...)`
    even though trust.py exposes calculate_trust as a plain module function.
    """
    def calculate_trust(self, **kwargs):
        from engine.trust import calculate_trust
        return calculate_trust(**kwargs)


_engines_initialised = False


def _get_engines():
    """Lazy-load all downstream engines once."""
    global _policy_engine, _drift_engine, _ml_engine, _trust_engine, _policy_generator
    global _engines_initialised
    if not _engines_initialised:
        from engine.policy import PolicyEngine
        from engine.drift import DriftEngine
        from engine.ml import MLEngine
        from engine.policy_generator import generate_policy

        _policy_engine = PolicyEngine()
        _policy_engine.load_policies()
        _drift_engine = DriftEngine()
        _ml_engine = MLEngine()
        _ml_engine.load_models()
        _trust_engine = _TrustEngineShim()
        _policy_generator = generate_policy
        _engines_initialised = True
    return _policy_engine, _drift_engine, _ml_engine, _trust_engine, _policy_generator


def _get_baseline(device_id: str) -> DeviceBaseline:
    """Thread-safe baseline access."""
    with _baselines_lock:
        if _baselines[device_id] is None:
            _baselines[device_id] = DeviceBaseline(device_id)
            logger.info(f"[Features] New device: {device_id} — CALIBRATING")
        return _baselines[device_id]


def _is_clean_window(window: dict) -> bool:
    """
    Heuristic to determine if a burn-in window is 'clean' (not anomalous).
    Used to gate baseline finalization — prevents attacker from poisoning burn-in.
    """
    return (
        window.get("dns_entropy", 0) < 3.5 and
        window.get("z_score", 0) < 3.0 and
        not window.get("new_ip_flag", False)
    )


def _compute_derived_features(window: dict, baseline: DeviceBaseline) -> dict:
    """
    Compute z_score, ewma_delta, spike_delta from raw bytes using the device baseline.
    Mutates and returns the window dict.
    """
    bytes_val = float(window["bytes"])

    # Z-Score
    z_score = 0.0
    if baseline.std > 0 and baseline.mean > 0:
        z_score = abs(bytes_val - baseline.mean) / baseline.std
    window["z_score"] = round(z_score, 4)

    # EWMA
    if baseline.ewma is None:
        baseline.ewma = bytes_val
    if not baseline.ewma_frozen:
        new_ewma = EWMA_ALPHA * bytes_val + (1 - EWMA_ALPHA) * baseline.ewma
        ewma_delta = abs(bytes_val - new_ewma) / max(new_ewma, 1)
        baseline.ewma = new_ewma
    else:
        # Frozen — use stored EWMA (anti-poisoning)
        ewma_delta = abs(bytes_val - baseline.ewma) / max(baseline.ewma, 1)

    window["ewma_delta"] = round(float(ewma_delta), 5)

    # Spike delta
    spike_delta = 0.0
    if baseline.prev_bytes is not None:
        spike_delta = (bytes_val - baseline.prev_bytes) / max(baseline.prev_bytes, 1)
    window["spike_delta"] = round(float(spike_delta), 4)
    baseline.prev_bytes = bytes_val

    return window


def _handle_burn_in(window: dict, baseline: DeviceBaseline) -> bool:
    """
    Add window to burn-in buffer. If enough clean windows collected, finalize baseline.
    Returns True if still in burn-in (skip scoring), False if burn-in complete.
    """
    baseline.add_to_buffer(window)
    baseline.window_count += 1

    clean_count = sum(1 for w in baseline.buffer if _is_clean_window(w))

    if baseline.window_count < BURN_IN_WINDOWS:
        logger.debug(f"[Features] {window['device_id']} CALIBRATING "
                     f"({baseline.window_count}/{BURN_IN_WINDOWS} windows, {clean_count} clean)")
        return True  # still calibrating

    # Check gate
    if clean_count < BURN_IN_CLEAN_THRESHOLD:
        logger.warning(
            f"[Features] {window['device_id']} burn-in gated: only {clean_count}/{BURN_IN_WINDOWS} "
            f"clean windows. Extending calibration."
        )
        return True  # extend calibration

    # Finalize
    baseline.compute_baseline_stats()
    baseline.state = STATE_ACTIVE
    logger.info(
        f"[Features] {window['device_id']} CALIBRATING → ACTIVE "
        f"(baseline: mean={baseline.mean:.0f} bytes, std={baseline.std:.0f})"
    )

    # Trigger auto-policy generation if no policy exists
    _, _, _, _, policy_generator = _get_engines()
    policy_generator(window["device_id"], window["device_type"], baseline.buffer)

    return False  # burn-in complete


def _check_anti_poisoning(window: dict, baseline: DeviceBaseline, is_anomaly: bool):
    """
    If >CONSECUTIVE_ANOMALY_FREEZE consecutive anomalies, freeze EWMA baseline.
    Prevents attacker from slowly training the system to accept malicious patterns.
    """
    if is_anomaly:
        baseline.consecutive_anomaly += 1
        if baseline.consecutive_anomaly >= CONSECUTIVE_ANOMALY_FREEZE and not baseline.ewma_frozen:
            baseline.ewma_frozen = True
            logger.warning(
                f"[Features] {window['device_id']} EWMA baseline FROZEN "
                f"({baseline.consecutive_anomaly} consecutive anomalies — anti-poisoning)"
            )
    else:
        if baseline.consecutive_anomaly > 0:
            baseline.consecutive_anomaly = 0
        if baseline.ewma_frozen:
            baseline.ewma_frozen = False
            logger.info(f"[Features] {window['device_id']} EWMA baseline unfrozen (clean window)")


def enrich_window(window: dict) -> Optional[dict]:
    """
    Main entry point. Called by synthetic.py (and simulate_attack.py) for each window.

    Steps:
      1. Get/create per-device baseline
      2. If still in burn-in: buffer the window, return None (skip scoring)
      3. Compute derived features (z_score, ewma_delta, spike_delta)
      4. Run policy → drift → ML → trust engines in sequence
      5. Anti-poisoning check
      6. Return final trust_result

    Returns:
      None if device is still CALIBRATING
      trust_result dict if scored
    """
    device_id = window["device_id"]
    baseline = _get_baseline(device_id)

    # ── Burn-in phase ───────────────────────────────────────────────────────
    if baseline.state == STATE_CALIBRATING:
        still_calibrating = _handle_burn_in(window, baseline)
        if still_calibrating:
            return None
        # Fall through: burn-in just finished, score this window

    # ── Active scoring phase ─────────────────────────────────────────────────
    baseline.add_to_buffer(window)
    baseline.compute_baseline_stats()

    # Compute derived features from baseline
    window = _compute_derived_features(window, baseline)

    # Get all engines
    policy_engine, drift_engine, ml_engine, trust_engine, _ = _get_engines()

    # Run engines
    policy_violations = policy_engine.check_policy(window)
    drift_signals     = drift_engine.check_drift(window)
    ml_result         = ml_engine.score_anomaly(window)

    # Anti-poisoning
    is_anomaly = bool(policy_violations or drift_signals or ml_result)
    _check_anti_poisoning(window, baseline, is_anomaly)

    # Compute trust score
    trust_result = trust_engine.calculate_trust(
        device_id=device_id,
        device_type=window["device_type"],
        policy_violations=policy_violations,
        drift_signals=drift_signals,
        ml_result=ml_result,
        timestamp=window["timestamp"],
    )

    logger.info(
        f"[Features] {device_id} → score={trust_result['score']} "
        f"status={trust_result['status']} "
        f"violations={len(policy_violations)} drift={len(drift_signals)} "
        f"ml={'⚠' if ml_result else '✓'}"
    )

    return trust_result


def get_device_states() -> dict:
    """Return current state of all known devices (for TUI status display)."""
    with _baselines_lock:
        return {
            device_id: baseline.state
            for device_id, baseline in _baselines.items()
            if baseline is not None
        }


# Normal baseline stats per device type (mean bytes, std bytes, starting score).
# These match train_models.py NORMAL_PROFILES exactly.
_SEED_PROFILES = {
    "camera": {"mean": 1_000_000, "std": 50_000,  "ewma": 1_000_000},
    "bulb":   {"mean":    50_000, "std":  5_000,  "ewma":    50_000},
    "sensor": {"mean":    10_000, "std":  1_000,  "ewma":    10_000},
}

_NORMAL_WINDOW_TEMPLATES = {
    "camera": {
        "bytes": 1_000_000, "packets": 120, "dns_entropy": 2.1,
        "unique_dest_ips": 2, "ports_used": [443], "new_ip_flag": False,
        "z_score": 0.8, "ewma_delta": 0.01, "spike_delta": 0.0,
    },
    "bulb": {
        "bytes": 50_000, "packets": 20, "dns_entropy": 1.2,
        "unique_dest_ips": 1, "ports_used": [443, 80], "new_ip_flag": False,
        "z_score": 0.5, "ewma_delta": 0.005, "spike_delta": 0.0,
    },
    "sensor": {
        "bytes": 10_000, "packets": 8, "dns_entropy": 0.8,
        "unique_dest_ips": 1, "ports_used": [443], "new_ip_flag": False,
        "z_score": 0.3, "ewma_delta": 0.003, "spike_delta": 0.0,
    },
}


def seed_device_baseline(device_id: str, device_type: str, initial_score: int = 92) -> None:
    """
    Force a device directly into ACTIVE state with pre-computed baseline stats.

    This bypasses the 10-window burn-in gate so that the attack simulator
    can inject malicious windows that are scored immediately.

    Also writes 'initial_score' to SQLite so the TUI shows a starting score
    for the device before any attack windows land.

    Args:
        device_id:     e.g. "cam-02"
        device_type:   e.g. "camera"
        initial_score: starting trust score (default 92 = healthy TRUSTED)
    """
    import time

    profile = _SEED_PROFILES.get(device_type, _SEED_PROFILES["camera"])
    tmpl    = _NORMAL_WINDOW_TEMPLATES.get(device_type, _NORMAL_WINDOW_TEMPLATES["camera"])

    with _baselines_lock:
        baseline = DeviceBaseline(device_id)
        baseline.state        = STATE_ACTIVE
        baseline.mean         = float(profile["mean"])
        baseline.std          = float(profile["std"])
        baseline.ewma         = float(profile["ewma"])
        baseline.prev_bytes   = float(profile["mean"])
        baseline.window_count = BURN_IN_WINDOWS  # pretend burn-in is done

        # Fill buffer with BURN_IN_WINDOWS copies of a clean template window
        for _ in range(BURN_IN_WINDOWS):
            baseline.buffer.append({
                "device_id":   device_id,
                "device_type": device_type,
                "timestamp":   int(time.time()),
                **tmpl,
            })

        _baselines[device_id] = baseline

    logger.info(
        f"[Features] Seeded baseline for {device_id} ({device_type}) "
        f"→ ACTIVE (mean={profile['mean']:,} std={profile['std']:,})"
    )

    # Write the initial trust score to SQLite so TUI shows it immediately
    try:
        from engine.trust import _current_scores, _init_db, _get_conn, _status_for
        import json

        _init_db()
        _current_scores[device_id] = initial_score
        status = _status_for(initial_score)
        conn = _get_conn()
        try:
            conn.execute(
                "INSERT INTO scores (device_id, score, status, reasons, timestamp) "
                "VALUES (?,?,?,?,?)",
                (device_id, initial_score, status, json.dumps([]), int(time.time()))
            )
            conn.commit()
        finally:
            conn.close()
        logger.info(
            f"[Features] Seeded initial score for {device_id}: "
            f"{initial_score} ({status})"
        )
    except Exception as e:
        logger.warning(f"[Features] Could not seed initial score: {e}")
