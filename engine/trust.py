"""
engine/trust.py — Trust Score Engine
Eclipse — IoT Trust Scoring

Aggregates signals from drift.py and ml.py into a 0-100 trust score.
Writes score + audit entry to SQLite on every window.

Score model (from CONTEXT.md):
  Start: 100 (or carry forward current score)
  Deductions:
    drift signals  → variable (-5, -15, -20)
    ML anomaly     → -8
  Recovery:
    Clean window   → +2 (capped at 100)
  Clamped: max(0, min(100, score))

Tiers:
  80-100 → TRUSTED    ✅
  60-79  → MONITOR    🟡
  40-59  → SUSPICIOUS 🟠
  < 40   → HIGH RISK  🔴
"""

import json
import logging
import sqlite3
import os
import time
from typing import Optional

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("ECLIPSE_DB_PATH", "eclipse.db")

RECOVERY_PTS = 2

TIERS = [
    (80, 100, "TRUSTED"),
    (60, 79,  "MONITOR"),
    (40, 59,  "SUSPICIOUS"),
    (0,  39,  "HIGH RISK"),
]


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.row_factory = sqlite3.Row
    return conn


def _init_db():
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scores (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id   TEXT NOT NULL,
            score       INTEGER NOT NULL,
            status      TEXT NOT NULL,
            reasons     TEXT NOT NULL,
            timestamp   INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    TEXT NOT NULL,
            event_type   TEXT NOT NULL,
            device_id    TEXT NOT NULL,
            details      TEXT NOT NULL,
            score_before INTEGER,
            score_after  INTEGER,
            prev_hash    TEXT NOT NULL,
            hash         TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_scores_device ON scores(device_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_device  ON audit_log(device_id, timestamp);
    """)
    conn.commit()
    conn.close()


_init_db()

# In-memory current score per device (avoids a DB read on every window)
_current_scores: dict[str, int] = {}


def _status_for(score: int) -> str:
    for lo, hi, label in TIERS:
        if lo <= score <= hi:
            return label
    return "HIGH RISK"


def _get_current_score(device_id: str) -> int:
    if device_id in _current_scores:
        return _current_scores[device_id]
    # First time — try to load from DB
    conn = _get_conn()
    row = conn.execute(
        "SELECT score FROM scores WHERE device_id=? ORDER BY timestamp DESC LIMIT 1",
        (device_id,)
    ).fetchone()
    conn.close()
    score = int(row["score"]) if row else 100
    _current_scores[device_id] = score
    return score


def calculate_trust(
    device_id: str,
    device_type: str,
    policy_violations: list[dict],
    drift_signals: list[dict],
    ml_result: Optional[dict],
    timestamp: int,
) -> dict:
    """
    Main entry point called by features.py for every scored window.

    Args:
        device_id:         e.g. "cam-02"
        device_type:       e.g. "camera"
        policy_violations: list from policy.py (may be empty)
        drift_signals:     list from drift.py (may be empty)
        ml_result:         dict from ml.py or None
        timestamp:         unix timestamp of the window

    Returns:
        trust_result dict matching the shared data contract:
        {
          "device_id": str,
          "score": int,
          "status": str,
          "reasons": [str, ...],
          "timestamp": int
        }
    """
    score_before = _get_current_score(device_id)
    # Collect all deductions: policy violations + drift signals + ML result
    all_deductions = list(policy_violations or []) + list(drift_signals or [])
    if ml_result:
        all_deductions.append(ml_result)

    total_deduction = sum(d["deduction"] for d in all_deductions)
    reasons = [d["reason"] for d in all_deductions]

    if total_deduction == 0:
        # Clean window — recover
        new_score = min(100, score_before + RECOVERY_PTS)
    else:
        new_score = score_before - total_deduction

    new_score = max(0, min(100, new_score))
    status = _status_for(new_score)

    _current_scores[device_id] = new_score

    # ── Write to SQLite ───────────────────────────────────────────────────────
    conn = _get_conn()
    try:
        conn.execute(
            "INSERT INTO scores (device_id, score, status, reasons, timestamp) VALUES (?,?,?,?,?)",
            (device_id, new_score, status, json.dumps(reasons), timestamp)
        )
        conn.commit()
    finally:
        conn.close()

    # ── Write audit entry (after conn is closed to avoid write lock) ──────────
    try:
        from compliance.audit import AuditLog
        event_type = "trust_violation" if reasons else "score_update"
        details = reasons[0] if reasons else "Clean window — score recovered"
        AuditLog.append(
            event_type=event_type,
            device_id=device_id,
            details=details,
            score_before=score_before,
            score_after=new_score,
        )
    except ImportError:
        pass

    trust_result = {
        "device_id": device_id,
        "score": new_score,
        "status": status,
        "reasons": reasons,
        "timestamp": timestamp,
    }

    logger.info(
        f"[Trust] {device_id} {score_before}→{new_score} {status} "
        f"deductions={total_deduction} reasons={len(reasons)}"
    )

    return trust_result


def get_latest_scores() -> list[dict]:
    """Return latest score for every device. Called by TUI every 1s."""
    conn = _get_conn()
    rows = conn.execute("""
        SELECT s.device_id, s.score, s.status, s.reasons, s.timestamp
        FROM scores s
        INNER JOIN (
            SELECT device_id, MAX(timestamp) as max_ts
            FROM scores GROUP BY device_id
        ) latest ON s.device_id = latest.device_id AND s.timestamp = latest.max_ts
        ORDER BY s.score ASC
    """).fetchall()
    conn.close()
    results = []
    for r in rows:
        results.append({
            "device_id": r["device_id"],
            "score":     r["score"],
            "status":    r["status"],
            "reasons":   json.loads(r["reasons"]),
            "timestamp": r["timestamp"],
        })
    return results


def get_score_history(device_id: str, limit: int = 20) -> list[dict]:
    """Return score history for one device, newest first. Called by responder.py."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM scores WHERE device_id=? ORDER BY timestamp DESC LIMIT ?",
        (device_id, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
