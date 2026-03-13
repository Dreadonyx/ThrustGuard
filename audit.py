"""
compliance/audit.py — Hash-Chained Tamper-Evident Audit Log
Eclipse — ported from Lockr server/audit.py

Every event is chained: entry.hash = SHA256(prev_hash + canonical_json(body))
Tamper with any entry → chain breaks at that point → verify() catches it.

ISO 27001 / SOC-2 event mapping:
  score_update     → A.8.15 / CC7.2
  trust_violation  → A.8.22 / CC6.6
  device_isolated  → A.5.18 / CC6.2
  anomaly_detected → A.8.16 / CC7.3
"""

import hashlib
import json
import logging
import sqlite3
import os
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("ECLIPSE_DB_PATH", "eclipse.db")
GENESIS_HASH = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

COMPLIANCE_MAP = {
    "score_update":    ("ISO A.8.15", "SOC-2 CC7.2"),
    "trust_violation": ("ISO A.8.22", "SOC-2 CC6.6"),
    "device_isolated": ("ISO A.5.18", "SOC-2 CC6.2"),
    "anomaly_detected":("ISO A.8.16", "SOC-2 CC7.3"),
}


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    return conn


def _compute_hash(prev_hash: str, body: dict) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    raw = prev_hash + canonical
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()


def _get_last_hash() -> str:
    conn = _get_conn()
    row = conn.execute(
        "SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    return row["hash"] if row else GENESIS_HASH


class AuditLog:
    """Static class — all methods are class-level for easy import."""

    @staticmethod
    def append(
        event_type: str,
        device_id: str,
        details: str,
        score_before: int = None,
        score_after: int = None,
    ) -> dict:
        """
        Append a new event to the audit log.
        Computes and stores the hash chain entry.
        Returns the written entry dict.
        """
        prev_hash = _get_last_hash()
        ts = datetime.now(timezone.utc).isoformat()

        body = {
            "timestamp":   ts,
            "event_type":  event_type,
            "device_id":   device_id,
            "details":     details,
            "score_before": score_before,
            "score_after":  score_after,
        }
        entry_hash = _compute_hash(prev_hash, body)

        conn = _get_conn()
        try:
            conn.execute(
                """INSERT INTO audit_log
                   (timestamp, event_type, device_id, details,
                    score_before, score_after, prev_hash, hash)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (ts, event_type, device_id, details,
                 score_before, score_after, prev_hash, entry_hash)
            )
            conn.commit()
        finally:
            conn.close()

        logger.debug(f"[Audit] {event_type} {device_id} hash={entry_hash[:20]}...")
        return {**body, "prev_hash": prev_hash, "hash": entry_hash}

    @staticmethod
    def verify() -> dict:
        """
        Recompute entire chain from genesis.
        Returns: {"verified": bool, "entries": int, "broken_at": id or None}
        """
        conn = _get_conn()
        entries = conn.execute(
            "SELECT * FROM audit_log ORDER BY id ASC"
        ).fetchall()
        conn.close()

        if not entries:
            return {"verified": True, "entries": 0, "broken_at": None}

        prev_hash = GENESIS_HASH
        for entry in entries:
            body = {
                "timestamp":    entry["timestamp"],
                "event_type":   entry["event_type"],
                "device_id":    entry["device_id"],
                "details":      entry["details"],
                "score_before": entry["score_before"],
                "score_after":  entry["score_after"],
            }
            expected_hash = _compute_hash(entry["prev_hash"], body)
            if expected_hash != entry["hash"] or entry["prev_hash"] != prev_hash:
                logger.warning(f"[Audit] Chain broken at id={entry['id']}")
                return {
                    "verified": False,
                    "entries": len(entries),
                    "broken_at": entry["id"],
                }
            prev_hash = entry["hash"]

        return {"verified": True, "entries": len(entries), "broken_at": None}

    @staticmethod
    def get_recent(device_id: str = None, limit: int = 20) -> list[dict]:
        """Fetch recent audit entries, optionally filtered by device."""
        conn = _get_conn()
        if device_id:
            rows = conn.execute(
                "SELECT * FROM audit_log WHERE device_id=? ORDER BY id DESC LIMIT ?",
                (device_id, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    @staticmethod
    def get_by_event_type(event_type: str) -> list[dict]:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE event_type=? ORDER BY id ASC",
            (event_type,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
