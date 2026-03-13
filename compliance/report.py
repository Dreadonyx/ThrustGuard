"""
compliance/report.py — Compliance Report Generator
Eclipse

Generates a structured plain-text compliance report from audit_log entries.
Called by GET /compliance/report in api/main.py.

ISO 27001 / SOC-2 event mapping (from audit.py):
  score_update     → ISO A.8.15 / SOC-2 CC7.2
  trust_violation  → ISO A.8.22 / SOC-2 CC6.6
  device_isolated  → ISO A.5.18 / SOC-2 CC6.2
  anomaly_detected → ISO A.8.16 / SOC-2 CC7.3
"""

import os
from datetime import datetime, timezone


DB_PATH = os.environ.get("ECLIPSE_DB_PATH", "eclipse.db")

COMPLIANCE_MAP = {
    "score_update":    ("ISO A.8.15", "SOC-2 CC7.2"),
    "trust_violation": ("ISO A.8.22", "SOC-2 CC6.6"),
    "device_isolated": ("ISO A.5.18", "SOC-2 CC6.2"),
    "anomaly_detected": ("ISO A.8.16", "SOC-2 CC7.3"),
}


def generate() -> str:
    """
    Build and return the full compliance report as a plain-text string.
    """
    from compliance.audit import AuditLog

    # Verify chain integrity first
    chain = AuditLog.verify()
    verified_str = "VERIFIED ✅" if chain["verified"] else f"BROKEN at entry {chain['broken_at']} ❌"

    lines = [
        "=" * 72,
        "  ECLIPSE IoT TRUST ENGINE — COMPLIANCE REPORT",
        f"  Generated : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "=" * 72,
        "",
        f"  Audit Chain : {verified_str}",
        f"  Total Entries : {chain['entries']}",
        "",
    ]

    for event_type, (iso_ref, soc_ref) in COMPLIANCE_MAP.items():
        entries = AuditLog.get_by_event_type(event_type)
        lines.append(f"── {event_type.upper()} ({iso_ref} / {soc_ref})  [{len(entries)} events]")
        if not entries:
            lines.append("   No events recorded.")
        else:
            for e in entries[-20:]:  # last 20 per category
                ts = e.get("timestamp", "")[:19].replace("T", " ")
                dev = e.get("device_id", "unknown")
                det = e.get("details", "")
                sb = e.get("score_before", "—")
                sa = e.get("score_after", "—")
                lines.append(f"   [{ts}] {dev:12s}  {det}  ({sb}→{sa})")
        lines.append("")

    lines += [
        "=" * 72,
        "  END OF REPORT",
        "=" * 72,
    ]

    return "\n".join(lines)
