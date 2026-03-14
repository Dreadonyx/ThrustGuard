"""
mcp_server.py — ThrushGuard MCP Server
Exposes ThrushGuard data as MCP tools for Claude Desktop or any MCP client.

Tools:
  get_device_scores()           — all devices, current trust scores + tiers
  get_device_detail(device_id)  — full history + violations for one device
  get_incident_report(device_id)— AI-generated narrative (Ollama phi3:mini)
  verify_audit_chain()          — hash chain integrity check

Run standalone (stdio transport for Claude Desktop):
  python mcp_server.py

Add to Claude Desktop config (~/.config/claude/claude_desktop_config.json):
  {
    "mcpServers": {
      "thrushguard": {
        "command": "python",
        "args": ["/path/to/ThrushGuard/mcp_server.py"]
      }
    }
  }

Or run alongside main.py — main.py calls start_mcp_background().
"""

import json
import os
import sys
import logging

sys.path.insert(0, os.path.dirname(__file__))

logging.basicConfig(level=logging.WARNING)  # quiet during MCP stdio

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    name="ThrushGuard",
    instructions=(
        "ThrushGuard is a local IoT behavioral trust scoring engine. "
        "It monitors IoT devices (cameras, bulbs, sensors) and scores them 0-100 "
        "based on policy violations, statistical drift, and ML anomaly detection. "
        "Use get_device_scores() first to see all devices, then drill into specific "
        "devices with get_device_detail() or get_incident_report()."
    ),
)

# ── Tool: get_device_scores ────────────────────────────────────────────────────

@mcp.tool(
    description=(
        "Get current trust scores for all monitored IoT devices. "
        "Returns device ID, score (0-100), status tier, and how long ago it was updated. "
        "Status tiers: TRUSTED (80-100), MONITOR (60-79), SUSPICIOUS (40-59), HIGH RISK (<40)."
    )
)
def get_device_scores() -> str:
    try:
        from engine.trust import get_latest_scores
        import time

        scores = get_latest_scores()
        if not scores:
            return "No devices found. Is ThrushGuard running? Try: python main.py"

        now = int(time.time())
        lines = ["# ThrushGuard Device Trust Scores\n"]

        tier_order = {"HIGH RISK": 0, "SUSPICIOUS": 1, "MONITOR": 2, "TRUSTED": 3, "CALIBRATING": 4}
        scores.sort(key=lambda d: tier_order.get(d.get("tier", "CALIBRATING"), 9))

        for d in scores:
            # trust.py stores ISO timestamp strings, not unix ints — handle both
            raw_ts = d.get("timestamp", "")
            try:
                import time as _time
                from datetime import datetime as _dt
                if isinstance(raw_ts, (int, float)):
                    age = int(_time.time()) - int(raw_ts)
                else:
                    age = int(_time.time()) - int(_dt.fromisoformat(raw_ts).timestamp())
                ago = f"{age}s ago" if age < 60 else f"{age//60}m ago"
            except Exception:
                ago = "unknown"

            score  = d["score"]
            status = d.get("tier", "CALIBRATING")  # trust.py uses 'tier'

            if status == "HIGH RISK":
                icon = "🔴"
            elif status == "SUSPICIOUS":
                icon = "🟠"
            elif status == "MONITOR":
                icon = "🟡"
            elif status == "TRUSTED":
                icon = "✅"
            else:
                icon = "⏳"

            lines.append(f"{icon} **{d['device_id']}**  score={score}  {status}  (updated {ago})")

            violations = d.get("violations", [])  # trust.py uses 'violations'
            if isinstance(violations, str):
                violations = json.loads(violations)
            if violations:
                lines.append(f"   Violations: {'; '.join(violations[:2])}")

        summary = {
            "TRUSTED":    sum(1 for d in scores if d.get("tier") == "TRUSTED"),
            "MONITOR":    sum(1 for d in scores if d.get("tier") == "MONITOR"),
            "SUSPICIOUS": sum(1 for d in scores if d.get("tier") == "SUSPICIOUS"),
            "HIGH RISK":  sum(1 for d in scores if d.get("tier") == "HIGH RISK"),
        }
        lines.append(f"\n**Summary:** {summary}")
        return "\n".join(lines)

    except Exception as e:
        return f"Error fetching scores: {e}"


# ── Tool: get_device_detail ────────────────────────────────────────────────────

@mcp.tool(
    description=(
        "Get full details for a specific IoT device: score history, all violations, "
        "and trend analysis. Use this after get_device_scores() to investigate a specific device. "
        "Example: get_device_detail('cam-02')"
    )
)
def get_device_detail(device_id: str) -> str:
    try:
        from engine.trust import get_score_history, get_latest_scores
        import time

        # Latest score
        latest_list = [d for d in get_latest_scores() if d["device_id"] == device_id]
        if not latest_list:
            return f"Device '{device_id}' not found. Check get_device_scores() for valid IDs."
        latest = latest_list[0]

        # History
        history = get_score_history(device_id, limit=10)
        scores  = [int(h["score"]) for h in reversed(history)]

        # Trend
        if len(scores) >= 2:
            delta = scores[-1] - scores[0]
            trend = f"↓ dropping ({delta:+d} pts)" if delta < -5 else \
                    f"↑ recovering ({delta:+d} pts)" if delta > 5 else \
                    "→ stable"
        else:
            trend = "insufficient data"

        violations = latest.get("violations", [])  # trust.py uses 'violations'
        if isinstance(violations, str):
            violations = json.loads(violations)

        # trust.py stores ISO timestamp strings
        raw_ts = latest.get("timestamp", "")
        try:
            from datetime import datetime as _dt
            if isinstance(raw_ts, (int, float)):
                age = int(time.time()) - int(raw_ts)
            else:
                age = int(time.time()) - int(_dt.fromisoformat(raw_ts).timestamp())
            ago = f"{age}s ago" if age < 60 else f"{age//60}m ago"
        except Exception:
            ago = "unknown"

        tier = latest.get("tier", "CALIBRATING")  # trust.py uses 'tier'

        lines = [
            f"# Device Detail: {device_id}",
            f"**Status:** {tier}  |  **Score:** {int(latest['score'])}/100  |  **Updated:** {ago}",
            f"**Trend:** {trend}",
            f"**Score history:** {' → '.join(str(s) for s in scores)}",
            "",
        ]

        if violations:
            lines.append("**Active violations:**")
            for r in violations:
                lines.append(f"  - {r}")
        else:
            lines.append("**No active violations.** Device operating normally.")

        if tier in ("HIGH RISK", "SUSPICIOUS"):
            lines.append(
                f"\n⚠️  This device is flagged. Run get_incident_report('{device_id}') "
                f"for a full AI-generated incident narrative."
            )

        return "\n".join(lines)

    except Exception as e:
        return f"Error fetching device detail: {e}"


# ── Tool: get_incident_report ──────────────────────────────────────────────────

@mcp.tool(
    description=(
        "Generate a plain-English incident report for a device using local AI (phi3:mini via Ollama). "
        "Explains what happened, the attack vector, timeline, and recommended action. "
        "Best used on HIGH RISK or SUSPICIOUS devices. "
        "Ollama must be running: `ollama serve` in a separate terminal. "
        "Example: get_incident_report('cam-02')"
    )
)
def get_incident_report(device_id: str) -> str:
    try:
        from engine.trust import get_score_history, get_latest_scores
        from intent.narrator import generate_report, generate_report_fallback

        latest_list = [d for d in get_latest_scores() if d["device_id"] == device_id]
        if not latest_list:
            return f"Device '{device_id}' not found."

        latest  = latest_list[0]
        history = get_score_history(device_id, limit=10)
        scores  = [int(h["score"]) for h in reversed(history)]

        violations = latest.get("violations", [])  # trust.py uses 'violations'
        if isinstance(violations, str):
            violations = json.loads(violations)

        # device_type is not stored in scores table — derive from device_id prefix
        did = device_id.lower()
        if did.startswith("cam"):
            dtype = "camera"
        elif did.startswith("bulb"):
            dtype = "bulb"
        elif did.startswith("sensor") or did.startswith("snr"):
            dtype = "sensor"
        else:
            dtype = "unknown"

        # Try Ollama first; generate_report internally falls back if Ollama is down
        report = generate_report(
            device_id     = device_id,
            violations    = violations,
            score_history = scores,
            device_type   = dtype,
        )
        if not report:
            report = generate_report_fallback(
                device_id     = device_id,
                violations    = violations,
                score_history = scores,
                device_type   = dtype,
            )
            report += "\n\n*Note: Ollama unavailable — using template report.*"

        # Save to file
        import time
        os.makedirs("reports", exist_ok=True)
        fname = f"reports/{device_id}_{int(time.time())}.md"
        with open(fname, "w") as f:
            f.write(report)

        return report + f"\n\n*Saved to: {fname}*"

    except Exception as e:
        return f"Error generating report: {e}"


# ── Tool: verify_audit_chain ───────────────────────────────────────────────────

@mcp.tool(
    description=(
        "Verify the tamper-evident audit log hash chain integrity. "
        "Returns whether all entries are intact and the total event count. "
        "A broken chain means audit log may have been tampered with."
    )
)
def verify_audit_chain() -> str:
    try:
        from compliance.audit import AuditLog
        result = AuditLog.verify()
        verified = result.get("verified", False)
        entries  = result.get("entries", 0)

        if verified:
            return (
                f"✅ Audit chain intact.\n"
                f"**Total events logged:** {entries}\n"
                f"All {entries} entries verified — no tampering detected."
            )
        else:
            broken_at = result.get("broken_at", "unknown")
            return (
                f"🔴 Audit chain BROKEN at entry {broken_at}.\n"
                f"**Total events:** {entries}\n"
                f"Hash mismatch detected — log may have been tampered with."
            )
    except ImportError:
        return "Audit log module not available."
    except Exception as e:
        return f"Error verifying chain: {e}"


# ── Background runner (called by main.py) ─────────────────────────────────────

def start_mcp_background():
    """
    Start MCP server in a background thread using SSE transport.
    Called by main.py step 6 alongside FastAPI.
    Port 8001 (FastAPI takes 8000).
    """
    import threading

    def _run():
        try:
            mcp.run(transport="sse", port=8001, host="127.0.0.1")
        except Exception as e:
            logging.getLogger("thrushguard.mcp").warning(f"MCP server error: {e}")

    t = threading.Thread(target=_run, daemon=True, name="mcp-server")
    t.start()
    return t


# ── Standalone entry point ────────────────────────────────────────────────────

if __name__ == "__main__":
    # stdio transport for Claude Desktop
    print("ThrushGuard MCP Server starting (stdio)...", file=sys.stderr)
    mcp.run(transport="stdio")
