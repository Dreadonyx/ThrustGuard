"""
mcp_server.py — ThrushGuard MCP Server
Reads from logs/live/_all_latest.json and per-device .jsonl files.
No SQLite dependency. No import-time side effects.

Tools:
  get_device_scores()            — all devices, live trust scores
  get_device_detail(device_id)   — full history + violations
  get_incident_report(device_id) — AI narrative via phi3:mini
  verify_audit_chain()           — hash chain check

Run for MCP Inspector:
  npx @modelcontextprotocol/inspector python mcp_server.py

Claude Desktop config (~/.config/claude/claude_desktop_config.json):
  {
    "mcpServers": {
      "thrushguard": {
        "command": "python",
        "args": ["/absolute/path/to/ThrushGuard/mcp_server.py"]
      }
    }
  }
"""

import json
import os
import sys
import time
import logging
import pathlib
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# stdout must be clean for MCP stdio protocol — all logging to stderr
logging.basicConfig(level=logging.ERROR)

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    name="ThrushGuard",
    instructions=(
        "ThrushGuard is a local IoT behavioral trust scoring engine. "
        "It monitors IoT devices (cameras, bulbs, sensors) and scores them 0-100 "
        "based on policy violations, statistical drift, and ML anomaly detection. "
        "Scores update every 5-60 seconds depending on mode. "
        "Start with get_device_scores() to see all devices, then use "
        "get_device_detail() or get_incident_report() for specifics."
    ),
)

# ── Data layer — reads logs/live/ directly ─────────────────────────────────────

_PROJECT_ROOT = pathlib.Path(__file__).parent
_LIVE_DIR     = _PROJECT_ROOT / "logs" / "live"


def _read_all_latest() -> dict:
    path = _LIVE_DIR / "_all_latest.json"
    if not path.exists():
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def _read_device_history(device_id: str, limit: int = 10) -> list:
    path = _LIVE_DIR / f"{device_id}.jsonl"
    if not path.exists():
        return []
    try:
        with open(path) as f:
            lines = f.readlines()
        rows = []
        for line in lines[-limit:]:
            line = line.strip()
            if not line: continue
            try:    rows.append(json.loads(line))
            except: pass
        return rows
    except Exception:
        return []


def _normalize(device_id: str, d: dict) -> dict:
    score  = int(float(d.get("trust_score") or d.get("score") or 0))
    status = d.get("tier") or d.get("status") or "TRUSTED"
    reasons = []
    for v in d.get("violations", []):
        reasons.append(v.get("reason") or v.get("type") or str(v) if isinstance(v, dict) else str(v))
    for s in d.get("signals", []):
        reasons.append(s.get("reason") or s.get("type") or str(s) if isinstance(s, dict) else str(s))
    raw_ts = d.get("timestamp") or time.time()
    try:    ts = int(float(raw_ts))
    except:
        try:    ts = int(datetime.fromisoformat(str(raw_ts)).timestamp())
        except: ts = int(time.time())
    return {
        "device_id":   device_id,
        "device_type": d.get("device_type", "unknown"),
        "score":       score,
        "status":      status,
        "reasons":     reasons,
        "timestamp":   ts,
    }


def _ago(ts: int) -> str:
    d = int(time.time()) - ts
    if d < 60:   return f"{d}s ago"
    if d < 3600: return f"{d//60}m ago"
    return f"{d//3600}h ago"


def _infer_type(did: str) -> str:
    did = did.lower()
    if did.startswith("cam"):    return "camera"
    if did.startswith("bulb"):   return "bulb"
    if did.startswith("sensor"): return "sensor"
    return "unknown"


# ── Tool: get_device_scores ────────────────────────────────────────────────────

@mcp.tool(description=(
    "Get current trust scores for all monitored IoT devices. "
    "Returns device ID, score (0-100), status tier, and time since last update. "
    "Tiers: TRUSTED (80-100), MONITOR (60-79), SUSPICIOUS (40-59), HIGH RISK (<40)."
))
def get_device_scores() -> str:
    raw = _read_all_latest()
    if not raw:
        return (
            "No device data found.\n"
            "Is ThrushGuard running? Start with: python main.py\n"
            f"Expected data at: {_LIVE_DIR}/_all_latest.json"
        )

    tier_order = {"HIGH RISK": 0, "SUSPICIOUS": 1, "MONITOR": 2, "TRUSTED": 3}
    devices    = sorted(
        [_normalize(did, d) for did, d in raw.items()],
        key=lambda x: tier_order.get(x["status"], 9)
    )

    icons = {"HIGH RISK": "🔴", "SUSPICIOUS": "🟠", "MONITOR": "🟡", "TRUSTED": "✅"}
    lines = ["# ThrushGuard — Live Device Trust Scores\n"]
    for d in devices:
        icon = icons.get(d["status"], "⏳")
        lines.append(
            f"{icon} **{d['device_id']}**  score={d['score']}  "
            f"{d['status']}  (updated {_ago(d['timestamp'])})"
        )
        if d["reasons"]:
            lines.append(f"   ↳ {'; '.join(d['reasons'][:2])}")

    summary = {t: sum(1 for d in devices if d["status"] == t)
               for t in ["TRUSTED", "MONITOR", "SUSPICIOUS", "HIGH RISK"]}
    lines.append(f"\n**Summary:** {summary}")
    return "\n".join(lines)


# ── Tool: get_device_detail ────────────────────────────────────────────────────

@mcp.tool(description=(
    "Get full details for a specific IoT device: score history, violations, trend. "
    "Use after get_device_scores() to investigate a flagged device. "
    "Example: get_device_detail('cam-02')"
))
def get_device_detail(device_id: str) -> str:
    raw = _read_all_latest()
    if device_id not in raw:
        return (
            f"Device '{device_id}' not found.\n"
            f"Valid IDs: {list(raw.keys())}\n"
            "Run get_device_scores() to see all devices."
        )

    d       = _normalize(device_id, raw[device_id])
    history = _read_device_history(device_id, limit=10)
    scores  = [int(float(h.get("trust_score") or h.get("score") or 0)) for h in history]

    if len(scores) >= 2:
        delta = scores[-1] - scores[0]
        trend = f"↓ dropping ({delta:+d} pts)" if delta < -5 else \
                f"↑ recovering ({delta:+d} pts)" if delta > 5 else "→ stable"
    else:
        trend = "insufficient history"

    lines = [
        f"# Device Detail: {device_id}",
        f"**Status:** {d['status']}  |  **Score:** {d['score']}/100  |  **Updated:** {_ago(d['timestamp'])}",
        f"**Type:** {d['device_type']}  |  **Trend:** {trend}",
        f"**Score history:** {' → '.join(str(s) for s in scores) or 'no history'}",
        "",
    ]
    if d["reasons"]:
        lines.append("**Active violations/signals:**")
        for r in d["reasons"]:
            lines.append(f"  - {r}")
    else:
        lines.append("**No active violations.** Device operating normally.")

    if d["status"] in ("HIGH RISK", "SUSPICIOUS"):
        lines.append(
            f"\n⚠️  Run get_incident_report('{device_id}') for an AI-generated incident narrative."
        )
    return "\n".join(lines)


# ── Tool: get_incident_report ──────────────────────────────────────────────────

@mcp.tool(description=(
    "Generate a plain-English incident report using local AI (phi3:mini via Ollama). "
    "Explains what happened, attack vector, timeline, and recommended action. "
    "Best on HIGH RISK or SUSPICIOUS devices. Ollama must be running. "
    "Example: get_incident_report('cam-02')"
))
def get_incident_report(device_id: str) -> str:
    raw = _read_all_latest()
    if device_id not in raw:
        return f"Device '{device_id}' not found. Run get_device_scores() for valid IDs."

    d       = _normalize(device_id, raw[device_id])
    history = _read_device_history(device_id, limit=10)
    scores  = [int(float(h.get("trust_score") or h.get("score") or 0)) for h in history]
    dtype   = d["device_type"] or _infer_type(device_id)

    try:
        from intent.narrator import generate_report, generate_report_fallback
        report = generate_report(device_id, d["reasons"], scores, dtype)
        if not report:
            report = generate_report_fallback(device_id, d["reasons"], scores, dtype)
            report += "\n\n*Note: Ollama unavailable — template report used.*"
    except ImportError:
        severity = "CRITICAL" if d["score"] < 40 else "HIGH" if d["score"] < 60 else "MEDIUM"
        report = (
            f"## Incident Report — {device_id}\n"
            f"**Severity:** {severity}\n"
            f"**Score:** {d['score']}/100  ({d['status']})\n"
            f"**Score history:** {' → '.join(str(s) for s in scores) or 'N/A'}\n\n"
            f"**Violations detected:**\n"
        )
        for r in (d["reasons"] or ["None"]):
            report += f"  - {r}\n"
        report += "\n**Recommended action:** " + (
            "Isolate device immediately and investigate." if d["score"] < 40
            else "Monitor closely over next 5 windows."
        )

    os.makedirs("reports", exist_ok=True)
    fname = f"reports/{device_id}_{int(time.time())}.md"
    with open(fname, "w") as f:
        f.write(report)

    return report + f"\n\n*Saved to: {fname}*"


# ── Tool: verify_audit_chain ───────────────────────────────────────────────────

@mcp.tool(description=(
    "Verify the tamper-evident audit log hash chain integrity. "
    "Returns chain status and total event count."
))
def verify_audit_chain() -> str:
    try:
        from compliance.audit import AuditLog
        result   = AuditLog.verify()
        verified = result.get("verified", False)
        entries  = result.get("entries", 0)
        if verified:
            return f"✅ Audit chain intact. {entries} events logged — no tampering detected."
        broken_at = result.get("broken_at", "unknown")
        return f"🔴 Chain BROKEN at entry {broken_at}. {entries} total events. Possible tampering."
    except ImportError:
        return "Audit log module not available (compliance/audit.py not found)."
    except Exception as e:
        return f"Error: {e}"


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=4242)
    parser.add_argument("--transport", default="stdio", choices=["stdio", "sse"])
    a = parser.parse_args()
    print(f"ThrushGuard MCP Server starting ({a.transport})...", file=sys.stderr)
    print(f"Data source: {_LIVE_DIR}", file=sys.stderr)
    if a.transport == "sse":
        print(f"Listening on port {a.port}", file=sys.stderr)
        mcp.settings.port = a.port
        mcp.settings.host = "0.0.0.0"
        # Disable DNS rebinding protection so LAN clients can connect
        from mcp.server.transport_security import TransportSecuritySettings
        mcp.settings.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=False
        )
        mcp.run(transport="sse")
    else:
        mcp.run(transport="stdio")
