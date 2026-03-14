"""
intent/narrator.py — ThrushGuard Incident Narrator
Generates plain-English incident reports from violation logs using Ollama (phi3:mini).
Fully local. No cloud. No API keys.

Called by TUI when user presses 'r' on a selected device.
Output saved to reports/<device_id>_<timestamp>.md

Usage:
    from intent.narrator import generate_report
    report = generate_report(
        device_id     = "cam-02",
        violations    = ["Port 22 unauthorized → -40pts", ...],
        score_history = [92, 87, 67, 28],
        device_type   = "camera",
    )
"""

import logging
import os
from datetime import datetime
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

OLLAMA_URL   = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "phi3:mini")
TIMEOUT      = 60  # phi3:mini is fast but give it room


# ── Prompt Builder ─────────────────────────────────────────────────────────────

def _build_prompt(
    device_id: str,
    device_type: str,
    violations: list,
    score_history: list,
    timestamp: str,
) -> str:
    score_start = score_history[0]  if score_history else 100
    score_end   = score_history[-1] if score_history else 100
    drop        = score_start - score_end
    traj        = " → ".join(str(s) for s in score_history)

    viol_block = "\n".join(f"  - {v}" for v in violations) if violations else "  (none)"

    if score_end < 40:   severity = "CRITICAL — immediate isolation recommended"
    elif score_end < 60: severity = "HIGH — active monitoring required"
    elif score_end < 80: severity = "MEDIUM — review flagged signals"
    else:                severity = "LOW — device operating normally"

    return f"""You are a SOC analyst writing an incident report for an IoT security system called ThrushGuard.

Device Information:
  Device ID:   {device_id}
  Device Type: {device_type}
  Report Time: {timestamp}
  Severity:    {severity}

Trust Score Trajectory (oldest → latest):
  {traj}
  Drop: {drop} points

Violations Detected:
{viol_block}

Write a concise incident report with these exact sections:
1. SUMMARY (2 sentences — what happened and severity)
2. ATTACK TIMELINE (bullet points — what fired in what order, what it indicates)
3. LIKELY ATTACK VECTOR (1-2 sentences — what the attacker probably did)
4. RECOMMENDED ACTION (1-2 sentences — what the SOC team should do right now)

Rules:
- Be specific. Reference actual values if present (e.g. "entropy rose to 4.9").
- Do NOT hallucinate signals not listed above.
- If violations list is empty, say the device is operating normally.
- Keep total report under 200 words.
- Plain English, not jargon.
"""


# ── Ollama Call ────────────────────────────────────────────────────────────────

def _call_ollama(prompt: str) -> Optional[str]:
    try:
        resp = httpx.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model":   OLLAMA_MODEL,
                "prompt":  prompt,
                "stream":  False,
                "options": {"temperature": 0.3, "num_predict": 400},
            },
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json().get("response", "").strip()
    except httpx.ConnectError:
        logger.error("[Narrator] Ollama not reachable — is it running? (ollama serve)")
        return None
    except httpx.TimeoutException:
        logger.error("[Narrator] Ollama timed out after %ss", TIMEOUT)
        return None
    except Exception as e:
        logger.error("[Narrator] Ollama call failed: %s", e)
        return None


# ── Fallback (no Ollama) ───────────────────────────────────────────────────────

def _fallback_narrative(violations: list, score: int) -> str:
    if not violations:
        return "## SUMMARY\nDevice is operating within normal parameters. No anomalies detected."

    if score < 40:   verdict = f"Trust score dropped to {score}/100 — HIGH RISK. Immediate investigation required."
    elif score < 60: verdict = f"Trust score dropped to {score}/100 — SUSPICIOUS. Active monitoring required."
    else:            verdict = f"Trust score dropped to {score}/100 — MONITOR. Review flagged signals."

    lines = [
        "## SUMMARY", verdict, "",
        "## ATTACK TIMELINE",
        *[f"- {v}" for v in violations], "",
        "## RECOMMENDED ACTION",
        "Isolate device from network and review traffic logs. Check firmware integrity.", "",
        "*(Ollama unavailable — rule-based fallback report)*",
    ]
    return "\n".join(lines)


# ── Report Formatter ───────────────────────────────────────────────────────────

def _format_report(
    device_id: str,
    device_type: str,
    score_end: int,
    violations: list,
    narrative: str,
    timestamp: str,
) -> str:
    viol_lines = "\n".join(f"- {v}" for v in violations) if violations else "- No violations detected."
    return f"""# ThrushGuard Incident Report

| Field        | Value                         |
|--------------|-------------------------------|
| Device       | `{device_id}`                 |
| Type         | {device_type}                 |
| Trust Score  | {score_end} / 100             |
| Generated    | {timestamp}                   |
| Model        | {OLLAMA_MODEL} (local)        |

## Violations Detected

{viol_lines}

## AI Analysis

{narrative}

---
*Generated by ThrushGuard — Exploit X, GDG JSSATEB Eclipse Hackathon*
*All analysis performed locally using {OLLAMA_MODEL}. No data left this machine.*
"""


# ── Public API ─────────────────────────────────────────────────────────────────

def generate_report(
    device_id: str,
    violations: list,
    score_history: list,
    device_type: str = "unknown",
) -> Optional[str]:
    """
    Generate a local AI incident report for a device.

    Args:
        device_id:     e.g. "cam-02"
        violations:    list of reason strings from trust.py
        score_history: list of recent scores, oldest first
        device_type:   e.g. "camera"

    Returns:
        Formatted markdown string. Never returns None — falls back to rule-based report.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    score_end = score_history[-1] if score_history else 0

    logger.info("[Narrator] Generating report for %s (score=%d)", device_id, score_end)

    prompt    = _build_prompt(device_id, device_type, violations, score_history, timestamp)
    narrative = _call_ollama(prompt)

    if narrative is None:
        logger.warning("[Narrator] Ollama unavailable — using fallback")
        narrative = _fallback_narrative(violations, score_end)

    return _format_report(device_id, device_type, score_end, violations, narrative, timestamp)


def generate_report_fallback(
    device_id: str,
    violations: list,
    score_history: list,
    device_type: str = "unknown",
) -> str:
    """
    Rule-based incident report — used when Ollama is unavailable.
    Called by mcp_server.py as a named fallback.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    score_end = score_history[-1] if score_history else 0
    narrative = _fallback_narrative(violations, score_end)
    return _format_report(device_id, device_type, score_end, violations, narrative, timestamp)
