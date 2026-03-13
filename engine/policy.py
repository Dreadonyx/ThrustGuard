"""
engine/policy.py — Policy Engine
ThrushGuard

Loads per-device-type JSON policy files dynamically.
Any device type works — just drop a <type>.json in policies/.
Unknown types fall back to default.json.

Deductions:
  Port not in allowed_ports    → -40pts
  new_ip_flag + allow_new_ips=false → -10pts
  dns_entropy > max            → -15pts

Design:
  - Policies are loaded once and cached in memory
  - Bad JSON → warning + fallback to default, never a crash
  - device_type is sanitized before use as a filename
"""

import json
import logging
import os
import re
from typing import Optional

logger = logging.getLogger(__name__)

POLICIES_DIR = os.path.join(os.path.dirname(__file__), "..", "policies")

# Deduction values (match CONTEXT.md)
PORT_DEDUCTION    = 40
NEW_IP_DEDUCTION  = 10
ENTROPY_DEDUCTION = 15

# Schema with safe defaults — used when a field is missing from the JSON
POLICY_DEFAULTS = {
    "allowed_ports":        [443, 80],
    "allow_new_ips":        False,
    "max_dns_entropy":      3.5,
    "max_bytes_per_window": 5_000_000,
}

# In-memory cache — policies loaded once per process
_policy_cache: dict[str, dict] = {}


def _sanitize_device_type(device_type: str) -> str:
    """
    Strip anything that could be used for path traversal or injection.
    Only allow lowercase alphanumeric + underscore + hyphen.
    e.g. "../../etc/passwd" → rejected → "default"
         "Smart-Camera_v2"  → "smart-camera_v2"
    """
    sanitized = re.sub(r"[^a-z0-9_\-]", "", device_type.lower().strip())
    if not sanitized:
        logger.warning(f"[Policy] Rejected device_type '{device_type}' — using default")
        return "default"
    return sanitized


def _load_policy(device_type: str) -> dict:
    """
    Load policy JSON for a device type.
    Falls back to default.json if the type-specific file doesn't exist.
    Falls back to POLICY_DEFAULTS if default.json is also missing.
    """
    safe_type = _sanitize_device_type(device_type)

    # Try type-specific file first, then default
    candidates = [
        os.path.join(POLICIES_DIR, f"{safe_type}.json"),
        os.path.join(POLICIES_DIR, "default.json"),
    ]

    for path in candidates:
        if not os.path.exists(path):
            continue
        try:
            with open(path) as f:
                raw = json.load(f)

            # Fill missing fields with safe defaults
            policy = {**POLICY_DEFAULTS, **raw}

            # Validate types — coerce or reject bad values
            policy["allowed_ports"]        = [int(p) for p in policy["allowed_ports"]]
            policy["allow_new_ips"]        = bool(policy["allow_new_ips"])
            policy["max_dns_entropy"]      = float(policy["max_dns_entropy"])
            policy["max_bytes_per_window"] = int(policy["max_bytes_per_window"])

            source = os.path.basename(path)
            if source != f"{safe_type}.json":
                logger.info(f"[Policy] No policy for '{device_type}' — using {source}")
            else:
                logger.debug(f"[Policy] Loaded {source}")

            return policy

        except (json.JSONDecodeError, ValueError, KeyError) as e:
            logger.warning(f"[Policy] Bad JSON in {path}: {e} — trying next")
            continue

    # Both files failed — use hardcoded defaults
    logger.warning(f"[Policy] No valid policy file found for '{device_type}' — using hardcoded defaults")
    return dict(POLICY_DEFAULTS)


def _get_policy(device_type: str) -> dict:
    """Get policy with in-memory caching."""
    safe_type = _sanitize_device_type(device_type)
    if safe_type not in _policy_cache:
        _policy_cache[safe_type] = _load_policy(safe_type)
    return _policy_cache[safe_type]


def reload_policies():
    """Clear cache — call this if policy files are edited at runtime."""
    _policy_cache.clear()
    logger.info("[Policy] Cache cleared — policies will reload on next window")


def list_available_policies() -> list[str]:
    """Return all device types with a policy file in policies/."""
    if not os.path.exists(POLICIES_DIR):
        return []
    return [
        os.path.splitext(f)[0]
        for f in os.listdir(POLICIES_DIR)
        if f.endswith(".json")
    ]


class PolicyEngine:

    def check_policy(self, window: dict) -> list[dict]:
        """
        Check a device_window against its policy.

        Args:
            window: enriched device_window dict

        Returns:
            List of violation dicts: [{"reason": str, "deduction": int}, ...]
            Empty list if no violations.
        """
        device_type = window.get("device_type", "default")
        device_id   = window.get("device_id", "unknown")
        policy      = _get_policy(device_type)

        violations = []

        # ── Port check ────────────────────────────────────────────────────────
        ports_used    = window.get("ports_used", [])
        allowed_ports = policy["allowed_ports"]
        bad_ports = [p for p in ports_used if p not in allowed_ports]
        if bad_ports:
            for port in bad_ports:
                violations.append({
                    "reason":    f"Port {port} unauthorized (allowed: {allowed_ports})",
                    "deduction": PORT_DEDUCTION,
                })
                logger.debug(f"[Policy] {device_id} port violation: {port}")

        # ── New IP check ──────────────────────────────────────────────────────
        if window.get("new_ip_flag", False) and not policy["allow_new_ips"]:
            violations.append({
                "reason":    "New destination IP contacted (not in baseline)",
                "deduction": NEW_IP_DEDUCTION,
            })
            logger.debug(f"[Policy] {device_id} new IP flag")

        # ── DNS entropy check ─────────────────────────────────────────────────
        # Note: drift.py also checks entropy — both fire independently.
        # Policy check uses per-device threshold (tighter for sensors/locks).
        dns_entropy     = float(window.get("dns_entropy", 0))
        max_dns_entropy = policy["max_dns_entropy"]
        if dns_entropy > max_dns_entropy:
            violations.append({
                "reason":    f"DNS entropy {dns_entropy:.2f} > policy max {max_dns_entropy} (tunneling?)",
                "deduction": ENTROPY_DEDUCTION,
            })
            logger.debug(f"[Policy] {device_id} DNS entropy {dns_entropy:.2f} > {max_dns_entropy}")

        if violations:
            logger.info(
                f"[Policy] {device_id} ({device_type}) — "
                f"{len(violations)} violation(s), "
                f"total deduction: {sum(v['deduction'] for v in violations)}pts"
            )

        return violations
