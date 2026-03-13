"""
engine/policy_generator.py — Auto-Policy Generator
Eclipse

After a device completes burn-in, this module inspects its baseline buffer
and writes a tailored policy JSON to policies/<device_id>.json.

Called by features.py::_handle_burn_in() after baseline is finalized.
"""

import json
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

POLICIES_DIR = os.path.join(os.path.dirname(__file__), "..", "policies")


def generate_policy(device_id: str, device_type: str, buffer: list[dict]) -> Optional[str]:
    """
    Inspect the burn-in buffer and emit a conservative policy JSON.

    Args:
        device_id:   e.g. "cam-02"
        device_type: e.g. "camera"
        buffer:      list of raw window dicts from burn-in period

    Returns:
        Path to the written policy file, or None on error.
    """
    if not buffer:
        logger.warning(f"[PolicyGen] Empty buffer for {device_id} — skipping policy generation")
        return None

    # Collect observed values across all burn-in windows
    all_ports: set[int] = set()
    all_dns_entropy: list[float] = []
    all_bytes: list[int] = []

    for w in buffer:
        for port in w.get("ports_used", []):
            all_ports.add(int(port))
        e = w.get("dns_entropy")
        if e is not None:
            all_dns_entropy.append(float(e))
        b = w.get("bytes")
        if b is not None:
            all_bytes.append(int(b))

    # Add reasonable headroom so normal traffic never triggers false positives
    max_dns = max(all_dns_entropy) * 1.2 if all_dns_entropy else 3.5
    max_bytes = int(max(all_bytes) * 1.5) if all_bytes else 5_000_000

    policy = {
        "device_id":          device_id,
        "device_type":        device_type,
        "allowed_ports":      sorted(all_ports) if all_ports else [443, 80],
        "allow_new_ips":      False,
        "max_dns_entropy":    round(max_dns, 2),
        "max_bytes_per_window": max_bytes,
        "_generated_by":      "auto-policy after burn-in",
        "_window_count":      len(buffer),
    }

    os.makedirs(POLICIES_DIR, exist_ok=True)
    out_path = os.path.join(POLICIES_DIR, f"{device_id}.json")

    try:
        with open(out_path, "w") as f:
            json.dump(policy, f, indent=2)
        logger.info(
            f"[PolicyGen] Generated policy for {device_id} → {out_path} "
            f"(ports={sorted(all_ports)}, max_entropy={max_dns:.2f}, max_bytes={max_bytes:,})"
        )
        return out_path
    except OSError as e:
        logger.error(f"[PolicyGen] Failed to write policy for {device_id}: {e}")
        return None
