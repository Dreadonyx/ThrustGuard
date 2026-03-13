"""
simulate_attack.py — Eclipse Attack Injector
Injects malicious device_windows directly into the engine pipeline.
Used during demo to trigger visible score degradation.

Usage:
  python simulate_attack.py --device cam-02 --attack dns_tunnel
  python simulate_attack.py --device cam-02 --attack botnet
  python simulate_attack.py --device cam-02 --attack port_scan
  python simulate_attack.py --device sensor-01 --attack exfil
  python simulate_attack.py --device cam-02 --attack dns_tunnel --dry-run

Flags:
  --device     device_id to target (cam-01, cam-02, bulb-01, bulb-02, sensor-01)
  --attack     attack type (dns_tunnel | botnet | port_scan | exfil)
  --dry-run    print windows without injecting (for testing)
  --interval   seconds between windows (default: 20)

Demo sequence:
  T=0:00  cam-02 at 92 TRUSTED (green)
  T=0:20  window_1 → 87 TRUSTED (barely, EWMA drift fires)
  T=0:40  window_2 → 39 SUSPICIOUS (Z-Score + DNS entropy + IF)
  T=1:00  window_3 → 28 HIGH RISK (port 22 + DNS + ML + new IP)
  T=1:10  type: "what happened to cam-02?" in TUI
"""

import argparse
import time
import json
import sys
import logging

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

# ─── Attack profiles ──────────────────────────────────────────────────────────
# Each attack is a sequence of windows (progressive escalation)
# Values are the OVERRIDES on top of the device's normal baseline

ATTACKS: dict[str, list[dict]] = {

    # DNS tunneling — entropy climbs, port 22 appears, massive bytes
    "dns_tunnel": [
        # Window 1 — EWMA drift only. Only ewma_delta crosses threshold (0.31 > 0.3).
        # Everything else stays near-normal → IF score > -0.1 → ML does NOT fire.
        # This gives the demo the clean layered sequence: EWMA fires first, ML later.
        {
            "bytes": 1_100_000, "packets": 122,
            "dns_entropy": 2.12, "unique_dest_ips": 2,
            "z_score": 0.9, "ewma_delta": 0.31,
            "ports_used": [443], "new_ip_flag": False,
            "spike_delta": 0.1,
        },
        # Window 2 — Z-Score fires, DNS entropy crosses threshold, IF flags
        {
            "bytes": 5_000_000, "packets": 4000,
            "dns_entropy": 3.9, "unique_dest_ips": 18,
            "z_score": 3.8, "ewma_delta": 0.9,
            "ports_used": [443], "new_ip_flag": False,
            "spike_delta": 1.5,
        },
        # Window 3 — full exfiltration: port 22, new IP, max entropy, IF at -0.43
        {
            "bytes": 9_000_000, "packets": 9000,
            "dns_entropy": 4.9, "unique_dest_ips": 47,
            "z_score": 8.4, "ewma_delta": 2.8,
            "ports_used": [22, 443], "new_ip_flag": True,
            "spike_delta": 7.0,
        },
    ],

    # Botnet C2 — lateral movement, many new IPs, port scan behavior
    "botnet": [
        {
            "bytes": 300_000, "packets": 600,
            "dns_entropy": 2.8, "unique_dest_ips": 12,
            "z_score": 1.8, "ewma_delta": 0.25,
            "ports_used": [443, 80], "new_ip_flag": True,
            "spike_delta": 0.3,
        },
        {
            "bytes": 800_000, "packets": 2000,
            "dns_entropy": 3.2, "unique_dest_ips": 35,
            "z_score": 4.1, "ewma_delta": 0.7,
            "ports_used": [443, 80, 8080], "new_ip_flag": True,
            "spike_delta": 1.6,
        },
        {
            "bytes": 4_000_000, "packets": 7000,
            "dns_entropy": 4.1, "unique_dest_ips": 80,
            "z_score": 7.2, "ewma_delta": 1.9,
            "ports_used": [22, 23, 80, 443, 8080], "new_ip_flag": True,
            "spike_delta": 4.0,
        },
    ],

    # Port scan — many ports, low bytes, high packet count
    "port_scan": [
        {
            "bytes": 120_000, "packets": 2000,
            "dns_entropy": 2.0, "unique_dest_ips": 3,
            "z_score": 1.2, "ewma_delta": 0.15,
            "ports_used": [443, 8080, 8443], "new_ip_flag": False,
            "spike_delta": 0.2,
        },
        {
            "bytes": 250_000, "packets": 8000,
            "dns_entropy": 2.1, "unique_dest_ips": 5,
            "z_score": 2.8, "ewma_delta": 0.4,
            "ports_used": [22, 23, 80, 443, 3389, 8080, 8443], "new_ip_flag": True,
            "spike_delta": 1.0,
        },
        {
            "bytes": 500_000, "packets": 20000,
            "dns_entropy": 2.3, "unique_dest_ips": 8,
            "z_score": 5.5, "ewma_delta": 1.2,
            "ports_used": list(range(20, 30)) + [443, 3389, 5900],
            "new_ip_flag": True,
            "spike_delta": 0.9,
        },
    ],

    # Data exfiltration — huge sustained bytes, single IP, low entropy (encrypted)
    "exfil": [
        {
            "bytes": 4_000_000, "packets": 300,
            "dns_entropy": 1.9, "unique_dest_ips": 1,
            "z_score": 3.1, "ewma_delta": 0.5,
            "ports_used": [443], "new_ip_flag": True,
            "spike_delta": 3.0,
        },
        {
            "bytes": 10_000_000, "packets": 700,
            "dns_entropy": 2.0, "unique_dest_ips": 1,
            "z_score": 7.8, "ewma_delta": 1.4,
            "ports_used": [443], "new_ip_flag": True,
            "spike_delta": 1.5,
        },
        {
            "bytes": 20_000_000, "packets": 1200,
            "dns_entropy": 2.1, "unique_dest_ips": 1,
            "z_score": 12.0, "ewma_delta": 2.1,
            "ports_used": [443], "new_ip_flag": True,
            "spike_delta": 1.0,
        },
    ],
}

DEVICE_TYPE_MAP = {
    "cam-01": "camera", "cam-02": "camera",
    "bulb-01": "bulb",  "bulb-02": "bulb",
    "sensor-01": "sensor",
}


def build_window(device_id: str, attack_window: dict, window_num: int) -> dict:
    """Merge attack overrides with required device_window fields."""
    device_type = DEVICE_TYPE_MAP.get(device_id, "camera")
    return {
        "device_id":       device_id,
        "device_type":     device_type,
        "timestamp":       int(time.time()),
        **attack_window,
    }


_pipeline = None

def inject_window(window: dict) -> None:
    """
    Push window into the live engine pipeline.
    Instantiates FeaturePipeline and calls process_window.
    """
    global _pipeline
    try:
        if _pipeline is None:
            import os
            import sys
            # Ensure project root is in path
            root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if root not in sys.path:
                sys.path.insert(0, root)
            
            from engine.features import FeaturePipeline
            _pipeline = FeaturePipeline()

        device_id = window["device_id"]
        _pipeline.process_window(window)
        
        state = _pipeline.device_states.get(device_id)
        if state:
            logger.info(
                f"  ✅ Injected → {device_id}  score={state['score']} "
            )
    except Exception as e:
        logger.warning(f"  ⚠ Injection failed: {e}")
        logger.info(f"  Window (dry-run output):\n  {json.dumps(window, indent=2)}")


def run_attack(device_id: str, attack_name: str, interval: int, dry_run: bool) -> None:
    """Execute an attack sequence, sleeping interval seconds between windows."""
    windows = ATTACKS[attack_name]
    total = len(windows)

    print(f"\n🔴 ATTACK: {attack_name} → {device_id}")
    print(f"   {total} windows, {interval}s apart\n")

    for i, attack_window in enumerate(windows, 1):
        window = build_window(device_id, attack_window, i)
        print(f"[T+{(i-1)*interval:03d}s] Window {i}/{total}")
        print(f"  bytes={window['bytes']:,}  dns_entropy={window['dns_entropy']}  "
              f"z_score={window['z_score']}  ports={window['ports_used']}")

        if dry_run:
            print("  [DRY RUN — not injecting]")
        else:
            inject_window(window)

        if i < total:
            print(f"  ⏱  Waiting {interval}s...\n")
            time.sleep(interval)

    print(f"\n✅ Attack sequence complete. Check TUI for score changes.")
    if not dry_run:
        print(f"   Type: 'what happened to {device_id}?' in TUI chat")


def main():
    parser = argparse.ArgumentParser(
        description="Eclipse Attack Injector — simulate IoT device compromise"
    )
    parser.add_argument("--device",   required=True, choices=list(DEVICE_TYPE_MAP.keys()),
                        help="Target device ID")
    parser.add_argument("--attack",   required=True, choices=list(ATTACKS.keys()),
                        help="Attack type")
    parser.add_argument("--interval", type=int, default=20,
                        help="Seconds between windows (default: 20)")
    parser.add_argument("--dry-run",  action="store_true",
                        help="Print windows without injecting")

    args = parser.parse_args()
    run_attack(args.device, args.attack, args.interval, args.dry_run)


if __name__ == "__main__":
    main()
