"""
main.py — ThrustGuard Entry Point

Modes (controlled by env vars):
  ECLIPSE_FAST_MODE=1     5-second windows instead of 60s  (demo)
  ECLIPSE_IFACE=wlp8s0    override NIC for --live mode
  ECLIPSE_ATTACK=dns_tunnel|botnet|port_scan|exfil
                          auto-fire this attack after burn-in (synthetic mode)
  ECLIPSE_ATTACK_DEVICE=cam-02   device to attack (default: cam-02)
  ECLIPSE_NO_ATTACK=1     disable auto-attack even in fast mode

Run:
  .env/bin/python main.py                         # synthetic + auto-attack in fast mode
  ECLIPSE_FAST_MODE=1 .env/bin/python main.py     # fast 5s windows
  sudo .env/bin/python main.py --live             # live scapy sniffing on real NIC

Startup sequence:
  [1/5] Verify models + config
  [2/5] Init SQLite (eclipse.db)
  [3/5] Setup network interface  (virtual dummy → WiFi fallback)
  [4/5] Start synthetic threads + optional auto-attack scheduler
  [5/5] Launch Rich TUI
"""

import os
import sys
import time
import argparse
import threading
import subprocess
from pathlib import Path

# ── CLI ────────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="ThrustGuard IoT Trust Monitor")
parser.add_argument("--live", action="store_true",
                    help="Live scapy packet capture (requires sudo).")
args = parser.parse_args()

FAST_MODE      = os.environ.get("ECLIPSE_FAST_MODE")    == "1"
LIVE_MODE      = args.live
IFACE_OVERRIDE = os.environ.get("ECLIPSE_IFACE", "")
AUTO_ATTACK    = os.environ.get("ECLIPSE_ATTACK",        "dns_tunnel")
ATTACK_DEVICE  = os.environ.get("ECLIPSE_ATTACK_DEVICE", "cam-02")
NO_ATTACK      = os.environ.get("ECLIPSE_NO_ATTACK")    == "1"

VIRTUAL_IFACE  = "thrustguard0"   # dummy interface name
REAL_WIFI      = "wlp8s0"         # fallback real NIC

# ── Step 1: Verify requirements ────────────────────────────────────────────────

def check_requirements():
    model_sets = [
        ("models/camera_baseline.pkl", "models/cam_baseline.pkl"),
        ("models/bulb_baseline.pkl",),
        ("models/sensor_baseline.pkl",),
    ]
    missing = [alts[0] for alts in model_sets
               if not any(Path(p).exists() for p in alts)]
    if missing:
        print("\n[!] Missing baseline models — run first:")
        print("    .env/bin/python data/synthetic.py")
        print("    .env/bin/python train_models.py\n")
        sys.exit(1)
    if not Path("config/devices.json").exists():
        print("\n[!] config/devices.json not found.\n")
        sys.exit(1)
    print("[1/5] ✓ Models and config OK")

# ── Step 2: SQLite ─────────────────────────────────────────────────────────────

def init_db():
    try:
        from engine.trust import _init_db
        _init_db()
        print("[2/5] ✓ SQLite (eclipse.db) ready")
    except Exception as e:
        print(f"[2/5] ✗ SQLite init failed: {e}")
        sys.exit(1)

# ── Step 3: Network interface ──────────────────────────────────────────────────

def _create_virtual_iface(name: str) -> bool:
    """
    Try to create a dummy kernel interface for demo capture.
    Requires root. Returns True if successful.

    Creates:  sudo ip link add <name> type dummy
              sudo ip link set <name> up
    """
    try:
        subprocess.run(
            ["ip", "link", "add", name, "type", "dummy"],
            check=True, capture_output=True, timeout=5
        )
        subprocess.run(
            ["ip", "link", "set", name, "up"],
            check=True, capture_output=True, timeout=5
        )
        return True
    except subprocess.CalledProcessError as e:
        # Interface might already exist — check
        result = subprocess.run(
            ["ip", "link", "show", name],
            capture_output=True, timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False

def _iface_exists(name: str) -> bool:
    try:
        r = subprocess.run(["ip", "link", "show", name],
                            capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False

def setup_interface() -> str:
    """
    Interface priority:
      1. ECLIPSE_IFACE env var (explicit override)
      2. Virtual dummy interface (thrustguard0) — created if missing
      3. Real WiFi (wlp8s0) — fallback
      4. Loopback (lo) — last resort for synthetic-only demo
    Returns the chosen interface name.
    """
    if IFACE_OVERRIDE:
        print(f"[3/5] ✓ Interface: {IFACE_OVERRIDE}  [ECLIPSE_IFACE override]")
        return IFACE_OVERRIDE

    # Try virtual dummy
    if _iface_exists(VIRTUAL_IFACE):
        print(f"[3/5] ✓ Interface: {VIRTUAL_IFACE}  [virtual dummy — already exists]")
        return VIRTUAL_IFACE

    if _create_virtual_iface(VIRTUAL_IFACE):
        print(f"[3/5] ✓ Interface: {VIRTUAL_IFACE}  [virtual dummy — created]")
        return VIRTUAL_IFACE

    # Fallback to real WiFi
    if _iface_exists(REAL_WIFI):
        print(f"[3/5] ✓ Interface: {REAL_WIFI}  [real WiFi — fallback, dummy creation failed]")
        return REAL_WIFI

    # Last resort — loopback (synthetic still works, live capture won't yield IoT traffic)
    print(f"[3/5] ⚠  Interface: lo  [loopback — no dummy/WiFi available, synthetic mode only]")
    return "lo"

# ── Step 4a: Synthetic device threads ─────────────────────────────────────────

DEVICES = [
    ("cam-01",    "camera"),
    ("cam-02",    "camera"),
    ("bulb-01",   "bulb"),
    ("bulb-02",   "bulb"),
    ("sensor-01", "sensor"),
]

def _synthetic_device_loop(device_id: str, device_type: str):
    import random
    from engine.features import FeaturePipeline
    from data.synthetic import generate_window

    pipeline     = FeaturePipeline()
    window_secs  = 5 if FAST_MODE else 60
    time.sleep(random.uniform(0.2, 1.5))   # stagger start

    while True:
        try:
            raw = generate_window(device_type, device_id)
            raw.setdefault("new_ip_flag",      False)
            raw.setdefault("unique_dest_ips",  len(raw.get("dst_ips", [])))
            raw.setdefault("ports_used",       raw.get("ports", []))
            pipeline.process_window(raw)
        except Exception as e:
            print(f"[synth:{device_id}] {e}", file=sys.stderr)
        time.sleep(window_secs)

def start_synthetic():
    label = "FAST 5s" if FAST_MODE else "NORMAL 60s"
    print(f"[4/5] ✓ {len(DEVICES)} synthetic device threads started  [{label}]")
    for dev_id, dev_type in DEVICES:
        threading.Thread(
            target=_synthetic_device_loop,
            args=(dev_id, dev_type),
            daemon=True,
            name=f"synth-{dev_id}",
        ).start()

# ── Step 4b: Live sniffer ──────────────────────────────────────────────────────

def start_live_sniffer(iface: str):
    print(f"[4/5] Starting live sniffer on {iface}...")
    try:
        from capture.sniffer import LiveSniffer
        from engine.features import FeaturePipeline
        pipeline = FeaturePipeline()
        sniffer  = LiveSniffer(
            callback=pipeline.process_window,
            interface=iface,
            fast_mode=FAST_MODE,
        )
        threading.Thread(target=sniffer.start, daemon=True, name="sniffer").start()
        print(f"[4/5] ✓ Live sniffer on {iface}")
    except PermissionError:
        print(f"[4/5] ✗ Permission denied — need sudo for live capture")
        sys.exit(1)
    except Exception as e:
        print(f"[4/5] ✗ Sniffer error: {e}")
        sys.exit(1)

# ── Step 4c: Auto-attack scheduler ────────────────────────────────────────────

def _auto_attack_thread(device_id: str, attack_name: str, window_secs: int):
    """
    Wait for burn-in (enough windows for all devices to be ACTIVE),
    then fire the attack automatically. This gives the demo its 'wow moment'
    without anyone needing to open a second terminal.
    """
    # Wait 2 full window cycles to let devices accumulate scores,
    # then fire the attack on the 3rd cycle.
    burn_in_wait = window_secs * 2 + 5
    print(f"[AUTO-ATTACK] Scheduled: {attack_name} → {device_id} "
          f"in {burn_in_wait}s (after burn-in)", flush=True)
    time.sleep(burn_in_wait)

    try:
        import sys as _sys
        root = os.path.dirname(os.path.abspath(__file__))
        if root not in _sys.path:
            _sys.path.insert(0, root)

        from data.simulate_attack import ATTACKS, build_window, inject_window

        windows = ATTACKS.get(attack_name)
        if not windows:
            print(f"[AUTO-ATTACK] Unknown attack: {attack_name}", flush=True)
            return

        interval = window_secs   # one window per engine cycle
        print(f"\n[AUTO-ATTACK] 🔴 Firing {attack_name} on {device_id} "
              f"({len(windows)} windows × {interval}s)\n", flush=True)

        for i, attack_window in enumerate(windows, 1):
            window = build_window(device_id, attack_window, i)
            inject_window(window)
            if i < len(windows):
                time.sleep(interval)

        print(f"[AUTO-ATTACK] ✓ Attack complete — watch {device_id} in TUI", flush=True)

    except Exception as e:
        print(f"[AUTO-ATTACK] Error: {e}", flush=True)

def schedule_auto_attack():
    if NO_ATTACK:
        return
    window_secs = 5 if FAST_MODE else 60
    threading.Thread(
        target=_auto_attack_thread,
        args=(ATTACK_DEVICE, AUTO_ATTACK, window_secs),
        daemon=True,
        name="auto-attack",
    ).start()
    print(f"[4/5] ✓ Auto-attack scheduled: {AUTO_ATTACK} → {ATTACK_DEVICE}  "
          f"[disable with ECLIPSE_NO_ATTACK=1]")

# ── Step 5: TUI ───────────────────────────────────────────────────────────────

def start_tui():
    print("[5/5] Launching dashboard...\n")
    time.sleep(0.5)
    try:
        from TUI.dashboard import run_dashboard
        run_dashboard()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"\n[!] TUI error: {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    mode = "LIVE" if LIVE_MODE else "SYNTHETIC"
    fast = "  [FAST MODE]" if FAST_MODE else ""
    print(f"\n{'─'*52}")
    print(f"  ThrustGuard  —  {mode}{fast}")
    print(f"{'─'*52}\n")

    check_requirements()          # [1/5]
    init_db()                     # [2/5]
    iface = setup_interface()     # [3/5]

    if LIVE_MODE:
        start_live_sniffer(iface) # [4/5]  — real packets
    else:
        start_synthetic()         # [4/5]  — synthetic windows
        schedule_auto_attack()    #         — auto demo attack

    start_tui()                   # [5/5]  — blocks until q/Ctrl+C


if __name__ == "__main__":
    main()
