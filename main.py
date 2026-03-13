"""
main.py — ThrustGuard Entry Point
Coordinates Sniffer capture and TUI dashboard.
"""

import os
import sys
import threading
import time
from pathlib import Path
from scapy.all import conf
from capture.sniffer import LiveSniffer
from engine.features import FeaturePipeline

def check_requirements():
    """Verify that models and configs exist before starting."""
    models = ["camera_baseline.pkl", "bulb_baseline.pkl", "sensor_baseline.pkl"]
    missing = [m for m in models if not Path(f"models/{m}").exists()]
    
    if missing:
        print("\n[!] CRITICAL ERROR: Missing baseline models.")
        print(f"    Not found: {', '.join(missing)}")
        print("    Please run 'python train_models.py' first.")
        sys.exit(1)
        
    if not Path("config/devices.json").exists():
        print("\n[!] CRITICAL ERROR: config/devices.json not found.")
        sys.exit(1)

def main():
    check_requirements()
    
    # ── Initialize Pipeline ───────────────────────────────────────────
    pipeline = FeaturePipeline()
    
    # ── Configuration ─────────────────────────────────────────────────
    # Interface overridable via env var
    target_iface = os.environ.get("ECLIPSE_IFACE", "Wi-Fi") 
    fast_mode = os.environ.get("ECLIPSE_FAST_MODE") == "1"
    
    print("[*] Available Network Interfaces:")
    try:
        print(conf.ifaces)
    except Exception as e:
        print(f"[!] Warning: Could not list interfaces: {e}")
    
    # ── Start Sniffer Thread ──────────────────────────────────────────
    sniffer = LiveSniffer(
        callback=pipeline.process_window,
        interface=target_iface,
        fast_mode=fast_mode
    )
    
    print(f"[*] Starting Sniffer on {target_iface}...")
    sniffer_thread = threading.Thread(target=sniffer.start, daemon=True)
    sniffer_thread.start()
    
    # ── Launch TUI ────────────────────────────────────────────────────
    print("[*] Launching Dashboard...")
    try:
        from TUI.dashboard import run_dashboard
        run_dashboard()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] TUI Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
