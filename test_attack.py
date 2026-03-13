"""
Quick test: seed cam-02, inject 3 attack windows, print results.
Run: python test_attack.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.features import seed_device_baseline, enrich_window
from data.simulate_attack import ATTACKS, build_window

print("Seeding cam-02 baseline (score=92, ACTIVE)...")
seed_device_baseline("cam-02", "camera", initial_score=92)

print("\nInjecting dns_tunnel attack windows:\n")
for i, attack_w in enumerate(ATTACKS["dns_tunnel"], 1):
    window = build_window("cam-02", attack_w, i)
    result = enrich_window(window)
    print(f"  Window {i}: score={result['score']:3d}  status={result['status']}")
    if result["reasons"]:
        for r in result["reasons"]:
            print(f"    - {r}")
    print()

print("Done. Check SQLite for stored scores:")
from engine.trust import get_score_history
for row in get_score_history("cam-02"):
    print(f"  score={row['score']}  status={row['status']}  ts={row['timestamp']}")
