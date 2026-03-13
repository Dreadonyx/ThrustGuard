"""
test_rules.py — Eclipse Rule Engine Tests
Tests each detection rule in isolation + full pipeline integration.

Run: pytest test_rules.py -v
     python test_rules.py        (standalone, prints pass/fail summary)
"""

import os
import sys
import json
import time
import tempfile

# Isolate to a throw-away DB so this never touches eclipse.db
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["ECLIPSE_DB_PATH"] = _tmp.name

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ─── Window factory ───────────────────────────────────────────────────────────

def _window(device_id="t-cam", device_type="camera", **overrides) -> dict:
    """Return a clean camera window, overriding any fields."""
    base = {
        "device_id":       device_id,
        "device_type":     device_type,
        "bytes":           1_000_000,
        "packets":         120,
        "dns_entropy":     2.1,
        "unique_dest_ips": 2,
        "ports_used":      [443],
        "new_ip_flag":     False,
        "z_score":         0.5,
        "ewma_delta":      0.01,
        "spike_delta":     0.0,
        "timestamp":       int(time.time()),
    }
    base.update(overrides)
    return base


# ─── Drift engine tests ───────────────────────────────────────────────────────

class TestDriftRules:

    def setup_method(self):
        from engine.drift import DriftEngine
        self.drift = DriftEngine()

    def test_zscore_clean(self):
        """Z-score at exactly threshold (3.0) must NOT fire — rule is strict >."""
        signals = self.drift.check_drift(_window(z_score=3.0))
        assert not any("Z=" in s["reason"] for s in signals)

    def test_zscore_fires(self):
        """Z-score above threshold → -20pt deduction."""
        signals = self.drift.check_drift(_window(z_score=3.1))
        hit = next((s for s in signals if "Z=" in s["reason"]), None)
        assert hit is not None, "Z-score rule should have fired"
        assert hit["deduction"] == 20

    def test_ewma_clean(self):
        """EWMA delta at boundary must NOT fire."""
        signals = self.drift.check_drift(_window(ewma_delta=0.30))
        assert not any("EWMA" in s["reason"] for s in signals)

    def test_ewma_fires(self):
        """EWMA delta above threshold → -5pt deduction."""
        signals = self.drift.check_drift(_window(ewma_delta=0.31))
        hit = next((s for s in signals if "EWMA" in s["reason"]), None)
        assert hit is not None, "EWMA rule should have fired"
        assert hit["deduction"] == 5

    def test_entropy_clean(self):
        """DNS entropy at boundary must NOT fire."""
        signals = self.drift.check_drift(_window(dns_entropy=3.50))
        assert not any("entropy" in s["reason"].lower() for s in signals)

    def test_entropy_fires(self):
        """DNS entropy above threshold → -15pt deduction."""
        signals = self.drift.check_drift(_window(dns_entropy=3.51))
        hit = next((s for s in signals if "entropy" in s["reason"].lower()), None)
        assert hit is not None, "DNS entropy rule should have fired"
        assert hit["deduction"] == 15

    def test_all_three_fire(self):
        """All three drift signals fire simultaneously → total -40pts."""
        signals = self.drift.check_drift(_window(z_score=4.0, ewma_delta=0.5, dns_entropy=4.2))
        assert len(signals) == 3, f"Expected 3 drift signals, got {len(signals)}: {signals}"
        assert sum(s["deduction"] for s in signals) == 40

    def test_no_false_positives_normal_window(self):
        """Fully normal window → zero drift signals."""
        signals = self.drift.check_drift(_window())
        assert signals == [], f"Unexpected signals on clean window: {signals}"


# ─── Policy engine tests ──────────────────────────────────────────────────────

class TestPolicyRules:

    def setup_method(self):
        from engine.policy import PolicyEngine
        self.policy = PolicyEngine()
        self.policy.load_policies()

    def test_clean_camera_no_violations(self):
        assert self.policy.check_policy(_window()) == []

    def test_unauthorized_port_fires(self):
        """Port 22 is not in camera allowlist → -40pts."""
        violations = self.policy.check_policy(_window(ports_used=[22, 443]))
        hit = next((v for v in violations if "Port 22" in v["reason"]), None)
        assert hit is not None, "Port 22 should be flagged"
        assert hit["deduction"] == 40

    def test_authorized_ports_pass(self):
        """Ports 443 and 80 are both in camera allowlist."""
        violations = self.policy.check_policy(_window(ports_used=[443, 80]))
        port_v = [v for v in violations if "unauthorized" in v["reason"]]
        assert port_v == [], "443 and 80 are authorized — no violation expected"

    def test_new_ip_fires(self):
        """new_ip_flag=True → -10pts (allow_new_ips is False in camera policy)."""
        violations = self.policy.check_policy(_window(new_ip_flag=True))
        hit = next((v for v in violations if "New destination IP" in v["reason"]), None)
        assert hit is not None, "new_ip_flag should trigger a violation"
        assert hit["deduction"] == 10

    def test_policy_dns_entropy_fires(self):
        """Policy-level DNS entropy check fires independently of drift."""
        violations = self.policy.check_policy(_window(dns_entropy=3.6))
        hit = next((v for v in violations if "DNS entropy" in v["reason"]), None)
        assert hit is not None, "Policy DNS entropy check should fire"

    def test_multiple_bad_ports_each_flagged(self):
        """Each unauthorized port generates its own violation."""
        violations = self.policy.check_policy(_window(ports_used=[22, 23, 3389]))
        port_violations = [v for v in violations if "unauthorized" in v["reason"]]
        assert len(port_violations) == 3, f"Expected 3 port violations, got {len(port_violations)}"

    def test_bulb_policy_allows_80(self):
        """Port 80 is explicitly allowed for bulb devices."""
        w = _window(device_id="t-bulb", device_type="bulb", ports_used=[443, 80])
        violations = self.policy.check_policy(w)
        port_v = [v for v in violations if "unauthorized" in v["reason"]]
        assert port_v == [], "Port 80 should be allowed for bulb"

    def test_combined_policy_violations(self):
        """Port violation + new IP → both fire in same window."""
        violations = self.policy.check_policy(_window(ports_used=[22], new_ip_flag=True))
        reasons = [v["reason"] for v in violations]
        assert any("Port 22" in r for r in reasons)
        assert any("New destination IP" in r for r in reasons)


# ─── ML engine tests ──────────────────────────────────────────────────────────

class TestMLRules:

    def setup_method(self):
        from engine.ml import MLEngine
        self.ml = MLEngine()
        self.ml.load_models()

    def test_normal_window_passes(self):
        """Normal camera traffic → IsolationForest returns None."""
        result = self.ml.score_anomaly(_window())
        assert result is None, f"Normal window should not be flagged, got: {result}"

    def test_extreme_attack_window_flagged(self):
        """dns_tunnel w3 values → IsolationForest must flag as anomaly."""
        attack = _window(
            bytes=9_000_000, packets=9000, dns_entropy=4.9,
            unique_dest_ips=47, z_score=8.4, ewma_delta=2.8,
            new_ip_flag=True, spike_delta=7.0,
        )
        result = self.ml.score_anomaly(attack)
        assert result is not None, "Extreme attack window must trigger ML anomaly"
        assert result["deduction"] == 8
        assert result["if_score"] < -0.1

    def test_anomaly_result_has_required_fields(self):
        attack = _window(bytes=9_000_000, dns_entropy=4.9, z_score=8.4, ewma_delta=2.8)
        result = self.ml.score_anomaly(attack)
        if result is not None:
            assert "reason" in result
            assert "deduction" in result
            assert "if_score" in result

    def test_bulb_model_loaded(self):
        """Bulb model must score its own clean profile as normal."""
        w = _window(device_id="t-bulb", device_type="bulb",
                    bytes=50_000, packets=20, dns_entropy=1.2,
                    unique_dest_ips=1, z_score=0.5, ewma_delta=0.005, spike_delta=0.0)
        result = self.ml.score_anomaly(w)
        assert result is None, f"Clean bulb window should not be anomalous, got: {result}"

    def test_sensor_model_loaded(self):
        """Sensor model must score its own clean profile as normal."""
        w = _window(device_id="t-sensor", device_type="sensor",
                    bytes=10_000, packets=8, dns_entropy=0.8,
                    unique_dest_ips=1, z_score=0.3, ewma_delta=0.003, spike_delta=0.0)
        result = self.ml.score_anomaly(w)
        assert result is None, f"Clean sensor window should not be anomalous, got: {result}"


# ─── Integration tests (full enrich_window pipeline) ─────────────────────────

class TestIntegrationRules:
    """End-to-end tests using enrich_window() with seeded baselines."""

    def _seed(self, device_id: str, device_type: str = "camera", score: int = 92):
        from engine.features import seed_device_baseline
        seed_device_baseline(device_id, device_type, score)

    def test_clean_window_recovers_score(self):
        """Clean window on a healthy device → score stays same or rises (+2)."""
        did = "integ-clean"
        self._seed(did, score=80)
        from engine.features import enrich_window
        result = enrich_window(_window(device_id=did))
        assert result is not None
        assert result["score"] >= 80

    def test_zscore_spike_reduces_score(self):
        """
        Bytes=1_500_000 with seeded baseline (mean=1_000_000, std=50_000) →
        computed z_score=10 → drift fires → score drops below 92.
        Note: z_score/ewma_delta passed in the raw window are irrelevant —
        _compute_derived_features always recomputes them from raw bytes.
        """
        did = "integ-zscore"
        self._seed(did)
        from engine.features import enrich_window
        result = enrich_window(_window(device_id=did, bytes=1_500_000))
        assert result is not None
        assert result["score"] < 92, f"Score should drop from 92, got {result['score']}"

    def test_unauthorized_port_reduces_score(self):
        """Port 22 violation → 40pt deduction from starting score."""
        did = "integ-port"
        self._seed(did, score=92)
        from engine.features import enrich_window
        result = enrich_window(_window(device_id=did, ports_used=[22, 443]))
        assert result is not None
        assert result["score"] <= 52, f"Expected ≤52 after port violation, got {result['score']}"

    def test_new_ip_flag_reduces_score(self):
        did = "integ-newip"
        self._seed(did, score=92)
        from engine.features import enrich_window
        result = enrich_window(_window(device_id=did, new_ip_flag=True))
        assert result is not None
        assert result["score"] < 92

    def test_dns_tunnel_escalation_hits_high_risk(self):
        """3-window dns_tunnel sequence must push device into HIGH RISK."""
        did = "integ-tunnel"
        self._seed(did, score=92)
        from engine.features import enrich_window

        enrich_window(_window(did, bytes=1_100_000, z_score=0.9, ewma_delta=0.31, spike_delta=0.1))
        enrich_window(_window(did, bytes=5_000_000, z_score=3.8, dns_entropy=3.9, ewma_delta=0.9, spike_delta=1.5))
        r3 = enrich_window(_window(did, bytes=9_000_000, packets=9000, dns_entropy=4.9,
                                    unique_dest_ips=47, z_score=8.4, ewma_delta=2.8,
                                    ports_used=[22, 443], new_ip_flag=True, spike_delta=7.0))
        assert r3 is not None
        assert r3["score"] < 40, f"After dns_tunnel, score={r3['score']} should be < 40"
        assert r3["status"] == "HIGH RISK"

    def test_port_scan_escalation(self):
        """3-window port_scan → score must degrade significantly."""
        did = "integ-portscan"
        self._seed(did, score=92)
        from engine.features import enrich_window

        enrich_window(_window(did, ports_used=[443, 8080, 8443], z_score=1.2, ewma_delta=0.15))
        enrich_window(_window(did, ports_used=[22, 23, 80, 443, 3389, 8080], new_ip_flag=True,
                               z_score=2.8, ewma_delta=0.4, spike_delta=1.0))
        r3 = enrich_window(_window(did, ports_used=list(range(20, 30)) + [443, 3389, 5900],
                                    new_ip_flag=True, z_score=5.5, ewma_delta=1.2, spike_delta=0.9))
        assert r3 is not None
        assert r3["score"] < 60, f"After port_scan, score={r3['score']} should be < 60"

    def test_score_never_exceeds_100(self):
        did = "integ-cap"
        self._seed(did, score=100)
        from engine.features import enrich_window
        result = enrich_window(_window(device_id=did))
        assert result is not None
        assert result["score"] <= 100

    def test_score_never_goes_below_0(self):
        did = "integ-floor"
        self._seed(did, score=5)
        from engine.features import enrich_window
        result = enrich_window(_window(device_id=did,
            bytes=9_000_000, dns_entropy=4.9, z_score=8.4, ewma_delta=2.8,
            ports_used=[22, 23, 3389], new_ip_flag=True, spike_delta=7.0))
        assert result is not None
        assert result["score"] >= 0, f"Score went below 0: {result['score']}"

    def test_trust_result_has_required_fields(self):
        did = "integ-fields"
        self._seed(did)
        from engine.features import enrich_window
        result = enrich_window(_window(device_id=did))
        assert result is not None
        for field in ("device_id", "score", "status", "reasons", "timestamp"):
            assert field in result, f"Missing field: {field}"

    def test_no_mutation_of_input_window(self):
        """enrich_window must not modify the caller's dict."""
        did = "integ-nomut"
        self._seed(did)
        from engine.features import enrich_window
        w = _window(device_id=did)
        original_keys = set(w.keys())
        original_bytes = w["bytes"]
        enrich_window(w)
        assert set(w.keys()) == original_keys, "enrich_window mutated input window keys"
        assert w["bytes"] == original_bytes, "enrich_window mutated input bytes"


# ─── Standalone runner ────────────────────────────────────────────────────────

if __name__ == "__main__":
    import traceback

    suites = [TestDriftRules, TestPolicyRules, TestMLRules, TestIntegrationRules]
    passed = 0
    failed = 0
    errors = []

    GREEN  = "\033[32m"
    RED    = "\033[31m"
    YELLOW = "\033[33m"
    RESET  = "\033[0m"
    BOLD   = "\033[1m"

    print(f"\n{BOLD}Eclipse Rule Engine Tests{RESET}")
    print("─" * 50)

    for Suite in suites:
        suite_name = Suite.__name__
        instance   = Suite()
        methods    = [m for m in dir(Suite) if m.startswith("test_")]
        print(f"\n{YELLOW}{suite_name}{RESET} ({len(methods)} tests)")

        for method_name in methods:
            if hasattr(instance, "setup_method"):
                try:
                    instance.setup_method()
                except Exception as e:
                    print(f"  {RED}SETUP ERROR{RESET} {method_name}: {e}")
                    failed += 1
                    errors.append((f"{suite_name}.{method_name}", f"setup failed: {e}"))
                    continue

            try:
                getattr(instance, method_name)()
                print(f"  {GREEN}PASS{RESET} {method_name}")
                passed += 1
            except AssertionError as e:
                print(f"  {RED}FAIL{RESET} {method_name}: {e}")
                failed += 1
                errors.append((f"{suite_name}.{method_name}", str(e)))
            except Exception as e:
                print(f"  {RED}ERROR{RESET} {method_name}: {e}")
                failed += 1
                errors.append((f"{suite_name}.{method_name}", traceback.format_exc()))

    print(f"\n{'─' * 50}")
    total = passed + failed
    if failed == 0:
        print(f"{GREEN}{BOLD}All {total} tests passed.{RESET}\n")
        sys.exit(0)
    else:
        print(f"{RED}{BOLD}{failed}/{total} tests FAILED.{RESET}")
        print(f"\nFailures:")
        for name, msg in errors:
            print(f"  {RED}✗{RESET} {name}")
            print(f"    {msg.strip()}")
        print()
        sys.exit(1)
