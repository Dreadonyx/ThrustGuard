#!/usr/bin/env bash
# test_rule.sh — Eclipse Rule Engine Validation
# Checks every detection rule by simulating targeted attacks.
#
# Usage:
#   ./test_rule.sh              # run all tests
#   ./test_rule.sh --verbose    # show pytest output in full
#   ./test_rule.sh --fast       # skip integration tests (unit-only)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERBOSE=0
FAST=0

for arg in "$@"; do
    case "$arg" in
        --verbose|-v) VERBOSE=1 ;;
        --fast)       FAST=1    ;;
    esac
done

GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
CYAN="\033[36m"
BOLD="\033[1m"
RESET="\033[0m"

pass() { echo -e "  ${GREEN}[PASS]${RESET} $1"; }
fail() { echo -e "  ${RED}[FAIL]${RESET} $1"; }
info() { echo -e "  ${CYAN}[INFO]${RESET} $1"; }
section() { echo -e "\n${BOLD}${YELLOW}── $1 ──${RESET}"; }

cd "$SCRIPT_DIR"

echo -e "\n${BOLD}Eclipse Engine — Rule Validation Suite${RESET}"
echo -e "$(date '+%Y-%m-%d %H:%M:%S')  |  $(python3 --version 2>&1)"
echo "────────────────────────────────────────────────"

# ── Prerequisite checks ───────────────────────────────────────────────────────
section "Prerequisites"

PREREQ_OK=1

# Python
if ! command -v python3 &>/dev/null; then
    fail "python3 not found"
    PREREQ_OK=0
else
    pass "python3 found: $(python3 --version 2>&1)"
fi

# Required packages
for pkg in numpy sklearn rich fastapi; do
    if python3 -c "import $pkg" 2>/dev/null; then
        pass "import $pkg"
    else
        fail "import $pkg — run: pip install -r requirements.txt"
        PREREQ_OK=0
    fi
done

# ML models
for model in models/cam_baseline.pkl models/bulb_baseline.pkl models/sensor_baseline.pkl; do
    if [[ -f "$model" ]]; then
        pass "model: $model"
    else
        fail "model missing: $model — run: python train_models.py"
        PREREQ_OK=0
    fi
done

# Policy files
for policy in policies/camera.json policies/bulb.json policies/sensor.json; do
    if [[ -f "$policy" ]]; then
        pass "policy: $policy"
    else
        fail "policy missing: $policy"
        PREREQ_OK=0
    fi
done

if [[ "$PREREQ_OK" -eq 0 ]]; then
    echo -e "\n${RED}${BOLD}Prerequisites failed — fix above errors and retry.${RESET}\n"
    exit 1
fi

# ── Unit tests: Drift rules ───────────────────────────────────────────────────
section "Drift Rules (unit)"

run_drift_test() {
    local name="$1"
    local z="$2" ewma="$3" entropy="$4"
    local expect_count="$5"

    result=$(python3 - <<PYEOF
import sys, os
sys.path.insert(0, ".")
from engine.drift import DriftEngine
d = DriftEngine()
w = {"device_id": "t", "z_score": $z, "ewma_delta": $ewma, "dns_entropy": $entropy}
signals = d.check_drift(w)
print(len(signals))
PYEOF
    )

    if [[ "$result" == "$expect_count" ]]; then
        pass "$name (signals=$result)"
    else
        fail "$name — expected $expect_count signals, got $result"
    fi
}

run_drift_test "Z-score clean (3.0 exact = no fire)"        3.0  0.01 2.1   0
run_drift_test "Z-score fires (3.1 > threshold)"            3.1  0.01 2.1   1
run_drift_test "EWMA clean (0.30 exact = no fire)"          0.5  0.30 2.1   1   # z fires, ewma doesn't
run_drift_test "EWMA fires (0.31 > threshold)"              0.5  0.31 2.1   2   # z + ewma
run_drift_test "DNS entropy clean (3.50 = no fire)"         0.5  0.01 3.50  0
run_drift_test "DNS entropy fires (3.51 > threshold)"       0.5  0.01 3.51  1
run_drift_test "All three fire simultaneously"              3.1  0.31 3.51  3
run_drift_test "Normal window — zero signals"               0.5  0.01 2.1   0

# ── Unit tests: Policy rules ──────────────────────────────────────────────────
section "Policy Rules (unit)"

run_policy_test() {
    local name="$1"
    local ports="$2"
    local new_ip="$3"
    local entropy="$4"
    local expect_count="$5"

    result=$(python3 - <<PYEOF
import sys, os
sys.path.insert(0, ".")
from engine.policy import PolicyEngine
p = PolicyEngine()
p.load_policies()
w = {
    "device_id": "t", "device_type": "camera",
    "ports_used": $ports, "new_ip_flag": $new_ip,
    "dns_entropy": $entropy
}
v = p.check_policy(w)
print(len(v))
PYEOF
    )

    if [[ "$result" == "$expect_count" ]]; then
        pass "$name (violations=$result)"
    else
        fail "$name — expected $expect_count violations, got $result"
    fi
}

run_policy_test "Clean camera window"                  "[443]"         False  2.1  0
run_policy_test "Port 22 unauthorized"                 "[22, 443]"     False  2.1  1
run_policy_test "Port 443+80 authorized"               "[443, 80]"     False  2.1  0
run_policy_test "new_ip_flag fires"                    "[443]"         True   2.1  1
run_policy_test "DNS entropy policy fires"             "[443]"         False  3.6  1
run_policy_test "Multi bad ports (22,23,3389)"         "[22,23,3389]"  False  2.1  3
run_policy_test "new_ip + bad port combo"              "[22]"          True   2.1  2

# ── Unit tests: ML anomaly detection ─────────────────────────────────────────
section "ML Rules (unit)"

run_ml_test() {
    local name="$1"
    local bytes="$2" packets="$3" entropy="$4" z="$5" ewma="$6" new_ip="$7" spike="$8"
    local expect_anomaly="$9"

    result=$(python3 - <<PYEOF
import sys
sys.path.insert(0, ".")
from engine.ml import MLEngine
m = MLEngine()
m.load_models()
w = {
    "device_id": "t", "device_type": "camera",
    "bytes": $bytes, "packets": $packets, "dns_entropy": $entropy,
    "unique_dest_ips": 2, "z_score": $z, "ewma_delta": $ewma,
    "new_ip_flag": $new_ip, "spike_delta": $spike,
}
r = m.score_anomaly(w)
print("anomaly" if r else "normal")
PYEOF
    )

    if [[ "$result" == "$expect_anomaly" ]]; then
        pass "$name ($result)"
    else
        fail "$name — expected $expect_anomaly, got $result"
    fi
}

run_ml_test "Normal camera window"        1000000 120  2.1  0.5 0.01 False 0.0   normal
run_ml_test "DNS tunnel w3 (extreme)"     9000000 9000 4.9  8.4 2.80 True  7.0   anomaly
run_ml_test "Large exfil (high bytes)"    20000000 1200 2.1  12.0 2.1 True  1.0  anomaly

# ── Integration tests: full pipeline via enrich_window ───────────────────────
if [[ "$FAST" -eq 0 ]]; then
    section "Integration Tests (full pipeline)"

    run_integration_test() {
        local name="$1"
        local script="$2"
        local expect="$3"  # a python expression that evaluates to True on success

        result=$(python3 - <<PYEOF
import sys, os, tempfile, time
sys.path.insert(0, ".")

_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_db.close()
os.environ["ECLIPSE_DB_PATH"] = _db.name

$script

if $expect:
    print("PASS")
else:
    print("FAIL")
PYEOF
        )

        if [[ "$result" == "PASS" ]]; then
            pass "$name"
        else
            fail "$name (assertion failed)"
        fi
    }

    run_integration_test "Clean window recovers score" \
"from engine.features import seed_device_baseline, enrich_window
seed_device_baseline('d1', 'camera', 80)
r = enrich_window({'device_id':'d1','device_type':'camera','bytes':1000000,'packets':120,'dns_entropy':2.1,'unique_dest_ips':2,'ports_used':[443],'new_ip_flag':False,'timestamp':int(time.time())})" \
"r is not None and r['score'] >= 80"

    run_integration_test "Port 22 attack deducts ≥40pts from score" \
"from engine.features import seed_device_baseline, enrich_window
seed_device_baseline('d2', 'camera', 92)
r = enrich_window({'device_id':'d2','device_type':'camera','bytes':1000000,'packets':120,'dns_entropy':2.1,'unique_dest_ips':2,'ports_used':[22,443],'new_ip_flag':False,'z_score':0.5,'ewma_delta':0.01,'spike_delta':0.0,'timestamp':int(time.time())})" \
"r is not None and r['score'] <= 52"

    run_integration_test "DNS tunnel escalation → HIGH RISK" \
"from engine.features import seed_device_baseline, enrich_window
seed_device_baseline('d3', 'camera', 92)
def w(**kw):
    base = {'device_id':'d3','device_type':'camera','bytes':1000000,'packets':120,'dns_entropy':2.1,'unique_dest_ips':2,'ports_used':[443],'new_ip_flag':False,'z_score':0.5,'ewma_delta':0.01,'spike_delta':0.0,'timestamp':int(time.time())}
    base.update(kw)
    return base
enrich_window(w(bytes=1100000,z_score=0.9,ewma_delta=0.31,spike_delta=0.1))
enrich_window(w(bytes=5000000,z_score=3.8,dns_entropy=3.9,ewma_delta=0.9,spike_delta=1.5))
r = enrich_window(w(bytes=9000000,packets=9000,dns_entropy=4.9,unique_dest_ips=47,z_score=8.4,ewma_delta=2.8,ports_used=[22,443],new_ip_flag=True,spike_delta=7.0))" \
"r is not None and r['score'] < 40 and r['status'] == 'HIGH RISK'"

    run_integration_test "Score never goes below 0" \
"from engine.features import seed_device_baseline, enrich_window
seed_device_baseline('d4', 'camera', 5)
r = enrich_window({'device_id':'d4','device_type':'camera','bytes':9000000,'packets':9000,'dns_entropy':4.9,'unique_dest_ips':47,'ports_used':[22,23,3389],'new_ip_flag':True,'z_score':8.4,'ewma_delta':2.8,'spike_delta':7.0,'timestamp':int(time.time())})" \
"r is not None and r['score'] >= 0"

    run_integration_test "Score never exceeds 100" \
"from engine.features import seed_device_baseline, enrich_window
seed_device_baseline('d5', 'camera', 100)
r = enrich_window({'device_id':'d5','device_type':'camera','bytes':1000000,'packets':120,'dns_entropy':2.1,'unique_dest_ips':2,'ports_used':[443],'new_ip_flag':False,'z_score':0.5,'ewma_delta':0.01,'spike_delta':0.0,'timestamp':int(time.time())})" \
"r is not None and r['score'] <= 100"

    run_integration_test "enrich_window does not mutate input dict" \
"from engine.features import seed_device_baseline, enrich_window
seed_device_baseline('d6', 'camera', 92)
w = {'device_id':'d6','device_type':'camera','bytes':1000000,'packets':120,'dns_entropy':2.1,'unique_dest_ips':2,'ports_used':[443],'new_ip_flag':False,'timestamp':int(time.time())}
keys_before = set(w.keys())
bytes_before = w['bytes']
enrich_window(w)" \
"set(w.keys()) == keys_before and w['bytes'] == bytes_before"

    run_integration_test "trust_result contains required fields" \
"from engine.features import seed_device_baseline, enrich_window
seed_device_baseline('d7', 'camera', 92)
r = enrich_window({'device_id':'d7','device_type':'camera','bytes':1000000,'packets':120,'dns_entropy':2.1,'unique_dest_ips':2,'ports_used':[443],'new_ip_flag':False,'timestamp':int(time.time())})" \
"r is not None and all(k in r for k in ('device_id','score','status','reasons','timestamp'))"

else
    info "--fast flag set: skipping integration tests"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────────────"
echo -e "${BOLD}Done.${RESET} Run ${CYAN}pytest test_rules.py -v${RESET} for the full pytest suite."
echo ""
