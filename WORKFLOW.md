# Eclipse — ThrustGuard Project Workflow

> **One-stop reference** for how the system is set up, how data flows, and how to demo it.

---

## 📁 Project Structure

```
ThrustGuard/
├── main.py                  ← Entry point (7-step startup)
│
├── engine/                  ← Core scoring pipeline
│   ├── features.py          ← Burn-in, baseline, feature enrichment (orchestrator)
│   ├── policy.py            ← Rule-based port / DNS / IP checks
│   ├── drift.py             ← Z-Score, EWMA, Shannon entropy signals
│   ├── ml.py                ← IsolationForest anomaly scoring
│   ├── trust.py             ← Trust score aggregator → SQLite writer
│   └── policy_generator.py  ← Auto-writes policies after burn-in
│
├── data/
│   ├── synthetic.py         ← Generates normal device traffic (daemon threads)
│   └── simulate_attack.py   ← Injects malicious windows for demo
│
├── compliance/
│   ├── audit.py             ← SHA-256 hash-chained tamper-evident audit log
│   └── report.py            ← Compliance report (ISO 27001 / SOC-2)
│
├── TUI/
│   └── dashboard.py         ← Rich live terminal dashboard
│
├── api/
│   └── main.py              ← FastAPI: /health  /scores  /compliance/report
│
├── models/                  ← Pre-trained IsolationForest pickles
│   ├── cam_baseline.pkl
│   ├── bulb_baseline.pkl
│   └── sensor_baseline.pkl
│
├── policies/                ← Per-device-type JSON policy files
│   ├── camera.json
│   ├── bulb.json
│   ├── sensor.json
│   └── default.json
│
├── train_models.py          ← One-time model training script
├── verify_ml.py             ← Pre-demo model sanity check
└── eclipse.db               ← SQLite (WAL mode) — scores + audit log
```

---

## 🔄 Full Data Flow

```
[data/synthetic.py]
  One daemon thread per device (cam-01, cam-02, bulb-01, bulb-02, sensor-01)
  Every 60s (or 5s in FAST MODE) generates a normal traffic window dict
        │
        ▼
[engine/features.py] ← enrich_window(window)
  ┌─────────────────────────────────────────────────────┐
  │ BURN-IN (first 10 windows)                          │
  │   • Buffer window, count clean ones                 │
  │   • Need 8/10 clean to go ACTIVE                    │
  │   • On ACTIVE: compute baseline_mean, baseline_std  │
  │   • Trigger policy_generator → write policies/*.json│
  └─────────────────────────────────────────────────────┘
        │ (once ACTIVE)
        ▼
  Compute derived features:
    z_score    = (bytes - baseline_mean) / baseline_std
    ewma_delta = |bytes - ewma| / ewma
    spike_delta = (bytes - prev_bytes) / prev_bytes
        │
        ├──▶ [engine/policy.py]   check_policy(window)
        │      Ports not in allowed_ports  → -40 pts each
        │      new_ip_flag = True          → -10 pts
        │      dns_entropy > max           → -15 pts
        │
        ├──▶ [engine/drift.py]    check_drift(window)
        │      z_score > 3.0              → -20 pts
        │      ewma_delta > 0.3           → -5 pts
        │      dns_entropy > 3.5          → -15 pts
        │
        └──▶ [engine/ml.py]       score_anomaly(window)
               IsolationForest.decision_function()
               score < -0.1               → -8 pts
        │
        ▼
[engine/trust.py]  calculate_trust(device_id, violations, signals, ml_result)
  new_score = current_score - sum(all deductions)
  clean window → +2 pts (capped at 100)
  clamped to [0, 100]
  Tiers: 80-100 TRUSTED  60-79 MONITOR  40-59 SUSPICIOUS  0-39 HIGH RISK
        │
        ├──▶ Writes to SQLite: scores table
        └──▶ Writes to SQLite: audit_log (hash-chained)
        │
        ▼
[TUI/dashboard.py]  reads SQLite every 0.2s → refreshes live table
[api/main.py]       reads SQLite on HTTP request
```

---

## 🚀 Startup Sequence (`python main.py`)

| Step | What Happens |
|------|-------------|
| **1** | Load IsolationForest models from `models/*.pkl` — crash if missing (run `train_models.py`) |
| **2** | Initialize SQLite WAL mode, create `scores` and `audit_log` tables |
| **3** | Initialize AuditLog — load last hash, verify chain integrity |
| **4** | Ollama warmup in background thread (non-blocking — fallback if unavailable) |
| **5** | Start 5 synthetic device threads (all start in CALIBRATING) |
| **6** | Start FastAPI in background daemon thread on port 8000 |
| **7** | Launch Rich TUI (takes over main thread, 4 refreshes/sec) |

---

## 🛡️ Trust Score Model

```
Start:   100 (or carry forward previous score)

Deductions (cumulative per window):
  Policy violations:
    Unauthorized port        → -40 pts each
    New destination IP       → -10 pts
    DNS entropy > policy max → -15 pts
  
  Drift signals:
    Z-Score > 3.0            → -20 pts
    EWMA delta > 0.3         → -5 pts
    DNS entropy > 3.5        → -15 pts
  
  ML anomaly (IF score < -0.1) → -8 pts

Recovery (clean window):   +2 pts  (max 100)
Floor:                       0 pts  (never negative)

Tiers:
  80 – 100  →  TRUSTED    [√]  green
  60 –  79  →  MONITOR    [!]  yellow
  40 –  59  →  SUSPICIOUS [?]  orange
   0 –  39  →  HIGH RISK  [X]  red + blink
```

---

## 💥 Attack Simulation Flow

```
[data/simulate_attack.py]
  1. seed_device_baseline(device_id)   ← forces device ACTIVE, score=92
  2. For each escalating window:
       builds device_window dict with attack values
       calls enrich_window(window)      ← straight into engine pipeline
       prints score result
  3. SQLite updated → TUI reacts within 0.2s
```

### Attack Types

| Attack | Signature | End Score |
|--------|-----------|-----------|
| `dns_tunnel` | DNS entropy climbs, port 22 appears, huge bytes | ~0 HIGH RISK |
| `botnet` | Many new IPs, lateral ports (23, 8080), C2 bytes | ~0 HIGH RISK |
| `port_scan` | Hundreds of ports, low bytes, high packet count | ~0 HIGH RISK |
| `exfil` | Massive sustained bytes (20MB+), single IP, low entropy | ~0 HIGH RISK |

---

## 🔒 Audit & Compliance

Every score change writes a hash-chained entry to `audit_log`:

```
entry.hash = SHA256(prev_hash + canonical_json(event_body))
```

Tamper any entry → chain breaks → `compliance/audit.py::verify()` catches it.

**ISO 27001 / SOC-2 mapping:**

| Event Type | ISO 27001 | SOC-2 |
|-----------|-----------|-------|
| `score_update` | A.8.15 | CC7.2 |
| `trust_violation` | A.8.22 | CC6.6 |
| `device_isolated` | A.5.18 | CC6.2 |
| `anomaly_detected` | A.8.16 | CC7.3 |

**Get compliance report:**
```powershell
curl http://localhost:8000/compliance/report
```

---

## 🛠️ One-Time Setup Commands

```powershell
# 1. Create virtual environment
py -3.11 -m venv .venv
.\.venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Train ML models (only needed once, or after deleting models/)
python train_models.py

# 4. Verify models are healthy
python verify_ml.py
```

---

## 🎬 Demo Run Commands

```powershell
# ─── Terminal 1: Main Dashboard ───────────────────────
del eclipse.db            # fresh database
python main.py            # launches TUI

# FAST MODE (5s windows instead of 60s — for demos)
$env:ECLIPSE_FAST_MODE="1"; python main.py

# ─── Terminal 2: Attack Simulation ────────────────────
python data\simulate_attack.py --device cam-02 --attack dns_tunnel --interval 20
python data\simulate_attack.py --device cam-01 --attack botnet
python data\simulate_attack.py --device sensor-01 --attack port_scan
python data\simulate_attack.py --device bulb-01 --attack exfil

# Dry run (no injection, just prints windows)
python data\simulate_attack.py --device cam-02 --attack dns_tunnel --dry-run

# ─── API Endpoints (while main.py is running) ─────────
curl http://localhost:8000/health
curl http://localhost:8000/scores
curl http://localhost:8000/compliance/report
```

---

## 🗑️ Error Reference

| Error | Cause | Fix |
|-------|-------|-----|
| `FileNotFoundError: models/*.pkl` | Models not trained | `python train_models.py` |
| TUI exits immediately | Ctrl+C or terminal too small | Resize terminal, re-run |
| Attack shows no TUI change | Old code (burn-in bug) | Fixed — uses `seed_device_baseline()` now |
| `Ollama unreachable` | Ollama not running | System continues in fallback mode — OK |
| `SQLite locked` | Concurrent writes | WAL mode handles it automatically (3x retry) |
