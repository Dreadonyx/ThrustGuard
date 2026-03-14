# ThrushGuard — Project Context
> Feed this file to any AI model before asking it to write code.
> This is the single source of truth for architecture, data contracts, and design decisions.

---

## What We're Building

**ThrushGuard** — A local IoT behavioral trust scoring and anomaly detection engine.
No cloud. No browser. One terminal. Runs entirely on-device.

**One-line pitch:**
> "Silent behavioral drift is how attackers stay hidden for weeks. ThrushGuard catches it in 60 seconds — no cloud, no config, no alert fatigue."

**Team:** Exploit X — Harshit JK, Barath VS, Hemanth Gupta P, Sri Raghav R
**Event:** Eclipse Hackathon (GDG JSSATEB)
**Constraint:** 24-hour solo hackathon

---

## Hardware

```
OS:   Kali Linux (Arch on dev machine)
RAM:  24GB
GPU:  RTX 4050 6GB VRAM
LLM:  phi3:mini via Ollama (fully local, no API key)
```

---

## The Full Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│  DATA INGESTION                                             │
│                                                             │
│  simulate_attack.py                                         │
│    └─ injects fake traffic into dummy NIC "eclipse"         │
│         (sudo ip link add eclipse type dummy)               │
│                          │                                  │
│  data/scapy-collector.py ◄─── captures packets on NIC      │
│    └─ filters per-device features                           │
│    └─ writes one JSON line per 60s window → data.jsonl      │
│                                                             │
│  data/synthetic.py  (demo fallback — no NIC needed)         │
│    └─ generates device_window dicts                         │
│    └─ calls enrich_window() directly                        │
└───────────────────────┬─────────────────────────────────────┘
                        │  device_window dict
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  ENGINE PIPELINE  (entry: enrich_window(window))            │
│                                                             │
│  engine/features.py                                         │
│    ├─ Burn-in check  (10 windows, 8/10 must be clean)       │
│    ├─ Compute derived features (z_score, ewma, spike_delta) │
│    ├─ engine/policy.py   → rule violations                  │
│    ├─ engine/drift.py    → Z-Score, EWMA, entropy           │
│    ├─ engine/ml.py       → IsolationForest                  │
│    └─ engine/trust.py    → aggregate → 0-100 score          │
│                                                             │
│  Output: trust_result dict                                  │
│    → written to SQLite   (history, MCP/API queries)         │
│    → appended to results.jsonl  (TUI reads this)            │
│    → appended to audit.log      (hash-chained event log)    │
└───────────────────────┬─────────────────────────────────────┘
                        │  trust_result
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  OUTPUT LAYER                                               │
│                                                             │
│  TUI/dashboard.py        primary interface, btop-style      │
│    reads results.jsonl + SQLite                             │
│    [1-9] select device                                      │
│    [r]   AI incident report via phi3:mini (Ollama)          │
│    [i]   instant inspect (score history + violations)       │
│                                                             │
│  mcp_server.py           MCP tools (Claude Desktop / Inspector)
│    get_device_scores()                                      │
│    get_device_detail(device_id)                             │
│    get_incident_report(device_id)                           │
│    verify_audit_chain()                                     │
│                                                             │
│  api/main.py             FastAPI background (port 8000)     │
│    GET /health                                              │
│    GET /scores                                              │
│    GET /scores/{device_id}                                  │
└─────────────────────────────────────────────────────────────┘
```

---

## Startup Sequence

```bash
python train_models.py     # ONCE — bakes IsolationForest models
python verify_ml.py        # before every demo — sanity check
python seed_baseline.py    # before every demo — skips 10-min burn-in
python main.py             # boots everything
```

```
main.py steps:
  [1/6] Load IsolationForest models (models/*.pkl)
  [2/6] Init SQLite WAL (eclipse.db)
  [3/6] Init audit log (compliance/audit.py)
  [4/6] Start synthetic generator (5 device threads)
  [5/6] Start FastAPI + MCP server (background threads, ports 8000/8001)
  [6/6] Launch TUI (takes over main thread, blocks until q)
```

---

## Shared Data Contract

**ALL modules use these exact shapes. Never deviate.**

```python
# Input to all engines
device_window = {
    "device_id":       "cam-01",    # str
    "device_type":     "camera",    # camera|bulb|sensor|thermostat|router|lock
    "timestamp":       1234567890,  # unix int
    "bytes":           1_000_000,
    "packets":         120,
    "unique_dest_ips": 2,
    "dns_entropy":     2.1,         # Shannon entropy of DNS query strings
    "ports_used":      [443],
    "new_ip_flag":     False,
    # derived by features.py — DO NOT set manually:
    "ewma_delta":      0.01,
    "z_score":         0.8,
    "spike_delta":     0.0,
}

# Output from trust.py → SQLite + results.jsonl
trust_result = {
    "device_id":  "cam-01",
    "score":      87,              # int 0-100
    "status":     "TRUSTED",       # TRUSTED|MONITOR|SUSPICIOUS|HIGH RISK
    "reasons":    [                # list[str]
        "Port 22 unauthorized → -40pts",
        "DNS entropy 4.2 > 3.5 → -15pts",
    ],
    "timestamp":  1234567890,      # unix int
}

# Audit log entry
audit_entry = {
    "timestamp":    "2026-03-14T00:00:00Z",
    "event_type":   "trust_violation",
    "device_id":    "cam-02",
    "details":      "Port 22 unauthorized",
    "score_before": 92,
    "score_after":  52,
    "prev_hash":    "sha256:aabbcc...",
    "hash":         "sha256:ddeeff...",
}
```

---

## File Outputs

```
eclipse.db        SQLite WAL — score history, queried by MCP/API
results.jsonl     one trust_result per line — TUI reads this
audit.log         append-only hash-chained event log
data.jsonl        raw device windows from scapy (production path)
reports/          AI-generated .md incident reports
models/           pre-trained IsolationForest pickles (not in git)
```

**Why SQLite AND jsonl:**
- SQLite → history queries, MCP/API random access
- results.jsonl → TUI tails it like a log, human-readable, `cat`-able
- audit.log → survives DB corruption, tamper-evident

---

## Trust Score Model

```
Score starts: 100 (carries forward)
──────────────────────────────────────────────
Policy  port violation          -40 pts
Policy  new destination IP      -10 pts
Drift   traffic spike Z > 3.0   -20 pts
Drift   DNS entropy H > 3.5     -15 pts
Drift   EWMA drift Δ > 0.3       -5 pts
ML      IsolationForest < -0.1   -8 pts
──────────────────────────────────────────────
Clean window recovery            +2 pts
Clamped: max(0, min(100, score))

Tiers:
  80-100  TRUSTED      green
  60-79   MONITOR      yellow
  40-59   SUSPICIOUS   dark_orange
  0-39    HIGH RISK    red   ← TUI row flashes dark_red
```

---

## Burn-in

```
New device detected → STATE_CALIBRATING
  Engine buffers 10 windows
  8/10 must be clean
  On pass → STATE_ACTIVE, scoring begins
  TUI shows: score=--- status=⏳ CALIB...

seed_baseline.py pre-injects 10 clean windows → all devices boot ACTIVE
```

---

## Engine Modules

```
engine/features.py     entry point  enrich_window(window)
                       burn-in, derived features, orchestration
                       anti-poisoning: freeze EWMA after 3 consecutive anomalies

engine/policy.py       rule checks — loads policies/<device_type>.json
                       unknown type → policies/default.json (fallback)
                       sanitizes device_type (path traversal safe)
                       bad JSON → fallback, never crashes

engine/drift.py        Z-Score, EWMA delta, Shannon entropy signals

engine/ml.py           IsolationForest — pre-trained, never retrained live
                       feature vector (8 fixed):
                         [bytes, packets, dns_entropy, unique_dest_ips,
                          z_score, ewma_delta, new_ip_flag, spike_delta]
                       threshold: -0.1

engine/trust.py        aggregates all deductions → score
                       writes SQLite + appends results.jsonl
                       public: get_latest_scores(), get_score_history(device_id)

engine/policy_generator.py   stub (deferred feature)
```

---

## Policy Files

```
policies/default.json    paranoid fallback
policies/camera.json     ports [443,80,554], entropy max 3.5
policies/bulb.json       ports [443,80], entropy max 2.5
policies/sensor.json     ports [443,1883], entropy max 2.0
policies/thermostat.json
policies/router.json     allow_new_ips: true, entropy max 4.0
policies/lock.json       ultra paranoid, 50KB max
```

Add new device type: drop `<type>.json` in `policies/`. Zero code changes.

---

## IsolationForest Strategy

```
Training: python train_models.py
Verify:   python verify_ml.py  (run before every demo)

contamination=0.05, n_estimators=100, random_state=42
500 normal windows per class, tight Normal distributions

Normal window IF score: > -0.1  → clean
Attack window IF score: < -0.1  → anomaly → -8pts

Models: models/cam_baseline.pkl
        models/bulb_baseline.pkl
        models/sensor_baseline.pkl
```

---

## Demo Attack Sequence

```bash
# Terminal 1
python seed_baseline.py && python main.py

# Terminal 2 — after TUI shows all devices TRUSTED
ECLIPSE_FAST_MODE=1 python data/simulate_attack.py --device cam-02 --attack dns_tunnel
```

```
T=0:00  cam-02  92  TRUSTED    (baseline)
T=0:20  window1 87  TRUSTED    (EWMA -5)
T=0:40  window2 52  SUSPICIOUS (Z -20, DNS -15, ML -8)
T=1:00  window3 28  HIGH RISK  (port22 -40, DNS -15, newIP -10, Z -20, EWMA -5, ML -8)

TUI: cam-02 row flashes red
[2] select cam-02
[r] phi3:mini generates incident report (~8s)
[i] instant score history inspect
```

---

## MCP Demo (Arch Linux)

```bash
# While main.py is running:
npx @modelcontextprotocol/inspector python mcp_server.py
# opens http://localhost:5173
# judges click tools live — get_device_scores(), get_incident_report("cam-02")
```

---

## Project Structure

```
ThrushGuard/
├── engine/
│   ├── features.py           ✅
│   ├── policy.py             ✅
│   ├── drift.py              ✅
│   ├── ml.py                 ✅
│   ├── trust.py              ✅
│   └── policy_generator.py   ✅ stub
├── data/
│   ├── synthetic.py          ✅
│   └── scapy-collector.py    (real NIC capture)
├── TUI/
│   └── dashboard.py          ✅ [r] report, [i] inspect
├── intent/
│   └── narrator.py           ✅ phi3:mini reports
├── compliance/
│   └── audit.py              ✅ hash chain
├── policies/
│   └── *.json                ✅ 7 device types
├── models/
│   └── *.pkl                 ✅ pre-trained
├── tests/
│   └── test_api.py           ✅ 35 tests
├── main.py                   ✅
├── mcp_server.py             ✅
├── seed_baseline.py          ✅
├── train_models.py           ✅
├── verify_ml.py              ✅
├── simulate_attack.py        ✅
├── requirements.txt          ✅
└── .gitignore                ✅

NOT BUILT:
  api/main.py                 ← /health /scores /scores/{id}
```

---

## Tech Stack

```
Python 3.11+
rich          TUI (PRIMARY INTERFACE)
scikit-learn  IsolationForest
numpy         Z-Score, EWMA, Shannon entropy
fastapi       background REST API
sqlite3       WAL mode score history
mcp           FastMCP server
httpx         Ollama calls (async)
ollama        phi3:mini local LLM
scapy         live packet capture (production)
```

---

## Risk Mitigations

| Risk | Mitigation |
|------|-----------|
| Burn-in delay | seed_baseline.py |
| Ollama down | generate_report_fallback() always works |
| Models missing | verify_ml.py exits 1 before demo |
| SQLite lock | WAL mode + timeout=10 |
| TUI crash | headless fallback in main.py |
| Terminal narrow | hide DRIFT <100 cols, TYPE <80 cols |
| Attack too fast | time.sleep(20) between windows |