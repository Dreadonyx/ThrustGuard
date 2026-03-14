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

```text
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

```text
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

# Output from trust.py → SQLite + results.jsonl + live DB
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
```

---

## File Outputs

```text
eclipse.db        SQLite WAL — score history, queried by MCP/API
results.jsonl     one trust_result per line — legacy
logs/live/        JSON lines and atomic JSON dump outputs per device
reports/          AI-generated .md incident reports
models/           pre-trained IsolationForest pickles
```

---

## Trust Score Model

```text
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

## Project Structure

```text
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
│   └── dashboard.py          ✅ [r] report, [i] inspect, zero Rich Live artifacts
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
```
