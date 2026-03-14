# Eclipse — TrustGuard Project Workflow

> **One-stop reference** for how the system is set up, how data flows, and how to verify it.
> This project has transitioned to **JSON Mode** for real-time monitoring.

---

## 📁 Project Structure

```
ThrustGuard/
├── main.py                  ← Entry point (Interface selection + Sniffer + TUI)
│
├── engine/                  ← Core scoring pipeline
│   ├── features.py          ← enrichment, scoring, and atomic JSON writes (Orchestrator)
│   ├── policy.py            ← Rule-based port / DNS / IP checks
│   ├── drift.py             ← Z-Score, EWMA, Spike delta signals
│   └── ml.py                ← IsolationForest anomaly scoring
│
├── capture/                  
│   └── sniffer.py           ← Scapy-based live traffic harvester
│
├── data/
│   └── simulate_attack.py   ← Injects malicious windows into the pipeline
│
├── TUI/
│   └── dashboard.py         ← Rich live terminal dashboard (JSON Mode)
│
├── logs/live/               ← Intermediate state storage (Pollable)
│   ├── _all_latest.json     ← Aggregated state for all devices
│   └── {device_id}.jsonl    ← Historical windows for specific devices
│
├── models/                  ← Pre-trained IsolationForest pickles
│   ├── camera_baseline.pkl
│   ├── bulb_baseline.pkl
│   └── sensor_baseline.pkl
│
├── config/                  ← Static configuration
│   └── devices.json         ← MAC to Device ID mapping
│
├── compliance/              ← Optional: formal auditing module
│   ├── audit.py             ← SQLite hash-chained tamper-evident log
│   └── report.py            ← ISO 27001 / SOC-2 report generator
│
├── train_models.py          ← One-time model training script
└── verify_ml.py             ← Pre-demo model sanity check
```

---

## 🔄 Full Data Flow (JSON Mode)

```
[capture/sniffer.py] (Live)        OR        [data/simulate_attack.py] (Demo)
  Collects / Injects traffic windows
         │
         ▼
[engine/features.py]  (pipeline.process_window)
  ┌─────────────────────────────────────────────────────────┐
  │ 1. ENRICHMENT                                           │
  │    • z_score = |bytes - mean| / std                     │
  │    • ewma_delta = |bytes - ewma| / ewma                 │
  │    • spike_delta = (bytes - prev) / prev                │
  │                                                         │
  │ 2. SCORING                                              │
  │    • Policy Violations (unauthorized ports, IPs)        │
  │    • Drift Signals (statistical anomalies)              │
  │    • ML Anomaly (IsolationForest score < -0.1)          │
  │                                                         │
  │ 3. AGGREGATION                                          │
  │    • score = clamp(score + recovery or - penalties)      │
  │    • Tiers: TRUSTED, MONITOR, SUSPICIOUS, HIGH RISK     │
  └─────────────────────────────────────────────────────────┘
         │
         ▼
[logs/live/*.json]
  Writes atomic JSON updates for the TUI to poll
         │
         ▼
[TUI/dashboard.py]
  Polls _all_latest.json every 0.2s → Refreshes UI
```

---

## 🚀 Startup Sequence (`python main.py`)

| Step | What Happens |
|------|-------------|
| **1** | **Requirement Check**: Verifies `models/*.pkl` and `config/devices.json` exist. |
| **2** | **Engine Initialization**: Loads IsolationForest models into memory. |
| **3** | **Interface Selection**: Identifies available network interfaces (e.g., "Wi-Fi"). |
| **4** | **Sniffer Start**: Launches a background thread running Scapy's `AsyncSniffer`. |
| **5** | **Dashboard Launch**: Takes over the main thread with the Rich TUI. |

---

## 🛡️ Trust Score Model

```
Start:   100 (or carry forward from logs/live)

Deductions (cumulative per window):
  Policy violations:
    Unauthorized port        → -40 pts each
    New destination IP       → -10 pts
    DNS entropy > policy max → -15 pts
  
  Drift signals:
    Z-Score > 3.0            → -20 pts
    EWMA delta > 0.3         → -5 pts
  
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

```powershell
# In a second terminal:
python data\simulate_attack.py --device cam-02 --attack dns_tunnel --interval 10
```

1. **Injection**: `simulate_attack.py` builds an escalating series of malicious traffic windows.
2. **Bypass**: It bypasses the sniffer and calls `engine.features.process_window` directly.
3. **Observation**: The dashboard reacts immediately as `logs/live` is updated.

### Attack Types
| Attack | Key Signals |
|--------|-------------|
| `dns_tunnel` | High DNS entropy + Port 22 + High Z-Score |
| `botnet` | Multiple new destination IPs + Latent ports |
| `port_scan` | High packet count + Many unauthorized ports |
| `exfil` | Massive Spike Delta + Sustained high bytes |

---

## 🛠️ Setup & Development

### 1. Environment Setup
```powershell
# Create and activate virtual environment
py -3.11 -m venv .venv
.\.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
# Optional: pip install fastapi uvicorn (for API)
```

### 2. Model Preparation
```powershell
# Train ML models (needed once)
python train_models.py

# Verify models
python verify_ml.py
```

### 3. Demo Run
```powershell
# Clear old logs
Remove-Item -Recurse -Force logs/live/

# Start the system
python main.py

# FAST MODE (5s windows instead of 60s)
$env:ECLIPSE_FAST_MODE="1"; python main.py
```

---

## 🔄 Demo Reset (`reset_data.sh`)

Use the reset script to wipe all runtime-generated data and return the system to a **clean initial state** between demo sessions.

```bash
# Full reset (clears everything listed below)
bash reset_data.sh

# Preview what *would* be deleted without touching anything
bash reset_data.sh --dry-run

# Reset a single device only
DEVICE_ID=cam-01 bash reset_data.sh
```

### What gets reset

| Target | Path | Notes |
|--------|------|-------|
| Live device state | `logs/live/*.json / *.jsonl` | Per-device scores & aggregated view |
| Synthetic logs | `logs/synthetic/` | Generated traffic history |
| Compliance artefacts | `compliance/*.db / *.txt` | Audit DB + reports |
| Python bytecode | `**/__pycache__/` | Cosmetic; rebuilt automatically |

### What is **preserved**

| Target | Why |
|--------|-----|
| `models/*.pkl` | IsolationForest models (expensive to retrain) |
| `config/devices.json` | MAC → Device ID mapping |
| `data/` | Simulation scripts |
| `.venv/` | Python virtual environment |

> **After reset**, run `python main.py` (and optionally `simulate_attack.py`) to start fresh.

---

## 🗑️ Troubleshooting

| Error | Fix |
|-------|-----|
| `Missing baseline models` | Run `python train_models.py` |
| `Scapy Permission Denied` | Run terminal as Administrator (needed for live sniffing) |
| `No data in TUI` | Verify traffic is flowing or use `simulate_attack.py` |
| `Dashboard too small` | Resize terminal to at least 100x30 |
| `Interface not found` | Set `ECLIPSE_IFACE` env var to your active interface name |
