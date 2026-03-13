# ThrushGuard — Project Context
> Feed this file to any AI model before asking it to write code.
> Start every session by sharing this file alongside archi.md and control-flow.md.

---

## What We're Building

**ThrushGuard** — A self-hosted IoT trust scoring and behavioral drift analytics engine.
Runs entirely locally. No cloud. No browser. One terminal.

**One-line pitch:**
> "Silent behavioral drift is how attackers stay hidden for weeks. ThrushGuard catches it in 60 seconds — no cloud, no config, no alert fatigue."

**Team:** Exploit X — Harshit JK, Barath VS, Hemanth Gupta P, Sri Raghav R
**Event:** Eclipse Hackathon (GDG JSSATEB)
**Theme:** IoT Trust & Drift Analytics
**Constraint:** 24-hour hackathon, starting from zero.

---

## Hardware (Demo Machine)

```
RAM:  24GB
GPU:  RTX 4050 — 6GB VRAM
OS:   Kali Linux
```

---

## The Problem

IoT devices (cameras, bulbs, sensors) are notoriously hard to secure:
- They can't run endpoint agents
- Firmware rarely gets updated — old devices stay vulnerable forever
- One compromised device can pivot to breach the entire network
- SOC teams drown in alerts — 500/day, 490 false positives, real threats get missed

**The specific gap nobody solves well:**
Silent behavioral drift — a device gets compromised and slowly changes its communication
patterns. No single threshold fires. By the time anyone notices, the attacker has been
inside for weeks.

**Existing tools (Cisco, Defender for IoT, Darktrace):**
- Enterprise-only, six-figure contracts
- Cloud-dependent — data leaves your network
- Black box — no explainability
- Still require humans staring at dashboards

---

## Our Solution — Three Layers

**1. Policy Engine (rule-based, fires first)**
Hard rules per device class — allowed ports, max DNS entropy, new IP flag.
Catches known-bad behavior immediately. -40pts for port violation, -10pts for new IP.
Policies are JSON files in `policies/` — editable by admin.

**2. Drift Detection (statistical)**
- Z-Score → sudden traffic bursts
- EWMA   → slow gradual drift (low-and-slow attacks)
- Shannon Entropy → DNS tunneling (high-entropy query strings)

**3. ML Anomaly Detection (IsolationForest)**
Pre-trained on 500 normal windows per device class, pickled before demo.
Never retrained live. Catches subtle multi-feature anomalies the rules miss.
IF score < -0.1 → anomaly → -8pts.

**All three feed into trust.py → 0-100 score per device, updated every 60s.**

---

## Architecture Decisions

| Decision | Chosen | Rejected | Why |
|---|---|---|---|
| Frontend | Rich TUI (btop-style) | HTML/React | TUI is the differentiator — one terminal, no browser |
| TUI imports | Direct engine imports | HTTP calls | Zero networking complexity |
| FastAPI | Background only | Primary interface | Health + scores endpoint for judges |
| ML baseline | Pre-trained + pickled | Live retraining | Deterministic demo, no cold start |
| Attack sim | simulate_attack.py CLI | Manual injection | One command during demo |
| SQLite | WAL mode + timeout=10 | Default mode | Handles concurrent reads/writes |
| Ollama | Deferred (time permitting) | Core feature | Core layer ships first |
| Compliance ISO | Stripped | Kept | Not needed for core demo |

---

## Project Structure

```
ThrushGuard/
├── data/
│   ├── synthetic.py              # IoT traffic simulator — 5 devices, 60s windows
│   └── scapy_collector.py        # Real packet capture (production path, not used in demo)
│
├── engine/
│   ├── features.py               # Burn-in, derived features (z_score, ewma, spike_delta)
│   ├── policy.py                 # Rule-based checks — ports, DNS entropy, new IP
│   ├── drift.py                  # Z-Score + EWMA + Shannon Entropy signals
│   ├── ml.py                     # IsolationForest — pre-trained pickle, never retrains live
│   └── trust.py                  # Aggregates policy + drift + ml → 0-100 score
│
├── compliance/
│   └── audit.py                  # Hash-chained tamper-evident event log (no ISO mapping)
│
├── TUI/
│   └── dashboard.py              # Rich btop-style TUI — PRIMARY INTERFACE
│
├── data/simulate_attack.py       # CLI attack injector: --device --attack {dns_tunnel|botnet|port_scan|exfil}
│
├── models/
│   ├── cam_baseline.pkl
│   ├── bulb_baseline.pkl
│   └── sensor_baseline.pkl
│
├── policies/
│   ├── camera.json
│   ├── bulb.json
│   └── sensor.json
│
├── train_models.py               # Pre-train + pickle IsolationForest models
├── verify_ml.py                  # Pre-demo sanity check
├── seed_baseline.py              # Pre-load 10 clean windows → skip burn-in for demo
├── main.py                       # Entry point — boots everything
├── requirements.txt
└── tests/
    └── test_api.py
```

---

## Shared Data Contract (CRITICAL — all modules use this exact shape)

```python
# Input to all engines
device_window = {
    "device_id":       "cam-01",    # string
    "device_type":     "camera",    # camera | bulb | sensor
    "timestamp":       1234567890,  # unix int
    "bytes":           1048576,     # total bytes in 60s window
    "packets":         120,
    "unique_dest_ips": 2,
    "dns_entropy":     2.1,         # Shannon entropy of DNS query strings
    "ports_used":      [443],
    "new_ip_flag":     False,       # bool — contacted IP not in baseline?
    "ewma_delta":      0.02,        # deviation from EWMA baseline
    "z_score":         1.2,         # Z-Score of bytes this window
    "spike_delta":     0.0          # % change from previous window
}

# Output from trust.py → SQLite → TUI
trust_result = {
    "device_id": "cam-01",
    "score":     87,                # int 0-100
    "status":    "TRUSTED",        # TRUSTED | MONITOR | SUSPICIOUS | HIGH RISK
    "reasons":   [
        "Port 22 unauthorized → -40pts",
        "DNS entropy 4.2 > 3.5 → -15pts"
    ],
    "timestamp": 1234567890
}

# Audit log entry
audit_entry = {
    "timestamp":   "2025-01-01T00:00:00Z",
    "event_type":  "trust_violation",   # trust_violation | score_update | anomaly_detected
    "device_id":   "cam-02",
    "details":     "Port 22 unauthorized",
    "score_before": 92,
    "score_after":  52,
    "prev_hash":   "sha256:aabbcc...",
    "hash":        "sha256:ddeeff..."
}
```

---

## Trust Score Model

```
Score starts at: 100 (carries forward between windows)
────────────────────────────────────────────────────
Policy — port violation          → -40 pts
Policy — new destination IP      → -10 pts
Drift  — traffic spike (Z > 3)   → -20 pts
Drift  — DNS entropy (H > 3.5)   → -15 pts
Drift  — EWMA drift (Δ > 0.3)    → -5 pts
ML     — IF anomaly (< -0.1)     → -8 pts
────────────────────────────────────────────────────
Clean window recovery            → +2 pts
Clamped: max(0, min(100, score))

Tiers:
  80-100 → TRUSTED      ✅
  60-79  → MONITOR      🟡
  40-59  → SUSPICIOUS   🟠
  < 40   → HIGH RISK    🔴
```

---

## IsolationForest Strategy

- Pre-trained on 500 synthetic normal windows per device class
- `contamination=0.05`, `n_estimators=100`, `random_state=42`
- Pickled to `models/{class}_baseline.pkl` — never retrained live
- Feature vector (8, fixed order): `[bytes, packets, dns_entropy, unique_dest_ips, z_score, ewma_delta, new_ip_flag, spike_delta]`
- Run `python verify_ml.py` before every demo

---

## Demo Attack Sequence

```bash
# Terminal 1
python main.py

# Terminal 2 (after devices exit CALIBRATING)
python data/simulate_attack.py --device cam-02 --attack dns_tunnel
```

```
T=0:00  cam-02 at 92  TRUSTED    (green)
T=0:20  window 1 →    TRUSTED    (EWMA drift -5 only)
T=0:40  window 2 →    SUSPICIOUS (Z-Score -20, DNS -15, ML -8)
T=1:00  window 3 →    HIGH RISK  (port 22 -40, DNS -15, new IP -10, Z -20, EWMA -5, ML -8)
```

TUI flashes the HIGH RISK row red. Violation feed scrolls. Score bar drains live.

---

## TUI Design (btop-inspired)

- Dark panels, dotted progress bars (`░░░` empty, `█` filled)
- Sparkline score history column per device (`▁▂▄▇█▅▃▁`)
- Whole row flashes red on HIGH RISK
- Live stats bar: TRUSTED / MONITOR / RISK counts + clock
- Bottom input panel: `attack <device> <type>` and `inspect <device>` commands
- Refreshes every 1s via Rich Live

---

## Failure Risks & Mitigations

| Risk | Mitigation |
|---|---|
| IsolationForest not flagging | Pre-train + verify_ml.py before demo |
| SQLite write lock | WAL mode + timeout=10 |
| TUI layout breaks on projector | Test at 80/120/180 col widths |
| Burn-in delay (10 min) | seed_baseline.py pre-loads clean windows |
| Attack windows fire too fast | time.sleep(20) between windows |

---

## Tech Stack

```
Python 3.11+
├── scikit-learn  → IsolationForest
├── numpy         → Z-Score, EWMA, Shannon Entropy
├── Rich          → TUI dashboard (PRIMARY INTERFACE)
├── SQLite        → WAL mode, shared state store
├── FastAPI       → background health/scores endpoint
└── Scapy         → real packet capture (production, not used in demo)
```

---

## What's Deferred (build if time allows)

- Ollama NL query interface (intent/parser.py + responder.py)
- ISO 27001 / SOC-2 compliance report
- Live Scapy sniffing
- Multi-node deployment
