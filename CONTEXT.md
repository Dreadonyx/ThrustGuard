# ThrustGuard — Project Context
> Feed this file to any AI model before asking it to write code.
> Start every session by sharing this file alongside `archi.md` and `control-flow-1.md`.

---

## What We're Building

**ThrustGuard** — A self-hosted IoT trust scoring and behavioral drift analytics engine.
Runs entirely locally. No cloud. No browser. One terminal.

**One-line pitch:**
> "Silent behavioral drift is how attackers stay hidden for weeks. ThrustGuard catches it in 60 seconds — no cloud, no config, no alert fatigue."

**Team:** Exploit X — Harshit JK, Barath VS, Hemanth Gupta P, Sri Raghav R
**Event:** Eclipse Hackathon (GDG JSSATEB)
**Theme:** IoT Trust & Drift Analytics
**Constraint:** 24-hour hackathon, starting from zero.

> **Note on naming:** The codebase uses `ThrustGuard` (project name) and `Eclipse` (internal engine codename) interchangeably in logs and module docstrings. Both refer to the same system.

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

**1. Policy Engine (rule-based, fires alongside drift)**
Hard rules per device class — allowed ports, max DNS entropy, new IP flag.
Policies are JSON files in `policies/` — editable by admin. Loaded + cached in memory.
Falls back to `default.json` for unknown device types.
- Port unauthorized → -40pts (per bad port)
- New destination IP → -10pts
- DNS entropy > policy max → -15pts

**2. Drift Detection (statistical)**
Three signals run on every enriched window:
- Z-Score → sudden traffic bursts (Z > 3.0 → -20pts)
- EWMA → slow gradual drift / low-and-slow attacks (delta > 0.3 → -5pts)
- Shannon Entropy → DNS tunneling (H > 3.5 → -15pts)

**3. ML Anomaly Detection (IsolationForest)**
Pre-trained on 500 normal windows per device class, pickled before demo.
Never retrained live. Catches subtle multi-feature anomalies the rules miss.
IF score < -0.1 → anomaly → -8pts (severity: mild if > -0.25, severe otherwise).

**All three signals feed into trust.py → 0-100 score per device, updated every 60s.**

> ⚠️ **Current implementation note:** `trust.py` aggregates drift + ML signals only.
> Policy violations are computed in `features.py` (via `PolicyEngine.check_policy`) and
> passed to `trust.py`, but the `calculate_trust()` function currently treats
> `policy_violations` as an ignored parameter (interface compat). Policy deductions do
> not yet reduce the trust score — this is a known gap.

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
| Ollama | Warmup at startup (non-blocking) | Core feature | Core layer ships first; falls back gracefully |
| Burn-in gate | 8/10 clean windows required | Simple count | Prevents attacker from poisoning calibration phase |
| Anti-poisoning | Freeze EWMA after 3 consecutive anomalies | None | Stops slow drift from shifting baseline |

---

## Project Structure

```
ThrustGuard/
├── data/
│   ├── synthetic.py              # IoT traffic simulator — 5 devices, 60s windows
│   ├── simulate_attack.py        # CLI attack injector: --device --attack {dns_tunnel|botnet|port_scan|exfil}
│   └── scapy-collector.py        # Real packet capture (production path, not used in demo)
│
├── engine/
│   ├── features.py               # Burn-in, derived features (z_score, ewma, spike_delta), anti-poisoning
│   ├── policy.py                 # Rule-based checks — ports, DNS entropy, new IP; JSON-driven
│   ├── drift.py                  # Z-Score + EWMA + Shannon Entropy signals
│   ├── ml.py                     # IsolationForest — pre-trained pickle, never retrains live
│   └── trust.py                  # Aggregates drift + ML → 0-100 score; writes to SQLite
│
├── compliance/
│   └── audit.py                  # Hash-chained tamper-evident event log
│
├── TUI/
│   └── dashboard.py              # Rich btop-style TUI — PRIMARY INTERFACE
│                                 # Reads directly from engine.trust — no HTTP
│
├── models/
│   ├── cam_baseline.pkl
│   ├── bulb_baseline.pkl
│   └── sensor_baseline.pkl
│
├── policies/
│   ├── camera.json
│   ├── bulb.json
│   ├── sensor.json
│   └── default.json              # Fallback for unknown device types
│
├── api/                          # ⚠ directory exists but api/main.py not yet implemented
│
├── main.py                       # Entry point — 7-step boot sequence
├── train_models.py               # Pre-train + pickle IsolationForest models
├── verify_ml.py                  # Pre-demo sanity check
├── requirements.txt
└── tests/
    └── test_api.py
```

> **Missing files (not yet implemented):**
> - `api/main.py` — FastAPI background server (`start_background()` is called in `main.py` but module doesn't exist yet)
> - `seed_baseline.py` — Pre-load clean windows to skip burn-in delay (referenced in old docs, not present)

---

## Startup Sequence (`main.py`)

```
[1/7] Load IsolationForest models (ml.py)       — crashes if .pkl missing → run train_models.py
[2/7] Initialize SQLite (WAL mode)              — eclipse.db (or $ECLIPSE_DB_PATH)
[3/7] Initialize AuditLog (hash chain)          — warns but continues if broken
[4/7] Ollama warmup (non-blocking background)   — model: qwen2.5-coder:7b; falls back gracefully
[5/7] Start SyntheticGenerator thread           — 5 devices, 60s windows (5s if ECLIPSE_FAST_MODE=1)
[6/7] Start FastAPI background thread (port 8000) — ⚠ api/main.py not yet implemented
[7/7] Launch Rich TUI (takes over main thread)
```

Run modes:
```bash
python main.py                          # Normal (60s windows)
ECLIPSE_FAST_MODE=1 python main.py      # Fast demo (5s windows)
```

---

## Call Flow (per device window)

```
data/synthetic.py  OR  data/simulate_attack.py
    ↓
engine/features.py :: enrich_window(raw_window)
    ├── Burn-in check (CALIBRATING → ACTIVE after 10 windows, 8/10 must be clean)
    ├── Compute derived features: z_score, ewma_delta, spike_delta
    ├── engine/policy.py :: PolicyEngine.check_policy(window)    → violations[]
    ├── engine/drift.py  :: DriftEngine.check_drift(window)      → signals[]
    ├── engine/ml.py     :: MLEngine.score_anomaly(window)       → ml_result or None
    ├── Anti-poisoning: freeze EWMA if ≥3 consecutive anomalies
    └── engine/trust.py  :: TrustEngine.calculate_trust(...)     → trust_result{}
            ├── Apply drift + ML deductions to carried-forward score
            ├── +2 pts recovery on clean window (capped at 100)
            ├── Write to SQLite (scores table)
            └── Write audit entry (compliance/audit.py)

TUI/dashboard.py (every 0.25s)
    └── engine.trust.get_latest_scores() → reads SQLite → renders table
```

---

## Shared Data Contract (CRITICAL — all modules use this exact shape)

```python
# Input to engines (raw from synthetic.py, enriched by features.py)
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
    # ↓ Computed by features.py after burn-in:
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
        "Traffic spike Z=4.12 > 3.0",
        "DNS entropy 4.2 > 3.5 (tunneling suspected)",
        "ML anomaly [severe] IF score -0.431 < -0.1"
    ],
    "timestamp": 1234567890
}

# Audit log entry (compliance/audit.py — hash-chained)
audit_entry = {
    "timestamp":   "2025-01-01T00:00:00Z",
    "event_type":  "trust_violation",   # trust_violation | score_update
    "device_id":   "cam-02",
    "details":     "Traffic spike Z=4.12 > 3.0",
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
────────────────────────────────────────────────────────────────
Drift  — Z-Score burst (Z > 3.0)      → -20 pts
Drift  — EWMA gradual drift (Δ > 0.3) → -5 pts
Drift  — DNS entropy (H > 3.5)        → -15 pts
ML     — IF anomaly (< -0.1)          → -8 pts
────────────────────────────────────────────────────────────────
Policy — port violation (per port)    → -40 pts  ⚠ not yet wired into score
Policy — new destination IP           → -10 pts  ⚠ not yet wired into score
Policy — DNS entropy > policy max     → -15 pts  ⚠ not yet wired into score
────────────────────────────────────────────────────────────────
Clean window recovery                 → +2 pts
Clamped: max(0, min(100, score))

Tiers:
  80-100 → TRUSTED      [√]
  60-79  → MONITOR      [!]
  40-59  → SUSPICIOUS   [?]
  < 40   → HIGH RISK    [X]
```

---

## Burn-in & Anti-Poisoning

**Burn-in (CALIBRATING → ACTIVE):**
- Requires `BURN_IN_WINDOWS = 10` windows
- Gate: at least `BURN_IN_CLEAN_THRESHOLD = 8` must be "clean" (dns_entropy < 3.5, z_score < 3.0, no new IP)
- If gate fails, calibration extends until threshold is met
- On ACTIVE transition: triggers `policy_generator` to auto-create a device policy

**Anti-poisoning (active phase):**
- If `≥ CONSECUTIVE_ANOMALY_FREEZE = 3` consecutive anomaly windows: EWMA baseline is frozen
- While frozen, drift is measured against the last-known-clean EWMA value
- Baseline unfreezes on first clean window

---

## IsolationForest Strategy

- Pre-trained on 500 synthetic normal windows per device class
- `contamination=0.05`, `n_estimators=100`, `random_state=42`
- Pickled to `models/{class}_baseline.pkl` — never retrained live
- Feature vector (8, **fixed order — do not change**):
  ```
  [bytes, packets, dns_entropy, unique_dest_ips, z_score, ewma_delta, new_ip_flag, spike_delta]
  ```
- `new_ip_flag` cast to int (0/1) before scoring
- Anomaly threshold: `< -0.1` → deduct 8pts
  - mild: score > -0.25
  - severe: score ≤ -0.25 (dns_tunnel attack lands around -0.43)
- Run `python verify_ml.py` before every demo

---

## TUI Design (btop-inspired)

- Dark panels, block progress bars (`░░░` empty, `█` filled)
- Braille sparkline score history column per device (uses `engine.trust.get_score_history`)
- Braille snake spinner in header bar (animates at 10Hz)
- Whole row turns `on dark_red` + blinks on HIGH RISK
- Live stats bar: TRUSTED / MONITOR / RISK counts + clock
- Bottom input panel: `attack <device> <type>` and `inspect <device>` commands (display only)
- Refreshes every 0.25s via Rich Live (4 FPS)
- Status icons: `[√]` TRUSTED, `[!]` MONITOR, `[?]` SUSPECT, `[X]` RISKY, `[∞]` CALIBRATING
- Device type icons: `[CAM]` camera, `[LIT]` bulb, `[SNR]` sensor

---

## SQLite Schema

```sql
-- eclipse.db (WAL mode, timeout=10s)

CREATE TABLE scores (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   TEXT NOT NULL,
    score       INTEGER NOT NULL,
    status      TEXT NOT NULL,
    reasons     TEXT NOT NULL,   -- JSON array of strings
    timestamp   INTEGER NOT NULL
);

CREATE TABLE audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT NOT NULL,
    event_type   TEXT NOT NULL,  -- trust_violation | score_update
    device_id    TEXT NOT NULL,
    details      TEXT NOT NULL,
    score_before INTEGER,
    score_after  INTEGER,
    prev_hash    TEXT NOT NULL,
    hash         TEXT NOT NULL
);
```

Current score per device is also cached in-memory (`_current_scores` dict in `trust.py`) to avoid a DB read on every window.

---

## Demo Attack Sequence

```bash
# Terminal 1
python main.py

# Terminal 2 (after devices exit CALIBRATING, ~10 windows × 60s = 10 min)
# Use ECLIPSE_FAST_MODE=1 to reduce to 10 × 5s = 50 seconds
python data/simulate_attack.py --device cam-02 --attack dns_tunnel
```

Expected progression on cam-02:
```
T=0:00  cam-02 at 92  TRUSTED     (green)
T=0:20  window 1 →    TRUSTED     (EWMA drift -5 only)
T=0:40  window 2 →    SUSPICIOUS  (Z-Score -20, DNS entropy -15, ML -8)
T=1:00  window 3 →    HIGH RISK   (Z -20, DNS -15, EWMA -5, ML -8)
```

TUI flashes the HIGH RISK row red. Score bar drains live. Reasons listed in violation feed.

---

## Tech Stack

```
Python 3.11+
├── scikit-learn ≥ 1.3.0  → IsolationForest
├── numpy        ≥ 1.24.0 → Z-Score, EWMA, Shannon Entropy
├── pandas       ≥ 2.0.0  → data manipulation (train_models.py)
├── rich         ≥ 13.0.0 → TUI dashboard (PRIMARY INTERFACE)
├── fastapi      ≥ 0.104.0 → background health/scores endpoint (⚠ api/main.py pending)
├── uvicorn      ≥ 0.24.0 → ASGI server for FastAPI
├── httpx        ≥ 0.25.0 → Ollama warmup ping
├── pytest       ≥ 8.0.0  → test runner
└── scapy                 → real packet capture (production, not used in demo)
```

---

## Failure Risks & Mitigations

| Risk | Mitigation |
|---|---|
| IsolationForest not flagging | Pre-train + `verify_ml.py` before demo |
| SQLite write lock | WAL mode + `timeout=10` |
| TUI layout breaks on projector | Test at 80/120/180 col widths |
| Burn-in delay (~10 min normal, ~50s fast mode) | Use `ECLIPSE_FAST_MODE=1` |
| Policy violations not reducing score | Known gap — `trust.py` ignores `policy_violations` arg |
| `api/main.py` missing | TUI still works; FastAPI startup will log a warning and continue |
| Ollama unavailable | Non-blocking warmup; fallback mode active automatically |

---

## What's Deferred / Known Gaps

| Item | Status |
|---|---|
| `api/main.py` — FastAPI background server | ❌ Not implemented |
| Policy deductions wired into trust score | ❌ Not wired (`policy_violations` param ignored in `trust.py`) |
| `seed_baseline.py` — skip burn-in for demo | ❌ Not present (use `ECLIPSE_FAST_MODE=1` instead) |
| Ollama NL query interface | ❌ Warmup only; no parser/responder |
| ISO 27001 / SOC-2 compliance report | ❌ Deferred |
| Live Scapy sniffing | ❌ `scapy-collector.py` exists but not integrated |
| Multi-node deployment | ❌ Deferred |
