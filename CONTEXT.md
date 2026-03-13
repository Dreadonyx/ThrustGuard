# ThrustGuard — Project Context

> **Feed this file to any AI model before asking it to write code.**
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

> ✅ **Policy deductions ARE now wired in.** As of the current implementation,
> `trust.py::calculate_trust()` collects `policy_violations`, `drift_signals`, and
> `ml_result` into a single `all_deductions` list and applies them all to the score.
> The previous gap (policy being ignored) is **resolved**.

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
| Attack seeding | `seed_device_baseline()` called on first inject | Separate seed script | Attack windows are scored immediately; no separate setup step |

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
│   ├── features.py               # Burn-in, derived features (z_score, ewma, spike_delta),
│   │                             # anti-poisoning, seed_device_baseline(), enrich_window()
│   ├── policy.py                 # Rule-based checks — ports, DNS entropy, new IP; JSON-driven
│   ├── policy_generator.py       # Auto-generates per-device policy JSON after burn-in
│   ├── drift.py                  # Z-Score + EWMA + Shannon Entropy signals
│   ├── ml.py                     # IsolationForest — pre-trained pickle, never retrains live
│   └── trust.py                  # Aggregates ALL signals (policy + drift + ML) → 0-100 score;
│                                 # writes to SQLite + audit log
│
├── compliance/
│   ├── audit.py                  # Hash-chained tamper-evident event log (SHA-256 chain)
│   └── report.py                 # Plain-text compliance report generator (ISO 27001 / SOC-2)
│
├── api/
│   └── main.py                   # ✅ FastAPI background server (IMPLEMENTED)
│                                 #    GET /health  GET /scores  GET /compliance/report
│                                 #    Runs via start_background(port=8000) in uvicorn daemon thread
│
├── TUI/
│   └── dashboard.py              # Rich btop-style TUI — PRIMARY INTERFACE
│                                 # Reads directly from engine.trust — no HTTP
│
├── models/
│   ├── cam_baseline.pkl          # IsolationForest model for cameras
│   ├── bulb_baseline.pkl         # IsolationForest model for bulbs
│   └── sensor_baseline.pkl       # IsolationForest model for sensors
│
├── policies/
│   ├── camera.json               # Class-level type policy (allowed_ports, max_dns_entropy, ...)
│   ├── bulb.json
│   ├── sensor.json
│   ├── default.json              # Fallback for unknown device types
│   ├── cam-01.json               # ← Auto-generated per-device policies (written after burn-in
│   ├── cam-02.json               #   by policy_generator.py — tighter than class defaults)
│   ├── bulb-01.json
│   ├── bulb-02.json
│   └── sensor-01.json
│
├── main.py                       # Entry point — 7-step boot sequence
├── train_models.py               # Pre-train + pickle IsolationForest models
├── verify_ml.py                  # Pre-demo sanity check
├── requirements.txt
└── tests/
    └── test_api.py
```

---

## Startup Sequence (`main.py`)

```
[1/7] Load IsolationForest models (ml.py)       — crashes if .pkl missing → run train_models.py
[2/7] Initialize SQLite (WAL mode)              — eclipse.db (or $ECLIPSE_DB_PATH)
[3/7] Initialize AuditLog (hash chain)          — warns but continues if broken
[4/7] Ollama warmup (non-blocking background)   — model: qwen2.5-coder:7b; falls back gracefully
[5/7] Start SyntheticGenerator thread           — 5 devices, 60s windows (5s if ECLIPSE_FAST_MODE=1)
[6/7] Start FastAPI background thread (port 8000) — ✅ api/main.py IS implemented
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
    ├── Burn-in check (CALIBRATING → ACTIVE after ≥10 windows AND ≥8/10 clean)
    │       └── On ACTIVE: trigger policy_generator.generate_policy() → writes policies/<device_id>.json
    ├── Compute derived features: z_score, ewma_delta, spike_delta
    ├── engine/policy.py  :: PolicyEngine.check_policy(window)    → violations[]
    ├── engine/drift.py   :: DriftEngine.check_drift(window)      → signals[]
    ├── engine/ml.py      :: MLEngine.score_anomaly(window)       → ml_result or None
    ├── Anti-poisoning: freeze EWMA if ≥3 consecutive anomalies
    └── engine/trust.py   :: calculate_trust(...)                 → trust_result{}
            ├── Combine: all_deductions = policy_violations + drift_signals + [ml_result]
            ├── Apply total deduction (all three sources) to carried-forward score
            ├── +2 pts recovery on clean window (capped at 100)
            ├── Write to SQLite (scores table)
            └── Write audit entry (compliance/audit.py)

TUI/dashboard.py (every 0.25s)
    └── engine.trust.get_latest_scores() → reads SQLite → renders table

api/main.py (GET /scores, GET /compliance/report)
    └── engine.trust.get_latest_scores() / compliance.report.generate()
```

---

## Shared Data Contract (CRITICAL — all modules use this exact shape)

```python
# Raw input from synthetic.py / simulate_attack.py
device_window_raw = {
    "device_id":       "cam-01",    # string
    "device_type":     "camera",    # camera | bulb | sensor
    "timestamp":       1234567890,  # unix int
    "bytes":           1048576,     # total bytes in 60s window
    "packets":         120,
    "unique_dest_ips": 2,
    "dns_entropy":     2.1,         # Shannon entropy of DNS query strings
    "ports_used":      [443],
    "new_ip_flag":     False,       # bool — contacted IP not in baseline?
}

# Enriched window (after features.py adds derived fields)
device_window_enriched = {
    **device_window_raw,
    "ewma_delta":  0.02,   # deviation from EWMA baseline
    "z_score":     1.2,    # Z-Score of bytes this window
    "spike_delta": 0.0,    # % change from previous window
}

# Output from trust.py → SQLite → TUI / API
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

# Deduction dict format — shared by policy.py, drift.py, ml.py
deduction = {
    "reason":    "Port 22 unauthorized (allowed: [443, 80])",
    "deduction": 40,           # points to subtract from trust score
    # ml.py also adds: "if_score": -0.431
}

# Audit log entry (compliance/audit.py — hash-chained)
audit_entry = {
    "timestamp":    "2025-01-01T00:00:00Z",
    "event_type":   "trust_violation",   # trust_violation | score_update
    "device_id":    "cam-02",
    "details":      "Traffic spike Z=4.12 > 3.0",
    "score_before": 92,
    "score_after":  52,
    "prev_hash":    "sha256:aabbcc...",
    "hash":         "sha256:ddeeff..."
}
```

---

## Trust Score Model

```
Score starts at: 100 (carries forward between windows — in-memory + SQLite)
────────────────────────────────────────────────────────────────────────────
Policy — port violation (per bad port)    → -40 pts  ✅ WIRED
Policy — new destination IP               → -10 pts  ✅ WIRED
Policy — DNS entropy > policy max         → -15 pts  ✅ WIRED
────────────────────────────────────────────────────────────────────────────
Drift  — Z-Score burst (Z > 3.0)          → -20 pts  ✅ WIRED
Drift  — EWMA gradual drift (Δ > 0.3)    →  -5 pts  ✅ WIRED
Drift  — DNS entropy (H > 3.5)           → -15 pts  ✅ WIRED
────────────────────────────────────────────────────────────────────────────
ML     — IF anomaly (< -0.1)             →  -8 pts  ✅ WIRED
────────────────────────────────────────────────────────────────────────────
Clean window recovery                    →  +2 pts
Clamped: max(0, min(100, score))

Note: DNS entropy is checked TWICE (drift.py uses global threshold 3.5;
      policy.py uses per-device threshold from policy JSON). Both can fire
      independently on the same window, each deducting their own points.

Tiers:
  80-100 → TRUSTED      [√]
  60-79  → MONITOR      [!]
  40-59  → SUSPICIOUS   [?]
  < 40   → HIGH RISK    [X]
```

---

## Burn-in & Anti-Poisoning

**Burn-in (CALIBRATING → ACTIVE):**
- Requires `BURN_IN_WINDOWS = 10` windows minimum
- Gate: at least `BURN_IN_CLEAN_THRESHOLD = 8` of those must be "clean":
  - `dns_entropy < 3.5` AND `z_score < 3.0` AND `new_ip_flag == False`
- If gate fails after 10 windows, calibration extends until threshold is met
- On ACTIVE transition: `policy_generator.generate_policy()` is called — writes
  `policies/<device_id>.json` with headroom added above observed burn-in maximums
- While CALIBRATING: `enrich_window()` returns `None` — window is silently dropped

**Attack simulator bypass (`seed_device_baseline`):**
- `simulate_attack.py` calls `features.seed_device_baseline(device_id, device_type, initial_score=92)`
  on the **first window** for each injected device
- This forces the device directly into `STATE_ACTIVE` with pre-computed baseline stats
  (mean/std/ewma from `_SEED_PROFILES`) and fills the buffer with clean template windows
- Also writes the `initial_score` to SQLite so the TUI shows the device immediately
- Without this, all attack windows during demo would be consumed by calibration

**Anti-poisoning (active phase):**
- If `≥ CONSECUTIVE_ANOMALY_FREEZE = 3` consecutive anomaly windows: EWMA baseline is frozen
- While frozen: drift is measured against the last-known-clean EWMA value
- Baseline unfreezes on first clean window

**EWMA mechanics:**
- `EWMA_ALPHA = 0.3` (30% current window, 70% history)
- `ewma_delta = abs(bytes - ewma) / ewma`  — fractional deviation
- When frozen: EWMA value doesn't update, but ewma_delta still computes against it

---

## IsolationForest Strategy

- Pre-trained on 500 synthetic normal windows per device class (`train_models.py`)
- `contamination=0.05`, `n_estimators=100`, `random_state=42`, `n_jobs=-1`
- Pickled to `models/{class}_baseline.pkl` — **never retrained live**
- Feature vector (8, **fixed order — do not change**):
  ```
  [bytes, packets, dns_entropy, unique_dest_ips, z_score, ewma_delta, new_ip_flag, spike_delta]
  ```
  This order is defined as `FEATURE_ORDER` in both `engine/ml.py` and `train_models.py` — they must stay in sync.
- `new_ip_flag` cast to `int` (0/1) before scoring
- Anomaly threshold: `< -0.1` → deduct 8pts
  - mild: score > -0.25
  - severe: score ≤ -0.25 (dns_tunnel attack window 3 lands around -0.43)
- Run `python verify_ml.py` before every demo

---

## Policy Engine Details (`engine/policy.py`)

- Policies cached in `_policy_cache: dict[str, dict]` — loaded **once** per process
- Lookup order: `policies/<device_id>.json` → `policies/<device_type>.json` → `policies/default.json` → hardcoded defaults
  - Wait: `policy.py` actually checks `<device_type>.json` first, then `default.json`. Auto-generated `<device_id>.json` files are in the directory but policy.py loads by type, not by ID.
  - To use per-device policy, the device_type would need to match `<device_id>` or the code would need to check device_id first. Per-device JSONs exist but are generated by `policy_generator.py` with a device-specific key.
- Path traversal protection: `_sanitize_device_type()` strips anything not `[a-z0-9_\-]`
- Missing policy fields filled from `POLICY_DEFAULTS`:
  ```python
  {"allowed_ports": [443, 80], "allow_new_ips": False,
   "max_dns_entropy": 3.5, "max_bytes_per_window": 5_000_000}
  ```
- `reload_policies()` clears cache — for hot-reload if JSONs are edited at runtime
- Three checks (all fire independently):
  1. Port check: for each port in `ports_used` not in `policy.allowed_ports` → -40pts each
  2. New IP: if `new_ip_flag` and `not policy.allow_new_ips` → -10pts
  3. DNS entropy: if `dns_entropy > policy.max_dns_entropy` → -15pts

---

## Policy Generator (`engine/policy_generator.py`)

- Called by `features.py::_handle_burn_in()` once burn-in completes
- Inspects the buffer of burn-in windows and derives conservative limits:
  - `allowed_ports`: union of all ports seen
  - `max_dns_entropy`: `max(observed) × 1.2` (20% headroom)
  - `max_bytes_per_window`: `max(observed) × 1.5` (50% headroom)
  - `allow_new_ips`: always `False` (conservative default)
- Writes to `policies/<device_id>.json` (e.g. `policies/cam-02.json`)
- If file write fails → logs error, continues (no crash)

---

## SQLite Schema

```sql
-- eclipse.db (WAL mode, synchronous=NORMAL, timeout=10s)

CREATE TABLE scores (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   TEXT NOT NULL,
    score       INTEGER NOT NULL,
    status      TEXT NOT NULL,
    reasons     TEXT NOT NULL,   -- JSON array of strings
    timestamp   INTEGER NOT NULL -- unix timestamp (int)
);
CREATE INDEX idx_scores_device ON scores(device_id, timestamp);

CREATE TABLE audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT NOT NULL,   -- ISO-8601 UTC string
    event_type   TEXT NOT NULL,   -- trust_violation | score_update
    device_id    TEXT NOT NULL,
    details      TEXT NOT NULL,
    score_before INTEGER,
    score_after  INTEGER,
    prev_hash    TEXT NOT NULL,
    hash         TEXT NOT NULL    -- sha256: prefixed hex
);
CREATE INDEX idx_audit_device ON audit_log(device_id, timestamp);
```

**In-memory cache:** `_current_scores: dict[str, int]` in `trust.py` — avoids a DB read on every window. Loaded from DB on first access per device; written on every scored window.

**`get_latest_scores()`** uses a self-join to return only the row with `MAX(timestamp)` per device, sorted by score ascending (lowest trust first).

---

## Compliance & Audit (`compliance/`)

**`audit.py` — Hash-chained log:**
- Every append computes: `hash = SHA256(prev_hash + canonical_json(body))`
- Genesis hash: `sha256:000...000`
- `AuditLog.verify()` replays entire chain from genesis; returns `{verified, entries, broken_at}`
- `AuditLog.get_recent(device_id=None, limit=20)` — for TUI inspect panel
- `AuditLog.get_by_event_type(event_type)` — for compliance report

**Event types and compliance mappings:**
| Event | ISO 27001 | SOC-2 |
|---|---|---|
| `score_update` | A.8.15 | CC7.2 |
| `trust_violation` | A.8.22 | CC6.6 |
| `device_isolated` | A.5.18 | CC6.2 |
| `anomaly_detected` | A.8.16 | CC7.3 |

**`report.py` — Plain-text report:**
- Called by `GET /compliance/report`
- Shows chain verification status, total entries, and last 20 events per event type

---

## API (`api/main.py`) — ✅ IMPLEMENTED

```
GET /health               → {"status": "ok", "service": "eclipse"}
GET /scores               → latest trust score per device (JSON array)
GET /compliance/report    → full audit-backed compliance report (plain text)
```

- Runs via `start_background(port=8000)` — uvicorn in daemon thread
- Host configurable via `$ECLIPSE_API_HOST` (default `0.0.0.0`)
- FastAPI and uvicorn are optional: if not installed, logs warning and skips silently
- Reads only from SQLite — no shared mutable state with the engine threads

---

## TUI Design (`TUI/dashboard.py`)

- Dark panels, block progress bars (`░░░` empty, `█` filled)
- Braille sparkline score history column per device (uses `engine.trust.get_score_history()`)
- Braille snake spinner in header bar (animates at 10Hz)
- Whole row turns `on dark_red` + blinks on HIGH RISK
- Live stats bar: TRUSTED / MONITOR / RISK counts + clock
- Bottom input panel: `attack <device> <type>` and `inspect <device>` commands (display only)
- Refreshes every 0.25s via Rich Live (4 FPS)
- Status icons: `[√]` TRUSTED, `[!]` MONITOR, `[?]` SUSPECT, `[X]` RISKY, `[∞]` CALIBRATING
- Device type icons: `[CAM]` camera, `[LIT]` bulb, `[SNR]` sensor

---

## Devices

| device_id | device_type | Normal bytes/window | Normal DNS entropy |
|---|---|---|---|
| cam-01 | camera | ~1,000,000 ± 50,000 | ~2.1 ± 0.1 |
| cam-02 | camera | ~1,000,000 ± 50,000 | ~2.1 ± 0.1 |
| bulb-01 | bulb | ~50,000 ± 5,000 | ~1.2 ± 0.1 |
| bulb-02 | bulb | ~50,000 ± 5,000 | ~1.2 ± 0.1 |
| sensor-01 | sensor | ~10,000 ± 1,000 | ~0.8 ± 0.1 |

Traffic generated by one daemon thread per device. Threads stagger their first window by a random offset (`0 … interval/5`) to avoid SQLite write contention.

---

## Attack Types (`data/simulate_attack.py`)

Each attack is a **3-window progressive sequence**. The injector calls `seed_device_baseline()` for the target device on the first window.

| Attack | Window 1 | Window 2 | Window 3 |
|---|---|---|---|
| `dns_tunnel` | EWMA fires only (δ=0.31) | Z-Score + DNS entropy + IF | Port 22 + new IP + max entropy + IF severe |
| `botnet` | New IP, many dest IPs | High Z-Score + port 8080 | Port 22/23, 80 dest IPs |
| `port_scan` | Ports 8080/8443 | Port 22/23/3389 + new IP | 10+ port range + high Z |
| `exfil` | Huge bytes (4MB) + new IP | 10MB + Z=7.8 | 20MB + Z=12.0 |

CLI usage:
```bash
python data/simulate_attack.py --device cam-02 --attack dns_tunnel
python data/simulate_attack.py --device cam-02 --attack botnet
python data/simulate_attack.py --device sensor-01 --attack exfil
python data/simulate_attack.py --device cam-02 --attack dns_tunnel --dry-run
python data/simulate_attack.py --device cam-02 --attack dns_tunnel --interval 10
```

---

## Demo Attack Sequence

```bash
# Terminal 1
ECLIPSE_FAST_MODE=1 python main.py

# Terminal 2 (devices become ACTIVE in ~50s with fast mode)
python data/simulate_attack.py --device cam-02 --attack dns_tunnel
```

Expected progression on cam-02:
```
T=0:00  cam-02 seeded at 92  TRUSTED     (green)
T=0:20  window 1 →   ~87    TRUSTED     (EWMA drift -5 only; ML does NOT fire this window)
T=0:40  window 2 →   ~54    SUSPICIOUS  (Z-Score -20, DNS entropy -15+15, ML -8)
T=1:00  window 3 →   ~11    HIGH RISK   (Port 22 -40, new IP -10, Z -20, DNS -30, EWMA -5, ML -8)
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
├── fastapi      ≥ 0.104.0 → background health/scores/compliance endpoint
├── uvicorn      ≥ 0.24.0 → ASGI server for FastAPI
├── httpx        ≥ 0.25.0 → Ollama warmup ping
├── pytest       ≥ 8.0.0  → test runner
└── scapy                 → real packet capture (production, not used in demo)
```

---

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `ECLIPSE_FAST_MODE` | unset | Set to `1` for 5s windows instead of 60s |
| `ECLIPSE_DB_PATH` | `eclipse.db` | SQLite database path |
| `ECLIPSE_API_HOST` | `0.0.0.0` | FastAPI bind host |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama API base URL |

---

## Failure Risks & Mitigations

| Risk | Mitigation |
|---|---|
| IsolationForest not flagging | Pre-train + `verify_ml.py` before demo |
| SQLite write lock | WAL mode + `timeout=10` + per-device thread stagger |
| TUI layout breaks on projector | Test at 80/120/180 col widths |
| Burn-in delay (~10 min normal, ~50s fast mode) | Use `ECLIPSE_FAST_MODE=1` |
| Attack device not appearing in TUI | `seed_device_baseline()` is called automatically on first inject |
| `api/main.py` not starting | FastAPI/uvicorn optional — TUI still works; startup logs warning |
| Ollama unavailable | Non-blocking warmup; fallback mode active automatically |
| DNS entropy double-counted | Intentional — policy check uses per-device threshold; drift uses global 3.5 |

---

## What's Deferred / Known Gaps

| Item | Status |
|---|---|
| Ollama NL query interface | ❌ Warmup only; no parser/responder wired to TUI |
| ISO 27001 / SOC-2 compliance report (full) | ⚠ Basic report exists via `/compliance/report`; not a formal audit |
| Live Scapy sniffing | ❌ `scapy-collector.py` exists but not integrated into `main.py` |
| Multi-node deployment | ❌ Deferred |
| `policy.py` using per-device ID for lookup | ⚠ Policy loaded by `device_type`, not `device_id` — auto-generated per-device JSONs exist but aren't automatically consulted unless device_type matches device_id |
| TUI input commands (attack/inspect) | ⚠ Display only — not wired to a real command interpreter |
