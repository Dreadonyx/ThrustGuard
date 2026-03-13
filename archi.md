# Eclipse — Architecture Document
> Detailed module-level architecture. Read alongside CONTEXT.md and control-flow.md.

---

## System Overview

Eclipse is a single-machine, single-process system (with one optional background FastAPI process). There is no microservices architecture, no message broker, no external dependencies beyond Ollama and SQLite.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ECLIPSE PROCESS                             │
│                                                                     │
│  ┌──────────────┐    ┌─────────────────────────────────────────┐   │
│  │   data/      │    │              engine/                    │   │
│  │ synthetic.py │───▶│  features → policy → drift → ml → trust │   │
│  │    OR        │    └──────────────────┬──────────────────────┘   │
│  │ simulate_    │                       │                           │
│  │  attack.py   │                       ▼                           │
│  └──────────────┘              ┌─────────────────┐                 │
│                                │     SQLite       │                 │
│  ┌──────────────┐              │  (WAL mode)      │                 │
│  │  compliance/ │◀────────────▶│  - scores        │                 │
│  │   audit.py   │              │  - events        │                 │
│  └──────────────┘              │  - audit_log     │                 │
│                                └────────┬────────┘                 │
│  ┌──────────────┐                       │                           │
│  │   intent/    │◀──────────────────────┤                           │
│  │  parser.py   │                       │                           │
│  │ responder.py │                       │                           │
│  └──────┬───────┘                       │                           │
│         │ localhost:11434               │                           │
│         ▼                               ▼                           │
│  ┌──────────────┐              ┌─────────────────┐                 │
│  │    Ollama    │              │   tui/           │                 │
│  │  qwen2.5-   │              │  dashboard.py    │ ◀── PRIMARY UI  │
│  │  coder:7b   │              │  (Rich TUI)      │                 │
│  └──────────────┘              └─────────────────┘                 │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                    FASTAPI PROCESS (background)                     │
│              api/main.py — compliance/report only                   │
│              NOT demoed visually, runs on port 8000                 │
└─────────────────────────────────────────────────────────────────────┘
```

**Key architectural principle:** The TUI imports engine modules directly. No HTTP between TUI and engine. SQLite is the shared state store read by both TUI and FastAPI.

---

## Module Breakdown

---

### `data/synthetic.py` — Traffic Simulator

**Purpose:** Generates realistic IoT device_window dicts on a 60-second loop for demo purposes.

**Devices simulated:**
```
cam-01  camera   normal baseline (TRUSTED)
cam-02  camera   target for attack injection
bulb-01 bulb     normal baseline (TRUSTED)
bulb-02 bulb     slight drift (MONITOR)
sensor-01 sensor normal baseline (TRUSTED)
```

**Output:** Calls `engine/features.py` directly with generated device_window dict every 60 seconds per device.

**Normal distribution parameters (tight — essential for IsolationForest sensitivity):**
```python
camera_normal = {
    "bytes":           Normal(μ=1_000_000, σ=50_000),
    "packets":         Normal(μ=120, σ=5),
    "dns_entropy":     Normal(μ=2.1, σ=0.1),
    "unique_dest_ips": randint(1, 3),
    "z_score":         Normal(μ=0.8, σ=0.2),
    "ewma_delta":      Normal(μ=0.01, σ=0.005),
    "new_ip_flag":     False,
    "spike_delta":     Normal(μ=0.0, σ=0.05)
}
```

**Threading:** Runs in a background thread. Main thread is the TUI. No shared mutable state except SQLite.

---

### `data/scapy_collector.py` — Real Packet Capture (Production)

**Purpose:** Production path. Captures live packets via Scapy, extracts features into the same device_window shape as synthetic.py.

**Status:** Exists in codebase, not used in demo. Demo uses synthetic.py.

**Feature extraction from packets:**
- bytes: sum of packet lengths per 60s window
- packets: count of packets per 60s window
- unique_dest_ips: set of destination IPs per window
- dns_entropy: Shannon entropy of DNS query strings seen in window
- ports_used: set of destination ports seen in window
- new_ip_flag: True if any dest IP not in device baseline set

---

### `engine/features.py` — Feature Extraction

**Purpose:** Accepts raw device_window dict. Computes derived features (z_score, ewma_delta, spike_delta) against stored baseline. Returns enriched device_window ready for policy, drift, ML engines.

**Baseline storage:** Per-device rolling window of last N=10 observations stored in memory (dict keyed by device_id). Not SQLite — too fast-changing, doesn't need persistence.

**Computed fields:**
```python
# Z-Score of current bytes vs baseline
z_score = (current_bytes - baseline_mean) / baseline_std

# EWMA — exponential weighted moving average
ewma = alpha * current_bytes + (1 - alpha) * previous_ewma  # alpha=0.3
ewma_delta = abs(current_bytes - ewma) / ewma

# Spike delta — % change from previous window
spike_delta = (current_bytes - previous_bytes) / previous_bytes
```

**Burn-in handling:**
- First 10 windows per device: device marked CALIBRATING
- Scores suppressed during burn-in
- Baseline finalizes after 8/10 clean windows (gated learning)
- Trimmed mean: top/bottom 5% excluded from baseline calculation

---

### `engine/policy.py` — Policy Engine

**Purpose:** Loads per-device-type JSON policy. Checks current device_window against rules. Returns list of violations with point deductions.

**Policy file format:**
```json
{
    "device_type": "camera",
    "allowed_ports": [443, 80],
    "allowed_domains": ["vendor.com", "update.vendor.com"],
    "max_dns_entropy": 3.5,
    "max_bytes_per_window": 5000000
}
```

**Violation detection:**
```python
violations = []

if any(p not in policy["allowed_ports"] for p in window["ports_used"]):
    violations.append({"reason": f"Port {p} unauthorized", "deduction": 40})

if window["dns_entropy"] > policy["max_dns_entropy"]:
    violations.append({"reason": f"DNS entropy {window['dns_entropy']:.2f} > {policy['max_dns_entropy']}", "deduction": 15})

if window["new_ip_flag"]:
    violations.append({"reason": "New destination IP contacted", "deduction": 10})

if window["bytes"] > policy["max_bytes_per_window"]:
    violations.append({"reason": f"Bytes {window['bytes']} exceeds policy max", "deduction": 0})
    # bytes excess flagged but deduction handled by drift engine z-score
```

**Fires immediately** — does not wait for drift or ML engines.

---

### `engine/policy_generator.py` — Auto-Policy Generator

**Purpose:** Runs at end of burn-in period. Observes what device actually did during baseline, generates a JSON policy file with headroom. Zero manual config required.

**Generation logic:**
```python
auto_policy = {
    "device_type": detected_type,
    "allowed_ports": list(union_of_all_ports_seen),
    "allowed_domains": list(union_of_all_domains_seen),
    "max_dns_entropy": round(max_observed_entropy * 1.2, 2),     # 20% headroom
    "max_bytes_per_window": int(max_observed_bytes * 1.5)         # 50% headroom
}
# Written to policies/{device_id}.json
# Admin can edit this file to tighten/loosen rules
```

**Invoked by:** `engine/features.py` after burn-in completes.

---

### `engine/drift.py` — Statistical Drift Detection

**Purpose:** Runs Z-Score, EWMA, Shannon Entropy checks on enriched device_window. Returns drift signals with deductions.

**Z-Score:**
```python
# Flags sudden traffic bursts
if window["z_score"] > 3.0:
    signals.append({"reason": f"Traffic spike Z={window['z_score']:.2f}", "deduction": 20})
```

**EWMA:**
```python
# Flags gradual drift — low and slow attacks
if window["ewma_delta"] > 0.3:
    signals.append({"reason": f"EWMA drift delta={window['ewma_delta']:.3f}", "deduction": 5})
```

**Shannon Entropy:**
```python
# H = -sum(p_i * log2(p_i)) — applied to DNS query character distribution
if window["dns_entropy"] > 3.5:
    signals.append({"reason": f"DNS entropy {window['dns_entropy']:.2f} > 3.5 (tunneling)", "deduction": 15})
```

**Baseline freeze (anti-poisoning):**
```python
# If >3 consecutive anomalies, freeze EWMA baseline
# Prevents attacker from slowly 'training' the system
if consecutive_anomaly_count > 3:
    freeze_ewma_baseline(device_id)
```

---

### `engine/ml.py` — IsolationForest Anomaly Detection

**Purpose:** Loads pre-trained pickled IsolationForest per device class. Scores current window. Returns ML anomaly deduction.

**CRITICAL design decision:** Model is NEVER retrained during demo. Pre-trained offline on 500 normal windows per device class. Loaded once at startup.

```python
import pickle
from sklearn.ensemble import IsolationForest

class MLEngine:
    def __init__(self):
        self.models = {
            "camera": pickle.load(open("models/cam_baseline.pkl", "rb")),
            "bulb":   pickle.load(open("models/bulb_baseline.pkl", "rb")),
            "sensor": pickle.load(open("models/sensor_baseline.pkl", "rb")),
        }

    def score(self, window: dict) -> dict:
        features = self._extract_features(window)
        model = self.models[window["device_type"]]
        anomaly_score = model.decision_function([features])[0]

        if anomaly_score < -0.1:
            return {
                "reason": f"ML anomaly score {anomaly_score:.3f} < -0.1",
                "deduction": 8
            }
        return None

    def _extract_features(self, w):
        # 8-feature vector — must match training feature order exactly
        return [
            w["bytes"], w["packets"], w["unique_dest_ips"],
            w["dns_entropy"], int(any(p not in [443,80] for p in w["ports_used"])),
            w["spike_delta"], int(w["new_ip_flag"]), w["ewma_delta"]
        ]
```

**Training (run once, offline):**
```python
# train_models.py — run before hackathon demo, not during
clf = IsolationForest(contamination=0.05, random_state=42)
clf.fit(generate_normal_windows(n=500, device_type="camera"))
pickle.dump(clf, open("models/cam_baseline.pkl", "wb"))
```

---

### `engine/trust.py` — Trust Score Aggregator

**Purpose:** Receives violations (policy), signals (drift), anomaly (ML). Aggregates into final 0-100 score. Writes to SQLite. Writes to audit log.

```python
def calculate_trust(device_id, current_score, policy_violations, drift_signals, ml_result):
    deductions = []
    
    for v in policy_violations:
        deductions.append(v)
    for s in drift_signals:
        deductions.append(s)
    if ml_result:
        deductions.append(ml_result)

    total_deduction = sum(d["deduction"] for d in deductions)
    
    if not deductions:
        new_score = min(100, current_score + 2)  # clean window recovery
    else:
        new_score = max(0, current_score - total_deduction)

    status = score_to_status(new_score)

    result = {
        "device_id": device_id,
        "score": new_score,
        "status": status,
        "reasons": [d["reason"] + f" → -{d['deduction']}pts" for d in deductions],
        "timestamp": int(time.time())
    }

    db_write(result)               # SQLite scores table
    audit_log.append(result)       # compliance/audit.py hash chain

    return result

def score_to_status(score):
    if score >= 80: return "TRUSTED"
    if score >= 60: return "MONITOR"
    if score >= 40: return "SUSPICIOUS"
    return "HIGH RISK"
```

---

### `compliance/audit.py` — Hash-Chained Audit Log (ported from Lockr)

**Purpose:** Tamper-evident append-only event log. Every event is hashed against the previous entry. Any modification breaks the chain.

**Ported directly from Lockr `server/audit.py`.** Only change: event_type values swapped.

```python
import hashlib, json
from datetime import datetime, timezone

class AuditLog:
    def __init__(self, db_path="eclipse.db"):
        self.db_path = db_path
        self._init_db()

    def append(self, event_type, device_id, details, score_before, score_after):
        prev_hash = self._get_last_hash()
        
        entry_body = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,   # trust_violation | device_isolated | score_update | anomaly_detected
            "device_id": device_id,
            "details": details,
            "score_before": score_before,
            "score_after": score_after,
            "prev_hash": prev_hash,
        }
        
        entry_hash = "sha256:" + hashlib.sha256(
            (prev_hash + json.dumps(entry_body, sort_keys=True)).encode()
        ).hexdigest()
        
        entry_body["hash"] = entry_hash
        self._write(entry_body)

    def verify(self):
        # Recompute every hash, confirm chain integrity
        ...
```

**Event type → ISO/SOC-2 mapping:**
```
trust_violation     → ISO A.8.22 / SOC-2 CC6.6
device_score_update → ISO A.8.15 / SOC-2 CC7.2
device_isolated     → ISO A.5.18 / SOC-2 CC6.2
anomaly_detected    → ISO A.8.16 / SOC-2 CC7.3
```

---

### `compliance/report.py` — Compliance Report Generator

**Purpose:** Queries audit log, maps events to ISO 27001 / SOC-2 controls, generates structured text report.

**Served via:** `GET /compliance/report` (FastAPI background process)

**Output format:**
```
ECLIPSE — IoT TRUST COMPLIANCE REPORT
Generated: 2025-01-01T00:00:00Z
Chain Status: VERIFIED ✅

ISO 27001 / SOC-2 CONTROL EVIDENCE
═══════════════════════════════════

A.8.22 / CC6.6 — Network Security Controls
  12 trust_violation events logged
  Most recent: cam-02 Port 22 unauthorized [2025-01-01T00:45:00Z]

A.8.16 / CC7.3 — Monitoring Activities
  47 score_update events logged
  3 anomaly_detected events logged
  ...
```

---

### `intent/parser.py` — Natural Language Parser (ported from Lockr)

**Purpose:** Takes raw natural language question from TUI input. Sends to Ollama. Returns structured ParsedQuery object.

**Ported from Lockr `intent/parser.py`.** Swap vault-specific intent schema for device-monitoring schema.

```python
SYSTEM_PROMPT = """
You are a security analyst assistant for an IoT monitoring system.
Parse the user's question and return ONLY valid JSON in this exact format:
{
  "intent": "device_history" | "explain_drop" | "list_risky" | "audit_query" | "general",
  "device_id": "cam-02" | null,
  "time_range": "1h" | "24h" | null,
  "confidence": 0.0-1.0
}
No explanation. No markdown. JSON only.
"""

async def parse(question: str) -> ParsedQuery:
    response = await ollama_call(SYSTEM_PROMPT, question)
    # Executor always re-validates — LLM output is untrusted
    return validate_parsed_query(response)
```

**Fallback (if Ollama down/timeout):**
```python
# Keyword matching — system never hangs
KEYWORD_MAP = {
    "drop": "explain_drop",
    "why": "explain_drop",
    "happened": "device_history",
    "risk": "list_risky",
    "audit": "audit_query"
}
```

---

### `intent/responder.py` — Response Builder

**Purpose:** Takes ParsedQuery, fetches relevant data from SQLite, builds context, calls Ollama for plain English response.

**LLM security boundary (same as Lockr):**
```
LLM NEVER sees:           LLM always sees:
──────────────────        ────────────────────
Raw packet data           Device ID + type
IP addresses              Score history (numbers)
Internal network info     Violation reasons (text)
Raw audit hashes          Event timestamps
```

**Fallback response (Ollama down):**
```python
# Pull last 5 audit events for device, format as plain text
# Never return empty — always give the analyst something
def fallback_response(device_id):
    events = db_query_recent_events(device_id, limit=5)
    lines = [f"[{e['timestamp']}] {e['details']} (score: {e['score_before']}→{e['score_after']})" for e in events]
    return "Ollama unavailable. Recent events:\n" + "\n".join(lines)
```

---

### `tui/dashboard.py` — Rich TUI (PRIMARY INTERFACE)

**Purpose:** Full terminal UI. Live device table. Violation feed. NL chat input. No browser required.

**Layout:**
```
┌─────────────────────────────────────────────────────────┐
│ ECLIPSE — IoT Trust Monitor          [live • 60s update]│
├──────────┬──────────┬────────────┬───────────┬──────────┤
│ Device   │ Type     │ Score      │ Status    │ Updated  │
├──────────┼──────────┼────────────┼───────────┼──────────┤
│ cam-01   │ camera   │ ████████ 92│ TRUSTED ✅│ 12s ago  │
│ cam-02   │ camera   │ ██ 28      │ HIGH RISK🔴│ 5s ago  │
│ bulb-01  │ bulb     │ ███████ 84│ TRUSTED ✅│ 31s ago  │
│ bulb-02  │ bulb     │ █████ 67  │ MONITOR 🟡│ 18s ago  │
│ sensor-01│ sensor   │ ████████ 91│ TRUSTED ✅│ 44s ago  │
├──────────┴──────────┴────────────┴───────────┴──────────┤
│ RECENT VIOLATIONS                                        │
│ [00:45:03] cam-02 — Port 22 unauthorized → -40pts       │
│ [00:45:03] cam-02 — DNS entropy 4.9 > 3.5 → -15pts     │
│ [00:45:03] cam-02 — ML anomaly -0.43 < -0.1 → -8pts    │
├──────────────────────────────────────────────────────────┤
│ > what happened to cam-02?                               │
│                                                          │
│ [Ollama] cam-02 (Smart Camera) dropped from 92→28 due   │
│ to DNS tunneling (entropy 4.9), unauthorized SSH port,   │
│ and ML anomaly. Recommend immediate isolation.           │
└──────────────────────────────────────────────────────────┘
```

**Direct engine imports (no HTTP):**
```python
from engine.trust import get_latest_scores
from compliance.audit import get_recent_events
from intent.responder import ask
```

**Score color coding:**
```python
def score_color(score):
    if score >= 80: return "green"
    if score >= 60: return "yellow"
    if score >= 40: return "dark_orange"
    return "red"
```

**Ollama loading indicator:**
```python
with Live(Spinner("dots", text="Asking Ollama..."), refresh_per_second=10):
    response = await ask(question)
```

---

### `simulate_attack.py` — Attack Injector

**Purpose:** CLI tool that injects malicious device_window directly into the engine pipeline. Used during demo.

```bash
python simulate_attack.py --device cam-02 --attack dns_tunnel
```

**Attack profiles:**
```python
ATTACKS = {
    "dns_tunnel": [
        # window 1 — starts drifting
        {"bytes": 2_000_000, "dns_entropy": 3.1, "z_score": 2.1, "ewma_delta": 0.3, "ports_used": [443]},
        # window 2 — spike fires
        {"bytes": 5_000_000, "dns_entropy": 3.9, "z_score": 3.8, "ewma_delta": 0.9, "ports_used": [443]},
        # window 3 — full attack
        {"bytes": 9_000_000, "dns_entropy": 4.9, "z_score": 8.4, "ewma_delta": 2.8, "ports_used": [22, 443], "new_ip_flag": True},
    ],
    "botnet": [...],
    "port_scan": [...]
}

for window in ATTACKS[args.attack]:
    inject_window(args.device, window)
    time.sleep(20)   # CRITICAL: let TUI update visually between windows
```

---

### `verify_ml.py` — Pre-Demo Sanity Check

**Run before every demo:**
```bash
python verify_ml.py
```

**Expected output:**
```
Testing IsolationForest models...
cam_baseline.pkl  → normal: 0.082 ✅ | attack: -0.431 ✅
bulb_baseline.pkl → normal: 0.071 ✅ | attack: -0.388 ✅
All models verified. Safe to demo.
```

**If any assertion fails:** Retrain models with `python train_models.py` before proceeding.

---

## SQLite Schema

```sql
-- WAL mode enabled on connection
PRAGMA journal_mode=WAL;

CREATE TABLE scores (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   TEXT NOT NULL,
    score       INTEGER NOT NULL,
    status      TEXT NOT NULL,
    reasons     TEXT NOT NULL,    -- JSON array
    timestamp   INTEGER NOT NULL
);

CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    device_id   TEXT NOT NULL,
    details     TEXT NOT NULL,
    score_before INTEGER,
    score_after  INTEGER,
    prev_hash   TEXT NOT NULL,
    hash        TEXT NOT NULL
);

CREATE INDEX idx_scores_device ON scores(device_id, timestamp);
CREATE INDEX idx_audit_device  ON audit_log(device_id, timestamp);
```

**Connection settings:**
```python
conn = sqlite3.connect("eclipse.db", check_same_thread=False)
conn.execute("PRAGMA journal_mode=WAL")
```

---

## FastAPI Endpoints (background process)

```
GET  /health                → {"status": "ok"}
GET  /scores                → all devices latest score
GET  /scores/{device_id}    → score history for one device
GET  /compliance/report     → ISO 27001 / SOC-2 style text report
GET  /compliance/verify     → audit log hash chain verification result
```

Not demoed visually. Exists for judges who want to hit the API directly.
