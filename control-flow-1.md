# Eclipse — Control Flow Document
> Exact execution paths for every scenario. Read alongside CONTEXT.md and archi.md.

---

## Startup Sequence

```
python -m eclipse.main
│
├── 1. Load IsolationForest models from pickle
│      models/cam_baseline.pkl  → MLEngine.models["camera"]
│      models/bulb_baseline.pkl → MLEngine.models["bulb"]
│      models/sensor_baseline.pkl → MLEngine.models["sensor"]
│      ASSERT: all 3 loaded without error
│
├── 2. Initialize SQLite
│      PRAGMA journal_mode=WAL
│      Create tables if not exist (scores, audit_log)
│      check_same_thread=False
│
├── 3. Initialize AuditLog
│      Load last hash from audit_log table (genesis="sha256:00000...")
│      Ready to append
│
├── 4. Load policy files
│      policies/camera.json → PolicyEngine.policies["camera"]
│      policies/bulb.json   → PolicyEngine.policies["bulb"]
│      policies/sensor.json → PolicyEngine.policies["sensor"]
│      If file missing → flag device as NO_POLICY, trigger auto-generation after burn-in
│
├── 5. Ollama warmup query
│      POST localhost:11434/api/generate
│      body: {"model": "qwen2.5-coder:7b", "prompt": "ping", "stream": false}
│      Wait for response (up to 45s — model loading into VRAM)
│      Log: "Ollama ready" OR "Ollama warmup failed — fallback mode active"
│      NEVER crash on Ollama failure
│
├── 6. Start synthetic data generator thread
│      Thread: synthetic.py feed loop (60s interval per device)
│      5 devices initialized: cam-01, cam-02, bulb-01, bulb-02, sensor-01
│      All start in CALIBRATING state (burn-in active)
│
├── 7. Start FastAPI in background thread
│      uvicorn api.main:app --port 8000 --log-level error
│      Serves /compliance/report, /scores, /health
│
└── 8. Launch Rich TUI
       dashboard.py takes over main thread
       Renders initial table (all devices: CALIBRATING)
       Starts 1s refresh loop for display
       Opens NL input at bottom
```

---

## Normal Processing Loop (every 60 seconds per device)

```
synthetic.py generates device_window dict
│
│   device_window = {
│     "device_id": "cam-01", "device_type": "camera",
│     "bytes": 1_023_541, "packets": 118,
│     "dns_entropy": 2.08, "ports_used": [443],
│     "unique_dest_ips": 2, "new_ip_flag": False,
│     "timestamp": 1234567890
│   }
│
▼
engine/features.py → enrich_window(device_window)
│
├── Is device in burn-in? (fewer than 10 windows collected)
│   YES → add to baseline buffer, return enriched window with calibrating=True
│         TUI shows "CALIBRATING" for this device, skip scoring
│
│   NO → compute derived features:
│         z_score    = (bytes - baseline_mean) / baseline_std
│         ewma       = 0.3 * bytes + 0.7 * prev_ewma
│         ewma_delta = abs(bytes - ewma) / ewma
│         spike_delta = (bytes - prev_bytes) / prev_bytes
│
│         Update rolling baseline buffer (trimmed mean, drop top/bottom 5%)
│
▼
[Three engines run in sequence — all receive enriched device_window]
│
├── engine/policy.py → check_policy(device_window)
│   │
│   ├── Load policy for device_type (camera.json)
│   ├── Check ports_used vs allowed_ports
│   │     [443] ∈ [443, 80] → no violation
│   ├── Check dns_entropy vs max_dns_entropy
│   │     2.08 < 3.5 → no violation
│   ├── Check new_ip_flag
│   │     False → no violation
│   └── Return: policy_violations = []
│
├── engine/drift.py → check_drift(device_window)
│   │
│   ├── Z-Score check: 1.2 < 3.0 → no signal
│   ├── EWMA check: 0.02 < 0.3 → no signal
│   ├── Shannon entropy check: 2.08 < 3.5 → no signal
│   └── Return: drift_signals = []
│
└── engine/ml.py → score_anomaly(device_window)
    │
    ├── Extract 8-feature vector from window
    ├── Load cam_baseline.pkl model
    ├── decision_function([features]) → 0.082
    ├── 0.082 > -0.1 → not anomalous
    └── Return: ml_result = None
│
▼
engine/trust.py → calculate_trust(device_id, current_score=90, [], [], None)
│
├── No deductions
├── Clean window → new_score = min(100, 90 + 2) = 92
├── status = "TRUSTED"
├── reasons = []
│
├── Write to SQLite scores table
│     INSERT INTO scores (device_id, score, status, reasons, timestamp)
│
├── Write to audit_log (score_update event)
│     AuditLog.append("score_update", "cam-01", "Score updated", 90, 92)
│     → hash chain updated
│
└── Return trust_result = {device_id, score:92, status:"TRUSTED", reasons:[], timestamp}
│
▼
TUI reads from SQLite (direct import, no HTTP)
│
└── Refreshes cam-01 row: 92 | TRUSTED ✅ | green bar
```

---

## Attack Detection Flow

```
simulate_attack.py --device cam-02 --attack dns_tunnel

WINDOW 1 (T=0:20)
──────────────────
device_window = {
    "bytes": 2_000_000, "dns_entropy": 3.1,
    "z_score": 2.1, "ewma_delta": 0.3,
    "ports_used": [443], "new_ip_flag": False
}

policy.py   → violations = []              (port 443 OK, entropy 3.1 < 3.5)
drift.py    → signals = [EWMA drift -5]   (ewma_delta 0.3 = threshold)
ml.py       → ml_result = None            (score 0.041, above -0.1)

trust.py:
  current_score = 92
  deductions = [{"reason": "EWMA drift", "deduction": 5}]
  new_score = 92 - 5 = 87 → TRUSTED ✅ (barely)

[20 second sleep]

WINDOW 2 (T=0:40)
──────────────────
device_window = {
    "bytes": 5_000_000, "dns_entropy": 3.9,
    "z_score": 3.8, "ewma_delta": 0.9,
    "ports_used": [443], "new_ip_flag": False
}

policy.py   → violations = [DNS entropy 3.9 > 3.5, -15]
drift.py    → signals = [Z-Score 3.8 > 3.0, -20] + [EWMA delta -5]
ml.py       → ml_result = {score: -0.18, -8}      (now below -0.1)

trust.py:
  current_score = 87
  deductions = [-15, -20, -5, -8] = -48
  new_score = 87 - 48 = 39 → SUSPICIOUS 🟠

AuditLog entries:
  trust_violation → "DNS entropy 3.9 > 3.5"      → ISO A.8.22 / CC6.6
  anomaly_detected → "ML anomaly score -0.18"     → ISO A.8.16 / CC7.3

[20 second sleep]

WINDOW 3 (T=1:00)
──────────────────
device_window = {
    "bytes": 9_000_000, "dns_entropy": 4.9,
    "z_score": 8.4, "ewma_delta": 2.8,
    "ports_used": [22, 443], "new_ip_flag": True
}

policy.py   → violations = [
                Port 22 unauthorized → -40,
                DNS entropy 4.9 > 3.5 → -15,
                New IP contacted → -10
              ]
drift.py    → signals = [
                Z-Score 8.4 > 3.0 → -20,
                EWMA delta 2.8 → -5
              ]
ml.py       → ml_result = {score: -0.431 → -8}

trust.py:
  current_score = 39
  deductions = [-40, -15, -10, -20, -5, -8] = -98
  new_score = max(0, 39 - 98) = 0 → clamped to 28 (floor set in logic)
  status = "HIGH RISK" 🔴

  reasons = [
    "Port 22 unauthorized → -40pts",
    "DNS entropy 4.9 > 3.5 (tunneling) → -15pts",
    "New destination IP → -10pts",
    "Traffic spike Z=8.4 → -20pts",
    "EWMA drift delta=2.8 → -5pts",
    "ML anomaly -0.431 < -0.1 → -8pts"
  ]

AuditLog entries:
  trust_violation → "Port 22 unauthorized"
  trust_violation → "DNS entropy 4.9"
  device_isolated → [triggered if score < 40 + port violation]

TUI:
  cam-02 row: 28 | HIGH RISK 🔴 | red bar | violations panel updates
  Alert flashes in violation feed
```

---

## Natural Language Query Flow

```
User types in TUI: "what happened to cam-02?"
│
▼
tui/dashboard.py captures input
│
├── Show loading spinner: "Asking Ollama..."
│
▼
intent/parser.py → parse("what happened to cam-02?")
│
├── Build Ollama request:
│     system: SYSTEM_PROMPT (returns JSON intent only)
│     user: "what happened to cam-02?"
│
├── POST http://localhost:11434/api/generate
│     timeout: 30s
│
├── SUCCESS PATH:
│   │   Response: '{"intent":"explain_drop","device_id":"cam-02","time_range":"1h","confidence":0.94}'
│   │
│   └── validate_parsed_query(response)
│         ASSERT intent in valid_intents
│         ASSERT device_id format valid (no injection)
│         ASSERT confidence > 0.5 → use Ollama result
│         Return ParsedQuery(intent="explain_drop", device_id="cam-02")
│
└── FAILURE PATH (timeout / Ollama down / bad JSON):
      keyword_fallback("what happened to cam-02?")
      "happened" → "device_history"
      "cam-02" matched by regex → device_id="cam-02"
      Return ParsedQuery(intent="device_history", device_id="cam-02")
│
▼
intent/responder.py → build_response(ParsedQuery)
│
├── Fetch data from SQLite (direct query — no HTTP)
│     scores WHERE device_id="cam-02" ORDER BY timestamp DESC LIMIT 10
│     audit_log WHERE device_id="cam-02" ORDER BY timestamp DESC LIMIT 20
│
├── Build LLM context (sanitized — no IPs, no raw hashes):
│     context = {
│       "device_id": "cam-02",
│       "device_type": "camera",
│       "score_history": [92, 87, 39, 28],
│       "recent_violations": [
│         "Port 22 unauthorized → -40pts",
│         "DNS entropy 4.9 > 3.5 → -15pts",
│         "ML anomaly -0.431 → -8pts"
│       ],
│       "time_span": "last 3 windows (3 minutes)"
│     }
│
├── POST http://localhost:11434/api/generate
│     system: RESPONDER_PROMPT
│     user: json.dumps(context) + "\nQuestion: what happened to cam-02?"
│     timeout: 30s
│
├── SUCCESS PATH:
│   │   Ollama returns plain English explanation
│   │   Display in TUI chat panel
│
└── FAILURE PATH (Ollama down):
      fallback_response("cam-02")
      Format last 5 audit events as plain text
      Prepend: "[Ollama unavailable — showing raw audit log]"
      Display in TUI — never hang, always return something
```

---

## Burn-In and Auto-Policy Generation Flow

```
New device first seen (e.g. cam-02 on first run)
│
▼
engine/features.py
│
├── device_id not in baseline_buffer → initialize
│     baseline_buffer["cam-02"] = []
│     window_count["cam-02"] = 0
│     status["cam-02"] = "CALIBRATING"
│
├── TUI shows cam-02 as CALIBRATING (grey row, no score)
│
├── For each of next 10 windows (10 minutes):
│     Add window features to baseline_buffer["cam-02"]
│     window_count["cam-02"] += 1
│     Skip trust scoring — no deductions during burn-in
│
├── After 10 windows:
│     Check: at least 8 of 10 are "clean" (no extreme outliers)
│     If gated: trim top/bottom 5% of each feature
│     Compute baseline_mean, baseline_std per feature
│     Status → ACTIVE
│
│     Trigger policy_generator.py:
│       allowed_ports = union of all ports seen
│       allowed_domains = union of all domains seen
│       max_dns_entropy = max_seen * 1.2
│       max_bytes = max_seen * 1.5
│       Write to policies/cam-02.json
│
└── Normal scoring loop begins for cam-02
```

---

## SQLite Concurrency Flow

```
Three concurrent writers/readers:
  Thread A: synthetic.py (writes device_windows → triggers trust.py → writes scores + audit)
  Thread B: TUI refresh loop (reads scores every 1s)
  Thread C: FastAPI (reads scores + audit on request)

SQLite WAL mode:
  - Multiple readers never block each other
  - One writer at a time (trust.py writes are fast, <5ms)
  - WAL allows readers to see committed data while write in progress
  - No explicit locking needed in application code

Connection setup (all threads):
  conn = sqlite3.connect("eclipse.db", check_same_thread=False)
  conn.execute("PRAGMA journal_mode=WAL")
  conn.execute("PRAGMA synchronous=NORMAL")  # safe + faster than FULL
```

---

## Compliance Report Generation Flow

```
GET /compliance/report   (FastAPI — background process)
│
▼
compliance/report.py → generate()
│
├── compliance/audit.py → verify()
│     Recompute all hashes, confirm chain integrity
│     Return: {"verified": True, "entries": 47, "broken_at": null}
│
├── Query audit_log by event_type:
│     trust_violation events  → ISO A.8.22 / SOC-2 CC6.6
│     score_update events     → ISO A.8.15 / SOC-2 CC7.2
│     device_isolated events  → ISO A.5.18 / SOC-2 CC6.2
│     anomaly_detected events → ISO A.8.16 / SOC-2 CC7.3
│
├── Format as structured text report
│
└── Return as plain text response
     Content-Type: text/plain
```

---

## Demo Sequence (Exact Commands)

```bash
# Terminal 1 — Main (TUI + everything)
python -m eclipse.main

# Wait for "Ollama ready" message
# Wait for all 5 devices to exit CALIBRATING (10 min in production)
# For demo: pre-load baseline, skip burn-in, set initial scores via seed script

# Terminal 2 — Attack (run during demo)
python simulate_attack.py --device cam-02 --attack dns_tunnel

# That's it. 2 terminals. TUI reacts live.
# Type NL query in Terminal 1 TUI input box after score drops.
```

**Pre-demo checklist:**
```
[ ] python verify_ml.py         → all models verified
[ ] Ollama running: ollama serve
[ ] Model loaded: ollama run qwen2.5-coder:7b (send one test query)
[ ] SQLite fresh: rm eclipse.db
[ ] Baseline seeded: python seed_baseline.py (pre-loads 10 clean windows per device)
[ ] TUI renders correctly at current terminal size
[ ] Attack script tested: dry run with --dry-run flag
```

---

## Error Handling Summary

| Scenario | Detection | Response |
|---|---|---|
| Ollama timeout | httpx timeout=30s | Keyword fallback + audit log response |
| Ollama returns bad JSON | json.ParseError | Keyword fallback |
| SQLite write lock | sqlite3.OperationalError | Retry 3x with 100ms backoff |
| Pickle model missing | FileNotFoundError at startup | Crash with clear message "run train_models.py first" |
| IsolationForest not flagging | verify_ml.py assertion fails | Retrain with train_models.py |
| TUI layout breaks | Rich exception | Graceful resize handler |
| Policy file missing | FileNotFoundError in policy.py | Flag device NO_POLICY, schedule auto-generation |
| Attack window too anomalous (score < 0) | trust.py clamp | max(0, score) — never goes negative |
