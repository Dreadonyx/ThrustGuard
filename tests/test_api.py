"""
tests/test_api.py — ThrushGuard API Tests
Run with: pytest tests/test_api.py -v

Endpoints tested:
  GET /health
  GET /scores
  GET /scores/{device_id}

Scope: core layer only. No compliance report, no Ollama, no ISO framework.

Strategy:
  - Uses FastAPI TestClient — no server needed
  - Seeds a temporary SQLite DB with realistic data
  - If api/main.py doesn't exist yet, falls back to a minimal stub
    so tests stay runnable during development

Run modes:
  pytest tests/test_api.py -v              → full suite
  pytest tests/test_api.py -v -k health   → just health
  pytest tests/test_api.py -v -k scores   → just score endpoints
  pytest tests/test_api.py -v -k contract → just data contract tests
"""

import json
import os
import sys
import time
import sqlite3
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def db_path(tmp_path_factory):
    """
    Temporary SQLite DB seeded with realistic ThrushGuard data.
    5 devices, multiple score history rows, one under attack.
    """
    db = tmp_path_factory.mktemp("data") / "thrushguard_test.db"
    conn = sqlite3.connect(str(db))
    conn.execute("PRAGMA journal_mode=WAL")

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scores (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id   TEXT NOT NULL,
            score       INTEGER NOT NULL,
            status      TEXT NOT NULL,
            reasons     TEXT NOT NULL,
            timestamp   INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    TEXT NOT NULL,
            event_type   TEXT NOT NULL,
            device_id    TEXT NOT NULL,
            details      TEXT NOT NULL,
            score_before INTEGER,
            score_after  INTEGER,
            prev_hash    TEXT NOT NULL,
            hash         TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_scores_device ON scores(device_id, timestamp);
    """)

    now = int(time.time())

    # Seed devices — cam-02 is under attack (HIGH RISK)
    devices = [
        ("cam-01",    92, "TRUSTED",    []),
        ("cam-02",    28, "HIGH RISK",  [
            "Port 22 unauthorized → -40pts",
            "DNS entropy 4.9 > 3.5 → -15pts",
            "Traffic spike Z=8.4 → -20pts",
            "ML anomaly -0.225 → -8pts",
        ]),
        ("bulb-01",   84, "TRUSTED",    []),
        ("bulb-02",   67, "MONITOR",    ["EWMA drift delta=0.31 → -5pts"]),
        ("sensor-01", 91, "TRUSTED",    []),
    ]

    for device_id, score, status, reasons in devices:
        # 3 historical rows showing progression
        for i in range(3, 0, -1):
            conn.execute(
                "INSERT INTO scores (device_id, score, status, reasons, timestamp) VALUES (?,?,?,?,?)",
                (device_id, min(100, score + i * 10), "TRUSTED", "[]", now - i * 60)
            )
        # Latest row
        conn.execute(
            "INSERT INTO scores (device_id, score, status, reasons, timestamp) VALUES (?,?,?,?,?)",
            (device_id, score, status, json.dumps(reasons), now)
        )

    conn.commit()
    conn.close()
    return str(db)


@pytest.fixture(scope="session")
def client(db_path):
    """
    TestClient against real api/main.py if it exists, stub otherwise.
    """
    os.environ["ECLIPSE_DB_PATH"] = db_path

    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "api.main",
            os.path.join(os.path.dirname(__file__), "..", "api", "main.py")
        )
        if spec is None:
            raise ImportError("api/main.py not found")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        app = module.app
        print("\n  [test] Using real api/main.py")
    except (ImportError, FileNotFoundError, AttributeError):
        app = _build_stub_app(db_path)
        print("\n  [test] api/main.py not found — using stub")

    from fastapi.testclient import TestClient
    return TestClient(app)


def _build_stub_app(db_path: str):
    """
    Minimal stub mirroring the ThrushGuard API contract.
    Replace with real api/main.py when built.
    """
    import sqlite3, json
    from fastapi import FastAPI, HTTPException

    app = FastAPI(title="ThrushGuard API (stub)")

    def db():
        conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/scores")
    def all_scores():
        conn = db()
        rows = conn.execute("""
            SELECT s.device_id, s.score, s.status, s.reasons, s.timestamp
            FROM scores s
            INNER JOIN (
                SELECT device_id, MAX(timestamp) as max_ts
                FROM scores GROUP BY device_id
            ) latest ON s.device_id = latest.device_id
                      AND s.timestamp = latest.max_ts
            ORDER BY s.score ASC
        """).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    @app.get("/scores/{device_id}")
    def device_scores(device_id: str):
        conn = db()
        rows = conn.execute(
            "SELECT * FROM scores WHERE device_id=? ORDER BY timestamp DESC LIMIT 20",
            (device_id,)
        ).fetchall()
        conn.close()
        if not rows:
            raise HTTPException(status_code=404, detail=f"Device '{device_id}' not found")
        return [dict(r) for r in rows]

    return app


# ─── /health ──────────────────────────────────────────────────────────────────

class TestHealth:
    def test_returns_200(self, client):
        assert client.get("/health").status_code == 200

    def test_body(self, client):
        assert client.get("/health").json() == {"status": "ok"}

    def test_responds_fast(self, client):
        """Health check must respond under 200ms — it's a liveness probe."""
        start = time.time()
        client.get("/health")
        assert time.time() - start < 0.2, "Health check too slow"


# ─── /scores ──────────────────────────────────────────────────────────────────

class TestAllScores:
    def test_returns_200(self, client):
        assert client.get("/scores").status_code == 200

    def test_returns_list(self, client):
        assert isinstance(client.get("/scores").json(), list)

    def test_has_all_5_devices(self, client):
        ids = {d["device_id"] for d in client.get("/scores").json()}
        assert ids == {"cam-01", "cam-02", "bulb-01", "bulb-02", "sensor-01"}

    def test_one_row_per_device(self, client):
        """Must return latest score only — not full history."""
        ids = [d["device_id"] for d in client.get("/scores").json()]
        assert len(ids) == len(set(ids)), "Duplicate device_ids in /scores"

    def test_required_fields_present(self, client):
        required = {"device_id", "score", "status", "timestamp"}
        for device in client.get("/scores").json():
            missing = required - device.keys()
            assert not missing, f"Missing {missing} in {device['device_id']}"

    def test_score_in_valid_range(self, client):
        for device in client.get("/scores").json():
            assert 0 <= device["score"] <= 100, \
                f"{device['device_id']} score {device['score']} out of range"

    def test_status_values_valid(self, client):
        valid = {"TRUSTED", "MONITOR", "SUSPICIOUS", "HIGH RISK", "CALIBRATING"}
        for device in client.get("/scores").json():
            assert device["status"] in valid, \
                f"Invalid status '{device['status']}' for {device['device_id']}"

    def test_status_matches_score_tier(self, client):
        """
        Status tier must match score band from CONTEXT.md:
          80-100 TRUSTED | 60-79 MONITOR | 40-59 SUSPICIOUS | <40 HIGH RISK
        """
        tiers = [(80, 100, "TRUSTED"), (60, 79, "MONITOR"),
                 (40, 59, "SUSPICIOUS"), (0, 39, "HIGH RISK")]
        for device in client.get("/scores").json():
            if device["status"] == "CALIBRATING":
                continue
            score = device["score"]
            expected = next(s for lo, hi, s in tiers if lo <= score <= hi)
            assert device["status"] == expected, \
                f"{device['device_id']}: score={score} → expected {expected}, got {device['status']}"

    def test_cam02_is_high_risk(self, client):
        """cam-02 was attacked — must be HIGH RISK with score < 40."""
        cam02 = next(d for d in client.get("/scores").json() if d["device_id"] == "cam-02")
        assert cam02["score"] < 40, f"cam-02 score={cam02['score']} should be < 40"
        assert cam02["status"] == "HIGH RISK"

    def test_ordered_by_score_ascending(self, client):
        """Riskiest devices first — makes TUI table more useful."""
        scores = [d["score"] for d in client.get("/scores").json()]
        assert scores == sorted(scores), "Scores should be ordered ascending (riskiest first)"

    def test_idempotent(self, client):
        """Same request twice returns same device list."""
        ids1 = sorted(d["device_id"] for d in client.get("/scores").json())
        ids2 = sorted(d["device_id"] for d in client.get("/scores").json())
        assert ids1 == ids2


# ─── /scores/{device_id} ──────────────────────────────────────────────────────

class TestDeviceScores:
    def test_known_device_200(self, client):
        assert client.get("/scores/cam-01").status_code == 200

    def test_unknown_device_404(self, client):
        assert client.get("/scores/nonexistent-99").status_code == 404

    def test_returns_list(self, client):
        data = client.get("/scores/cam-01").json()
        assert isinstance(data, list)
        assert len(data) > 0

    def test_ordered_newest_first(self, client):
        rows = client.get("/scores/cam-02").json()
        timestamps = [r["timestamp"] for r in rows]
        assert timestamps == sorted(timestamps, reverse=True), \
            "History should be newest-first"

    def test_all_rows_belong_to_device(self, client):
        for row in client.get("/scores/cam-02").json():
            assert row["device_id"] == "cam-02"

    def test_max_20_rows(self, client):
        assert len(client.get("/scores/cam-01").json()) <= 20

    def test_cam02_latest_is_high_risk(self, client):
        latest = client.get("/scores/cam-02").json()[0]
        assert latest["score"] < 40
        assert latest["status"] == "HIGH RISK"

    def test_cam02_has_reasons(self, client):
        """Attacked device must have non-empty reasons on latest score."""
        latest = client.get("/scores/cam-02").json()[0]
        reasons = latest.get("reasons", "[]")
        if isinstance(reasons, str):
            reasons = json.loads(reasons)
        assert len(reasons) > 0, "cam-02 should have violation reasons"

    @pytest.mark.parametrize("device_id", [
        "cam-01", "cam-02", "bulb-01", "bulb-02", "sensor-01"
    ])
    def test_all_devices_resolvable(self, client, device_id):
        r = client.get(f"/scores/{device_id}")
        assert r.status_code == 200
        assert all(d["device_id"] == device_id for d in r.json())


# ─── Data contract ────────────────────────────────────────────────────────────

class TestDataContract:
    """
    Enforces the shared data contract from CONTEXT.md.
    These are the exact shapes engine.py and TUI depend on.
    """

    def test_trust_result_field_types(self, client):
        for device in client.get("/scores").json():
            assert isinstance(device["device_id"], str)
            assert isinstance(device["score"], int)
            assert isinstance(device["timestamp"], int)

    def test_reasons_is_json_list(self, client):
        """reasons must always be parseable as a JSON list."""
        for row in client.get("/scores/cam-02").json():
            reasons = row.get("reasons", "[]")
            if isinstance(reasons, str):
                parsed = json.loads(reasons)
            else:
                parsed = reasons
            assert isinstance(parsed, list), \
                f"reasons must be a list, got {type(parsed)}"

    def test_timestamps_are_recent(self, client):
        """Latest scores must be within last 24h — catches stale DB."""
        now = time.time()
        for device in client.get("/scores").json():
            age = now - device["timestamp"]
            assert age < 86400, \
                f"{device['device_id']} timestamp is {age:.0f}s old"

    def test_device_ids_follow_naming(self, client):
        """All device IDs must match pattern: <type>-<nn>"""
        import re
        pattern = re.compile(r"^(cam|bulb|sensor)-\d{2}$")
        for device in client.get("/scores").json():
            assert pattern.match(device["device_id"]), \
                f"Invalid device_id format: {device['device_id']}"


# ─── Edge cases ───────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_path_traversal_rejected(self, client):
        r = client.get("/scores/../../etc/passwd")
        assert r.status_code in (404, 422)

    def test_empty_device_id_rejected(self, client):
        r = client.get("/scores/%20")
        assert r.status_code in (404, 422)

    def test_sql_injection_rejected(self, client):
        r = client.get("/scores/cam-01' OR '1'='1")
        assert r.status_code in (404, 422)

    def test_health_under_concurrent_load(self, client):
        """Health must stay fast even with concurrent requests."""
        import threading
        results = []
        def hit():
            start = time.time()
            client.get("/health")
            results.append(time.time() - start)
        threads = [threading.Thread(target=hit) for _ in range(10)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert max(results) < 1.0, f"Slowest health request: {max(results):.2f}s"
