"""
main.py — Eclipse Entry Point
Startup sequence (from control-flow-1.md):
  1. Load IsolationForest models
  2. Initialize SQLite
  3. Initialize AuditLog
  4. Ollama warmup (non-blocking)
  5. Start synthetic data generator thread
  6. Start FastAPI in background thread
  7. Launch Rich TUI (takes over main thread)

Run: python main.py
     ECLIPSE_FAST_MODE=1 python main.py   (5s windows instead of 60s)
"""

import logging
import os
import sys
import threading
import time

# ── Logging setup (before any imports that use logging) ───────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("eclipse.main")


def step(n: int, msg: str):
    print(f"  [{n}/7] {msg}", flush=True)


def main():
    print()
    print("  ███████╗ ██████╗██╗     ██╗██████╗ ███████╗███████╗")
    print("  ██╔════╝██╔════╝██║     ██║██╔══██╗██╔════╝██╔════╝")
    print("  █████╗  ██║     ██║     ██║██████╔╝███████╗█████╗  ")
    print("  ██╔══╝  ██║     ██║     ██║██╔═══╝ ╚════██║██╔══╝  ")
    print("  ███████╗╚██████╗███████╗██║██║     ███████║███████╗")
    print("  ╚══════╝ ╚═════╝╚══════╝╚═╝╚═╝     ╚══════╝╚══════╝")
    print("  IoT Trust Scoring & Drift Analytics Engine")
    print("  Exploit X — GDG JSSATEB Eclipse Hackathon")
    print()

    # ── Step 1: Load ML models ────────────────────────────────────────────────
    step(1, "Loading IsolationForest models...")
    try:
        from engine.ml import MLEngine
        ml_engine = MLEngine()
        ml_engine.load_models()
        print("       ✅ cam / bulb / sensor models loaded")
    except FileNotFoundError as e:
        print(f"       ❌ {e}")
        print("       Run: python train_models.py")
        sys.exit(1)

    # ── Step 2: Initialize SQLite ─────────────────────────────────────────────
    step(2, "Initializing SQLite (WAL mode)...")
    try:
        from engine.trust import _init_db
        _init_db()
        db_path = os.environ.get("ECLIPSE_DB_PATH", "eclipse.db")
        print(f"       ✅ {db_path} ready")
    except Exception as e:
        print(f"       ❌ SQLite init failed: {e}")
        sys.exit(1)

    # ── Step 3: Initialize AuditLog ───────────────────────────────────────────
    step(3, "Initializing audit log (hash chain)...")
    try:
        from compliance.audit import AuditLog
        result = AuditLog.verify()
        print(f"       ✅ {result['entries']} existing entries | chain {'intact' if result['verified'] else '⚠ BROKEN'}")
    except Exception as e:
        print(f"       ⚠ Audit log warning: {e} (continuing)")

    # ── Step 4: Ollama warmup (non-blocking) ──────────────────────────────────
    step(4, "Ollama warmup (non-blocking)...")
    ollama_ready = threading.Event()

    def warmup_ollama():
        try:
            import httpx
            resp = httpx.post(
                "http://localhost:11434/api/generate",
                json={"model": "qwen2.5-coder:7b", "prompt": "ping", "stream": False},
                timeout=45,
            )
            if resp.status_code == 200:
                logger.info("[Ollama] Warmup OK")
                ollama_ready.set()
            else:
                logger.warning(f"[Ollama] Warmup returned {resp.status_code} — fallback mode")
        except Exception as e:
            logger.warning(f"[Ollama] Unreachable ({e}) — fallback mode active")

    threading.Thread(target=warmup_ollama, daemon=True, name="ollama-warmup").start()
    print("       ⏳ warming up in background (fallback active if unavailable)")

    # ── Step 5: Start synthetic data generator ────────────────────────────────
    step(5, "Starting synthetic device traffic generator...")
    try:
        from engine.features import enrich_window
        from data.synthetic import SyntheticGenerator
        generator = SyntheticGenerator(callback=enrich_window)
        generator.start()
        mode = "FAST (5s)" if os.environ.get("ECLIPSE_FAST_MODE") == "1" else "normal (60s)"
        print(f"       ✅ 5 devices started | interval: {mode}")
    except Exception as e:
        print(f"       ❌ Synthetic generator failed: {e}")
        sys.exit(1)

    # ── Step 6: Start FastAPI background thread ───────────────────────────────
    step(6, "Starting FastAPI (background, port 8000)...")
    try:
        from api.main import start_background
        start_background(port=8000)
        time.sleep(0.5)  # give uvicorn a moment to bind
        print("       ✅ http://localhost:8000 | /health /scores /compliance/report")
    except Exception as e:
        print(f"       ⚠ FastAPI failed to start ({e}) — TUI still works")

    # ── Step 7: Launch TUI ────────────────────────────────────────────────────
    step(7, "Launching TUI...")
    print()
    time.sleep(0.3)

    try:
        from TUI.dashboard import run_dashboard
        run_dashboard()
    except KeyboardInterrupt:
        pass
    except ImportError as e:
        print(f"  ❌ TUI not available: {e}")
        print("  Running in headless mode. API is live at http://localhost:8000")
        print("  Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    finally:
        print("\n  Shutting down Eclipse...")
        try:
            generator.stop()
        except Exception:
            pass
        print("  Goodbye.")


if __name__ == "__main__":
    main()
