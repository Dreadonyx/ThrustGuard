"""
api/main.py — FastAPI REST Layer
Eclipse

Serves:
  GET /health               → liveness probe
  GET /scores               → latest trust scores for all devices
  GET /compliance/report    → full audit-backed compliance report

Runs in a background daemon thread via start_background().
Does NOT use any shared mutable state — only reads from SQLite.
"""

import logging
import os
import threading
from typing import Optional

logger = logging.getLogger(__name__)

# ── Try to import FastAPI / uvicorn — optional dependency ─────────────────────
try:
    from fastapi import FastAPI
    from fastapi.responses import PlainTextResponse, JSONResponse
    import uvicorn
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False
    logger.warning("[API] fastapi/uvicorn not installed — API disabled (pip install fastapi uvicorn)")


def _build_app():
    """Build the FastAPI application object."""
    app = FastAPI(title="Eclipse IoT Trust Engine", version="1.0.0")

    @app.get("/health")
    def health():
        return {"status": "ok", "service": "eclipse"}

    @app.get("/scores")
    def scores():
        try:
            from engine.trust import get_latest_scores
            data = get_latest_scores()
            return JSONResponse(content=data)
        except Exception as e:
            logger.error(f"[API] /scores error: {e}")
            return JSONResponse(content={"error": str(e)}, status_code=500)

    @app.get("/compliance/report", response_class=PlainTextResponse)
    def compliance_report():
        try:
            from compliance.report import generate
            return PlainTextResponse(content=generate())
        except Exception as e:
            logger.error(f"[API] /compliance/report error: {e}")
            return PlainTextResponse(
                content=f"Report generation failed: {e}", status_code=500
            )

    return app


def start_background(port: int = 8000) -> Optional[threading.Thread]:
    """
    Start uvicorn in a daemon background thread.
    Returns the thread (or None if FastAPI not available).
    """
    if not _FASTAPI_AVAILABLE:
        logger.warning("[API] Skipping — fastapi/uvicorn not available")
        return None

    app = _build_app()

    host = os.environ.get("ECLIPSE_API_HOST", "0.0.0.0")

    def _run():
        try:
            uvicorn.run(
                app,
                host=host,
                port=port,
                log_level="error",
                access_log=False,
            )
        except Exception as e:
            logger.error(f"[API] uvicorn crashed: {e}")

    t = threading.Thread(target=_run, daemon=True, name="fastapi")
    t.start()
    logger.info(f"[API] FastAPI started on http://{host}:{port}")
    return t
