"""
ai/main.py

Sentinel-API AI service — FastAPI application.

HTTP endpoints (consumed by Go reporter and dashboard):
  POST /analyze-findings        Batch LLM remediation (mirrors gRPC AnalyzeFindings)
  GET  /health                  Liveness + model status
  GET  /history                 Paginated scan history from DuckDB
  GET  /history/{target}/trend  Score-over-time data for dashboard chart
  GET  /history/{target}/owasp  OWASP category coverage stats
  WS   /ws/scan/{scan_id}       Real-time scan event stream (dashboard)

The gRPC server runs alongside FastAPI in a background thread.
Both share the same LLM singleton and DuckDB connection pool.
"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from typing import Optional

import structlog
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .core.config import get_settings
from .core.event_bus import get_event_bus, ScanEvent
from .core.llm import generate_remediation, is_model_loaded, model_name
from .core.models import (
    AIRequest,
    AIFindingResponse,
    AIResponse,
    HealthResponse,
    HistoryResponse,
)
from .core.sentinel_rank import classify_priority, score_finding
from .db.database import (
    get_cached_remediation,
    get_owasp_stats,
    get_scan_history,
    get_score_trend,
    init_db,
    log_findings,
    save_remediation_cache,
    save_scan_history,
)

logger = structlog.get_logger(__name__)
_service_start = time.monotonic()

# ---------------------------------------------------------------------------
# Lifespan — startup / shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup:
      1. Initialise DuckDB schema
      2. Register asyncio loop with the event bus (for gRPC→WS fan-out)
      3. Start gRPC server in a background thread
      4. Begin lazy LLM loading in a background thread

    Shutdown:
      5. Stop gRPC server gracefully
    """
    cfg = get_settings()
    log = logger.bind(service=cfg.service_name, version=cfg.version)

    # 1. Database
    log.info("initialising_database")
    init_db()

    # 2. Event bus loop registration
    loop = asyncio.get_running_loop()
    get_event_bus().set_event_loop(loop)

    # 3. gRPC server
    grpc_server = None
    try:
        from .grpc.server import create_grpc_server, start_grpc_server, stop_grpc_server
        grpc_server = create_grpc_server()
        start_grpc_server(grpc_server)
    except ImportError as exc:
        log.warning("grpc_unavailable", reason=str(exc))

    # 4. LLM preload (non-blocking)
    async def _preload_llm():
        try:
            await asyncio.to_thread(_load_llm_blocking)
        except Exception as exc:
            log.warning("llm_preload_failed", error=str(exc))

    asyncio.create_task(_preload_llm())
    log.info("service_started", http_port=cfg.http_port, grpc_port=cfg.grpc_port)

    yield  # ← application runs here

    # 5. Shutdown
    if grpc_server:
        stop_grpc_server(grpc_server)
    log.info("service_stopped")


def _load_llm_blocking():
    """Blocking LLM load — runs in thread to avoid blocking the event loop."""
    try:
        from .core.llm import get_llm
        get_llm()
    except Exception as exc:
        logger.warning("llm_load_skipped", reason=str(exc))


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    cfg = get_settings()

    app = FastAPI(
        title="Sentinel-API AI Service",
        description=(
            "SentinelRank intelligence layer — LLM-powered remediation guidance, "
            "DuckDB scan history, and real-time WebSocket scan event streaming."
        ),
        version=cfg.version,
        lifespan=lifespan,
        docs_url="/docs" if cfg.environment != "production" else None,
        redoc_url=None,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    return app


app = create_app()
cfg = get_settings()

# ---------------------------------------------------------------------------
# Auth dependency (optional API key)
# ---------------------------------------------------------------------------

async def verify_api_key(x_api_key: str = Header(default="")):
    if cfg.api_key and x_api_key != cfg.api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health():
    """
    Liveness check. Returns model load status.
    The Go reporter polls this before submitting findings.
    """
    loaded = is_model_loaded()
    return HealthResponse(
        status="ok" if loaded else "starting",
        model_loaded=loaded,
        model_name=model_name(),
        uptime_s=round(time.monotonic() - _service_start, 2),
        version=cfg.version,
    )


@app.post(
    "/analyze-findings",
    response_model=AIResponse,
    tags=["Analysis"],
    dependencies=[Depends(verify_api_key)],
)
async def analyze_findings(request: AIRequest):
    """
    Batch LLM remediation endpoint.

    Called by the Go reporter (reporter/reporter.go → pushToAIBackend()).
    Also reachable via the gRPC AnalyzeFindings RPC for lower-latency calls.

    For each finding:
      1. Check remediation_cache (DuckDB) — return immediately on hit
      2. Run LLM inference with OWASP-specific prompt
      3. Cache result and return

    Returns AIResponse with per-finding remediation, code snippets, and
    SentinelRank rescores.
    """
    log = logger.bind(scan_id=request.scan_id, finding_count=len(request.findings))
    log.info("analyze_findings_start")
    t0 = time.monotonic()

    enriched_findings: list[AIFindingResponse] = []
    enriched_count = 0

    for finding in request.findings:
        try:
            # Cache check
            cached = await asyncio.to_thread(get_cached_remediation, finding)
            if cached:
                remediation, code_snippet = cached
            else:
                # LLM inference (blocking → thread)
                remediation, code_snippet = await asyncio.to_thread(
                    generate_remediation, finding
                )
                await asyncio.to_thread(
                    save_remediation_cache, finding, remediation, code_snippet, model_name()
                )

            risk = score_finding(finding)
            priority = classify_priority(finding)

            enriched_findings.append(
                AIFindingResponse(
                    id=finding.id,
                    remediation=remediation,
                    code_snippet=code_snippet,
                    priority=priority,
                    cvss_adjusted=finding.cvss_score,
                    risk_score=risk,
                )
            )
            enriched_count += 1

        except Exception as exc:
            log.warning("finding_enrichment_error", finding_id=finding.id, error=str(exc))
            enriched_findings.append(
                AIFindingResponse(
                    id=finding.id,
                    remediation="Remediation temporarily unavailable.",
                    priority="SHORT_TERM",
                )
            )

    # Persist findings to DuckDB log
    await asyncio.to_thread(log_findings, request.scan_id, request.target, request.findings)

    elapsed = (time.monotonic() - t0) * 1000
    log.info("analyze_findings_complete", enriched=enriched_count, elapsed_ms=round(elapsed))

    return AIResponse(
        findings=enriched_findings,
        findings_enriched=enriched_count,
        model_used=model_name(),
        inference_ms=round(elapsed, 2),
    )


@app.get("/history", response_model=HistoryResponse, tags=["History"])
async def list_history(
    target: str = "",
    limit: int = 20,
    offset: int = 0,
    _=Depends(verify_api_key),
):
    """Return paginated scan history, optionally filtered by target."""
    return await asyncio.to_thread(get_scan_history, target, limit, offset)


@app.get("/history/{target}/trend", tags=["History"])
async def score_trend(target: str, limit: int = 30, _=Depends(verify_api_key)):
    """Return the last N SentinelRank scores for a target — used for the trend chart."""
    data = await asyncio.to_thread(get_score_trend, target, limit)
    return {"target": target, "data": data}


@app.get("/history/{target}/owasp", tags=["History"])
async def owasp_coverage(target: str, _=Depends(verify_api_key)):
    """Return OWASP category coverage statistics for the target."""
    data = await asyncio.to_thread(get_owasp_stats, target)
    return {"target": target, "owasp": data}


# ---------------------------------------------------------------------------
# WebSocket — real-time scan event stream
# ---------------------------------------------------------------------------

@app.websocket("/ws/scan/{scan_id}")
async def scan_event_stream(websocket: WebSocket, scan_id: str):
    """
    WebSocket endpoint that streams live ScanEvent messages for a scan run.

    The dashboard connects here immediately when a scan is started.
    Events are published by the gRPC StreamScanEvents handler via the event bus.

    Protocol:
      Client → Server: { "type": "ping" }   (keepalive)
      Server → Client: ScanEvent JSON dict
      Server → Client: { "type": "done" }   (stream end sentinel)
    """
    await websocket.accept()
    bus = get_event_bus()
    q = bus.subscribe(scan_id)
    log = logger.bind(scan_id=scan_id, remote=websocket.client)
    log.info("ws_client_connected")

    try:
        while True:
            try:
                event: ScanEvent | None = await asyncio.wait_for(q.get(), timeout=30.0)
            except asyncio.TimeoutError:
                # Send ping to keep connection alive
                await websocket.send_json({"type": "ping"})
                continue

            if event is None:
                # Stream ended
                await websocket.send_json({"type": "done", "scan_id": scan_id})
                break

            await websocket.send_json(event.to_dict())

    except WebSocketDisconnect:
        log.info("ws_client_disconnected")
    except Exception as exc:
        log.warning("ws_error", error=str(exc))
    finally:
        bus.unsubscribe(scan_id, q)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "ai.main:app",
        host=cfg.host,
        port=cfg.http_port,
        workers=cfg.workers,
        log_level=cfg.log_level.lower(),
        access_log=cfg.environment != "production",
    )
