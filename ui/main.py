"""
ui/main.py — Sentinel-API HTMX Dashboard server.

Responsibilities:
  - Serve the base HTML shell (templates/base.html)
  - Render all HTMX partial templates from /templates/partials/
  - Proxy API calls to the Python AI backend (httpx)
  - Proxy the WebSocket scan event stream to connected browsers
  - Serve static assets (CSS, JS, favicon)

All rendering is server-side (Jinja2). HTMX swaps partial HTML
fragments into the page without a JavaScript framework.
"""
from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import httpx
import structlog
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, Form
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from websockets.client import connect as ws_connect

from .config import get_settings

logger = structlog.get_logger(__name__)
BASE_DIR = Path(__file__).parent
cfg = get_settings()

# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("sentinel_ui_starting", version=cfg.version, port=cfg.port)
    yield
    logger.info("sentinel_ui_stopped")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Sentinel-API Dashboard",
    version=cfg.version,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
)

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

# Inject global template context
templates.env.globals["version"] = cfg.version


# ---------------------------------------------------------------------------
# HTTP proxy helper
# ---------------------------------------------------------------------------

def _ai_headers() -> dict:
    h = {"Accept": "application/json", "Content-Type": "application/json"}
    if cfg.ai_api_key:
        h["X-API-Key"] = cfg.ai_api_key
    return h


async def _ai_get(path: str, params: dict | None = None) -> dict:
    async with httpx.AsyncClient(timeout=cfg.ai_timeout) as client:
        r = await client.get(f"{cfg.ai_backend_url}{path}", params=params, headers=_ai_headers())
        r.raise_for_status()
        return r.json()


async def _ai_post(path: str, body: dict) -> dict:
    async with httpx.AsyncClient(timeout=cfg.ai_timeout) as client:
        r = await client.post(f"{cfg.ai_backend_url}{path}", json=body, headers=_ai_headers())
        r.raise_for_status()
        return r.json()


# ---------------------------------------------------------------------------
# Full-page routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Dashboard home — overview page."""
    try:
        health = await _ai_get("/health")
    except Exception:
        health = {"status": "offline", "model_loaded": False, "model_name": "—"}

    try:
        history = await _ai_get("/history", {"limit": 5})
        recent = history.get("entries", [])
    except Exception:
        recent = []

    return templates.TemplateResponse("pages/index.html", {
        "request": request,
        "page": "overview",
        "health": health,
        "recent_scans": recent,
    })


@app.get("/scan", response_class=HTMLResponse)
async def scan_page(request: Request):
    """New scan launch page."""
    return templates.TemplateResponse("pages/scan.html", {
        "request": request,
        "page": "scan",
    })


@app.get("/results/{scan_id}", response_class=HTMLResponse)
async def results_page(request: Request, scan_id: str):
    """Full scan results page — loads report JSON from reports/ dir."""
    return templates.TemplateResponse("pages/results.html", {
        "request": request,
        "page": "results",
        "scan_id": scan_id,
    })


@app.get("/history", response_class=HTMLResponse)
async def history_page(request: Request, target: str = ""):
    """Scan history and trend charts page."""
    try:
        history = await _ai_get("/history", {"target": target, "limit": 50})
        entries = history.get("entries", [])
        total = history.get("total", 0)
    except Exception:
        entries, total = [], 0

    trend_data: list = []
    owasp_data: list = []
    if target:
        try:
            t = await _ai_get(f"/history/{target}/trend")
            trend_data = t.get("data", [])
        except Exception:
            pass
        try:
            o = await _ai_get(f"/history/{target}/owasp")
            owasp_data = o.get("owasp", [])
        except Exception:
            pass

    return templates.TemplateResponse("pages/history.html", {
        "request": request,
        "page": "history",
        "entries": entries,
        "total": total,
        "target": target,
        "trend_data_json": json.dumps(trend_data),
        "owasp_data_json": json.dumps(owasp_data),
    })


# ---------------------------------------------------------------------------
# HTMX partial routes (hx-get / hx-post targets)
# ---------------------------------------------------------------------------

@app.get("/partials/health", response_class=HTMLResponse)
async def partial_health(request: Request):
    """Live health badge — polled every 10s by HTMX."""
    try:
        health = await _ai_get("/health")
    except Exception:
        health = {"status": "offline", "model_loaded": False, "model_name": "—", "uptime_s": 0}
    return templates.TemplateResponse("partials/health_badge.html", {
        "request": request, "health": health,
    })


@app.get("/partials/recent-scans", response_class=HTMLResponse)
async def partial_recent_scans(request: Request):
    """Recent scans table row fragment."""
    try:
        history = await _ai_get("/history", {"limit": 10})
        entries = history.get("entries", [])
    except Exception:
        entries = []
    return templates.TemplateResponse("partials/recent_scans.html", {
        "request": request, "entries": entries,
    })


@app.get("/partials/findings/{scan_id}", response_class=HTMLResponse)
async def partial_findings(request: Request, scan_id: str):
    """Findings list fragment for results page."""
    report = _load_report(scan_id)
    findings = report.get("findings", []) if report else []
    return templates.TemplateResponse("partials/findings_list.html", {
        "request": request,
        "findings": findings,
        "scan_id": scan_id,
    })


@app.get("/partials/endpoints/{scan_id}", response_class=HTMLResponse)
async def partial_endpoints(request: Request, scan_id: str, filter: str = "all"):
    """Endpoints table fragment with optional status filter."""
    report = _load_report(scan_id)
    endpoints = report.get("endpoints", []) if report else []
    if filter != "all":
        endpoints = [e for e in endpoints if e.get("endpoint_status", "").upper() == filter.upper()]
    return templates.TemplateResponse("partials/endpoints_table.html", {
        "request": request,
        "endpoints": endpoints,
        "filter": filter,
    })


@app.get("/partials/cves/{scan_id}", response_class=HTMLResponse)
async def partial_cves(request: Request, scan_id: str):
    """CVE infrastructure findings fragment."""
    report = _load_report(scan_id)
    cves = report.get("tech_stack", {}).get("cves", []) if report else []
    return templates.TemplateResponse("partials/cve_table.html", {
        "request": request,
        "cves": cves,
    })


@app.get("/partials/shadow/{scan_id}", response_class=HTMLResponse)
async def partial_shadow(request: Request, scan_id: str):
    """Shadow API list fragment."""
    report = _load_report(scan_id)
    shadows = report.get("shadow_apis", []) if report else []
    return templates.TemplateResponse("partials/shadow_list.html", {
        "request": request,
        "shadows": shadows,
    })


@app.get("/partials/owasp/{scan_id}", response_class=HTMLResponse)
async def partial_owasp(request: Request, scan_id: str):
    """OWASP Top 10 coverage grid fragment."""
    report = _load_report(scan_id)
    findings = report.get("findings", []) if report else []
    owasp_scores = _compute_owasp_scores(findings)
    return templates.TemplateResponse("partials/owasp_grid.html", {
        "request": request,
        "owasp_scores": owasp_scores,
    })


@app.get("/partials/directory/{scan_id}", response_class=HTMLResponse)
async def partial_directory(request: Request, scan_id: str):
    """Directory risk map fragment."""
    report = _load_report(scan_id)
    tree = report.get("directory_tree") if report else None
    score = report.get("sentinel_rank_score", 0) if report else 0
    return templates.TemplateResponse("partials/directory_tree.html", {
        "request": request,
        "tree": tree,
        "score": score,
    })


@app.get("/partials/ratelimit/{scan_id}", response_class=HTMLResponse)
async def partial_ratelimit(request: Request, scan_id: str):
    """Rate-limit probe results fragment."""
    report = _load_report(scan_id)
    probes = report.get("rate_limit_probes", []) if report else []
    return templates.TemplateResponse("partials/ratelimit_probes.html", {
        "request": request,
        "probes": probes,
    })


@app.get("/partials/techstack/{scan_id}", response_class=HTMLResponse)
async def partial_techstack(request: Request, scan_id: str):
    """Tech stack + fingerprint card fragment."""
    report = _load_report(scan_id)
    tech = report.get("tech_stack", {}) if report else {}
    return templates.TemplateResponse("partials/techstack_card.html", {
        "request": request,
        "tech": tech,
    })


# ---------------------------------------------------------------------------
# Scan trigger
# ---------------------------------------------------------------------------

@app.post("/partials/scan/start", response_class=HTMLResponse)
async def start_scan(
    request: Request,
    target: str = Form(...),
    token: str = Form(""),
    openapi: str = Form(""),
    nvd_lookup: str = Form(""),
    concurrency: int = Form(25),
    no_owasp: str = Form(""),
    no_pii: str = Form(""),
):
    """
    HTMX form POST — launches a scan via CLI subprocess and returns
    the scan progress panel partial immediately. The actual progress
    streams via the WebSocket.
    """
    import subprocess, uuid, shlex
    scan_id = uuid.uuid4().hex[:8]

    cmd = ["./sentinel-api", "scan",
           "--target", target,
           "--output", "./reports",
           f"--concurrency={concurrency}",
           "--no-color"]

    if token:
        cmd += ["--token", token]
    if openapi:
        cmd += ["--openapi", openapi]
    if nvd_lookup:
        cmd += ["--nvd-lookup"]
    if no_owasp:
        cmd += ["--no-owasp"]
    if no_pii:
        cmd += ["--no-pii"]
    if cfg.ai_backend_url:
        cmd += ["--ai-backend", cfg.ai_backend_url]

    try:
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        status = "started"
        error = ""
    except FileNotFoundError:
        status = "error"
        error = "sentinel-api binary not found. Run: go build -o sentinel-api ./cmd/main.go"

    return templates.TemplateResponse("partials/scan_progress.html", {
        "request": request,
        "scan_id": scan_id,
        "target": target,
        "status": status,
        "error": error,
    })


# ---------------------------------------------------------------------------
# WebSocket proxy — browser ↔ AI backend scan event stream
# ---------------------------------------------------------------------------

@app.websocket("/ws/scan/{scan_id}")
async def ws_proxy(websocket: WebSocket, scan_id: str):
    """
    Proxies the AI backend WebSocket (/ws/scan/{scan_id}) to the browser.
    The browser connects here; this server connects to the AI backend and
    relays events in both directions.
    """
    await websocket.accept()
    ai_ws_url = cfg.ai_backend_url.replace("http://", "ws://").replace("https://", "wss://")
    ai_ws_url += f"/ws/scan/{scan_id}"

    try:
        async with ws_connect(ai_ws_url) as ai_ws:
            async def ai_to_browser():
                async for msg in ai_ws:
                    await websocket.send_text(msg if isinstance(msg, str) else msg.decode())

            async def browser_to_ai():
                async for msg in websocket.iter_text():
                    await ai_ws.send(msg)

            await asyncio.gather(ai_to_browser(), browser_to_ai())
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.warning("ws_proxy_error", scan_id=scan_id, error=str(exc))
        try:
            await websocket.send_json({"type": "error", "message": str(exc)})
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Report loader helper
# ---------------------------------------------------------------------------

def _load_report(scan_id: str) -> dict | None:
    """Load a scan report JSON file from ./reports/."""
    path = Path("./reports") / f"sentinel_{scan_id}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def _compute_owasp_scores(findings: list) -> list[dict]:
    """
    Aggregate findings by OWASP category and compute per-category scores
    for the OWASP Top 10 coverage grid.
    """
    CATEGORIES = [
        ("API1:2023 - Broken Object Level Authorization", "BOLA", "checkBOLA()"),
        ("API2:2023 - Broken Authentication", "Broken Auth", "checkBrokenAuth()"),
        ("API3:2023 - Broken Object Property Level Authorization", "Mass Assignment", "checkMassAssignment()"),
        ("API4:2023 - Unrestricted Resource Consumption", "Rate Limiting", "probeRateLimit()"),
        ("API5:2023 - Broken Function Level Authorization", "BFLA", "checkBFLA()"),
        ("API6:2023 - Unrestricted Access to Sensitive Business Flows", "Sensitive Flows", "heuristic"),
        ("API7:2023 - Server Side Request Forgery", "SSRF", "checkSSRF()"),
        ("API8:2023 - Security Misconfiguration", "Misconfiguration", "checkMisconfiguration()"),
        ("API9:2023 - Improper Inventory Management", "Inventory", "detectShadows()"),
        ("API10:2023 - Unsafe Consumption of APIs", "Unsafe Consumption", "heuristic"),
    ]
    WEIGHTS = {
        "API1:2023 - Broken Object Level Authorization": 1.10,
        "API2:2023 - Broken Authentication": 1.15,
        "API3:2023 - Broken Object Property Level Authorization": 0.95,
        "API4:2023 - Unrestricted Resource Consumption": 0.85,
        "API5:2023 - Broken Function Level Authorization": 1.05,
        "API6:2023 - Unrestricted Access to Sensitive Business Flows": 0.90,
        "API7:2023 - Server Side Request Forgery": 1.10,
        "API8:2023 - Security Misconfiguration": 0.80,
        "API9:2023 - Improper Inventory Management": 0.95,
        "API10:2023 - Unsafe Consumption of APIs": 0.75,
    }

    # Build a lookup: owasp_category → max risk_score
    cat_scores: dict[str, int] = {}
    for f in findings:
        cat = f.get("owasp_category", "")
        score = f.get("risk_score", 0)
        if cat not in cat_scores or score > cat_scores[cat]:
            cat_scores[cat] = score

    results = []
    for full_name, short_name, check_fn in CATEGORIES:
        score = cat_scores.get(full_name, 0)
        weight = WEIGHTS.get(full_name, 1.0)
        # Health score for this category (100 = no findings, 0 = worst)
        health = max(0, 100 - int(score * weight))
        status = "pass" if score == 0 else ("fail" if score >= 70 else "warn")
        results.append({
            "full_name": full_name,
            "short_name": short_name,
            "check_fn": check_fn,
            "score": score,
            "health": health,
            "weight": weight,
            "status": status,
        })
    return results


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("ui.main:app", host=cfg.host, port=cfg.port,
                reload=cfg.debug, log_level="debug" if cfg.debug else "info")
