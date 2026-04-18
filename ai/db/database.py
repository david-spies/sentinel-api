"""
ai/db/database.py

DuckDB persistence layer for Sentinel-API AI service.

Responsibilities:
  - Initialise the sentinel.db schema on startup
  - Persist ScanHistoryEntry records after each scan
  - Serve paginated history for the dashboard trend chart
  - Store per-finding remediation cache (avoids LLM re-inference for identical findings)
  - Aggregate OWASP coverage statistics for the dashboard

DuckDB runs in-process (no server daemon). All operations are synchronous;
async wrappers use anyio.to_thread.run_sync() to avoid blocking the event loop.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import duckdb
import structlog

from ..core.config import get_settings
from ..core.models import (
    Finding,
    ScanHistoryEntry,
    HistoryResponse,
)

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Schema DDL
# ---------------------------------------------------------------------------

SCHEMA_DDL = """
-- Scan history: one row per completed scan, used for trend charts
CREATE TABLE IF NOT EXISTS scan_history (
    scan_id         VARCHAR PRIMARY KEY,
    target          VARCHAR NOT NULL,
    scanned_at      TIMESTAMPTZ NOT NULL,
    duration        VARCHAR,
    sentinel_score  INTEGER NOT NULL,
    critical_count  INTEGER DEFAULT 0,
    high_count      INTEGER DEFAULT 0,
    medium_count    INTEGER DEFAULT 0,
    endpoint_count  INTEGER DEFAULT 0,
    shadow_count    INTEGER DEFAULT 0,
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- Finding cache: avoids LLM re-inference for semantically identical findings
CREATE TABLE IF NOT EXISTS remediation_cache (
    cache_key       VARCHAR PRIMARY KEY,    -- SHA256 of owasp_category + severity + path_pattern
    owasp_category  VARCHAR NOT NULL,
    severity        VARCHAR NOT NULL,
    remediation     TEXT NOT NULL,
    code_snippet    TEXT DEFAULT '',
    model_used      VARCHAR NOT NULL,
    hit_count       INTEGER DEFAULT 1,
    created_at      TIMESTAMPTZ DEFAULT now(),
    last_used_at    TIMESTAMPTZ DEFAULT now()
);

-- Findings log: detailed record of every finding for cross-scan analysis
CREATE TABLE IF NOT EXISTS findings_log (
    id              VARCHAR,
    scan_id         VARCHAR NOT NULL,
    target          VARCHAR NOT NULL,
    severity        VARCHAR NOT NULL,
    owasp_category  VARCHAR NOT NULL,
    title           VARCHAR NOT NULL,
    endpoint_path   VARCHAR,
    cvss_score      DOUBLE,
    risk_score      INTEGER,
    tags            VARCHAR[],
    discovered_at   TIMESTAMPTZ,
    PRIMARY KEY (id, scan_id)
);

-- OWASP coverage stats: aggregated by target for dashboard radar chart
CREATE VIEW IF NOT EXISTS owasp_coverage AS
SELECT
    target,
    owasp_category,
    COUNT(*)                     AS finding_count,
    AVG(risk_score)              AS avg_risk_score,
    MAX(risk_score)              AS max_risk_score,
    COUNT(CASE WHEN severity = 'CRITICAL' THEN 1 END) AS critical_count
FROM findings_log
GROUP BY target, owasp_category;
"""

# ---------------------------------------------------------------------------
# Connection pool (one connection per thread — DuckDB is not thread-safe)
# ---------------------------------------------------------------------------

_local = threading.local()
_db_path: Optional[Path] = None


def _get_conn() -> duckdb.DuckDBPyConnection:
    """Return a thread-local DuckDB connection, creating it if needed."""
    global _db_path
    if not hasattr(_local, "conn") or _local.conn is None:
        cfg = get_settings()
        path = _db_path or cfg.db_path
        path.parent.mkdir(parents=True, exist_ok=True)
        _local.conn = duckdb.connect(str(path))
        logger.debug("duckdb_connection_opened", thread=threading.current_thread().name)
    return _local.conn


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

def init_db(db_path: Optional[Path] = None) -> None:
    """
    Create the database schema if it does not exist.
    Call once at application startup.
    """
    global _db_path
    if db_path:
        _db_path = db_path
    conn = _get_conn()
    conn.execute(SCHEMA_DDL)
    logger.info("database_initialised", path=str(_db_path or get_settings().db_path))


# ---------------------------------------------------------------------------
# Scan history
# ---------------------------------------------------------------------------

def save_scan_history(entry: ScanHistoryEntry) -> None:
    """Upsert a ScanHistoryEntry into the scan_history table."""
    conn = _get_conn()
    conn.execute(
        """
        INSERT OR REPLACE INTO scan_history
            (scan_id, target, scanned_at, duration, sentinel_score,
             critical_count, high_count, medium_count, endpoint_count, shadow_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            entry.scan_id,
            entry.target,
            entry.scanned_at.isoformat(),
            entry.duration,
            entry.sentinel_score,
            entry.critical_count,
            entry.high_count,
            entry.medium_count,
            entry.endpoint_count,
            entry.shadow_count,
        ],
    )
    logger.info("scan_history_saved", scan_id=entry.scan_id, score=entry.sentinel_score)

    # Enforce row cap
    cfg = get_settings()
    conn.execute(
        """
        DELETE FROM scan_history
        WHERE scan_id NOT IN (
            SELECT scan_id FROM scan_history
            ORDER BY scanned_at DESC
            LIMIT ?
        )
        """,
        [cfg.db_history_max_rows],
    )


def get_scan_history(target: str = "", limit: int = 20, offset: int = 0) -> HistoryResponse:
    """Return paginated scan history, optionally filtered by target."""
    conn = _get_conn()
    where = "WHERE target = ?" if target else ""
    params = [target] if target else []

    total_row = conn.execute(
        f"SELECT COUNT(*) FROM scan_history {where}", params
    ).fetchone()
    total = total_row[0] if total_row else 0

    rows = conn.execute(
        f"""
        SELECT scan_id, target, scanned_at, duration, sentinel_score,
               critical_count, high_count, medium_count, endpoint_count, shadow_count
        FROM scan_history
        {where}
        ORDER BY scanned_at DESC
        LIMIT ? OFFSET ?
        """,
        params + [limit, offset],
    ).fetchall()

    entries = [
        ScanHistoryEntry(
            scan_id=r[0],
            target=r[1],
            scanned_at=datetime.fromisoformat(r[2]) if isinstance(r[2], str) else r[2],
            duration=r[3] or "",
            sentinel_rank_score=r[4],
            critical=r[5],
            high=r[6],
            medium=r[7],
            total_endpoints=r[8],
            shadow_apis=r[9],
        )
        for r in rows
    ]
    return HistoryResponse(entries=entries, total=total)


# ---------------------------------------------------------------------------
# Findings log
# ---------------------------------------------------------------------------

def log_findings(scan_id: str, target: str, findings: list[Finding]) -> None:
    """Batch-insert findings into the findings_log table."""
    if not findings:
        return
    conn = _get_conn()
    rows = [
        (
            f.id,
            scan_id,
            target,
            f.severity.value,
            f.owasp_category.value,
            f.title,
            f.endpoint.path if f.endpoint else None,
            f.cvss_score,
            f.risk_score,
            f.tags or [],
            f.discovered_at.isoformat() if f.discovered_at else None,
        )
        for f in findings
    ]
    conn.executemany(
        """
        INSERT OR IGNORE INTO findings_log
            (id, scan_id, target, severity, owasp_category, title,
             endpoint_path, cvss_score, risk_score, tags, discovered_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    logger.info("findings_logged", scan_id=scan_id, count=len(findings))


# ---------------------------------------------------------------------------
# Remediation cache
# ---------------------------------------------------------------------------

def _cache_key(finding: Finding) -> str:
    """Build a deterministic cache key from the semantically stable fields."""
    import hashlib
    path_pattern = ""
    if finding.endpoint:
        # Normalise numeric IDs so /users/1001 and /users/1002 share a cache entry
        import re
        path_pattern = re.sub(r"/\d+", "/{id}", finding.endpoint.path)
    raw = f"{finding.owasp_category}|{finding.severity}|{path_pattern}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def get_cached_remediation(finding: Finding) -> Optional[tuple[str, str]]:
    """
    Return (remediation, code_snippet) from cache, or None on cache miss.
    Updates last_used_at and increments hit_count on hit.
    """
    key = _cache_key(finding)
    conn = _get_conn()
    row = conn.execute(
        "SELECT remediation, code_snippet FROM remediation_cache WHERE cache_key = ?",
        [key],
    ).fetchone()
    if row:
        conn.execute(
            "UPDATE remediation_cache SET hit_count = hit_count + 1, last_used_at = now() WHERE cache_key = ?",
            [key],
        )
        logger.debug("remediation_cache_hit", key=key)
        return row[0], row[1]
    return None


def save_remediation_cache(
    finding: Finding,
    remediation: str,
    code_snippet: str,
    model_used: str,
) -> None:
    """Cache a remediation result for future identical findings."""
    key = _cache_key(finding)
    conn = _get_conn()
    conn.execute(
        """
        INSERT OR REPLACE INTO remediation_cache
            (cache_key, owasp_category, severity, remediation, code_snippet, model_used)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        [
            key,
            finding.owasp_category.value,
            finding.severity.value,
            remediation,
            code_snippet,
            model_used,
        ],
    )
    logger.debug("remediation_cached", key=key)


# ---------------------------------------------------------------------------
# Analytics queries for dashboard
# ---------------------------------------------------------------------------

def get_score_trend(target: str, limit: int = 30) -> list[dict]:
    """Return the last N scan scores for a target — used for the trend chart."""
    conn = _get_conn()
    rows = conn.execute(
        """
        SELECT scanned_at, sentinel_score, critical_count, high_count
        FROM scan_history
        WHERE target = ?
        ORDER BY scanned_at DESC
        LIMIT ?
        """,
        [target, limit],
    ).fetchall()
    return [
        {"scanned_at": str(r[0]), "score": r[1], "critical": r[2], "high": r[3]}
        for r in reversed(rows)
    ]


def get_owasp_stats(target: str) -> list[dict]:
    """Return OWASP category coverage stats for a target."""
    conn = _get_conn()
    rows = conn.execute(
        """
        SELECT owasp_category, finding_count, avg_risk_score, max_risk_score, critical_count
        FROM owasp_coverage
        WHERE target = ?
        ORDER BY max_risk_score DESC
        """,
        [target],
    ).fetchall()
    return [
        {
            "category": r[0],
            "count": r[1],
            "avg_risk": round(r[2], 1) if r[2] else 0,
            "max_risk": r[3],
            "critical": r[4],
        }
        for r in rows
    ]
