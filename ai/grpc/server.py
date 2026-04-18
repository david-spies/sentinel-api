"""
ai/grpc/server.py

gRPC server implementing the SentinelAI service defined in proto/sentinel.proto.

Generated stubs (sentinel_pb2 / sentinel_pb2_grpc) are produced by running:
    make proto   (or: python -m grpc_tools.protoc ...)

The server runs alongside the FastAPI HTTP server. Both share the same
LLM instance (singleton) and DuckDB connection pool.

gRPC is the preferred transport for Go→Python internal calls:
  - ~3-5× lower latency than HTTP for small payloads
  - Streaming support for real-time scan event fan-out
  - Strongly-typed message contracts via proto definitions
  - Built-in bi-directional flow control
"""

from __future__ import annotations

import asyncio
import time
from concurrent import futures
from typing import Iterator

import grpc
import structlog

# Generated protobuf stubs (created by: make proto)
try:
    from . import sentinel_pb2, sentinel_pb2_grpc
except ImportError:
    # Stubs not yet generated — provide a helpful error
    raise ImportError(
        "gRPC stubs not found. Run 'make proto' from the project root to generate them:\n"
        "  python -m grpc_tools.protoc -I proto "
        "--python_out=ai/grpc --grpc_python_out=ai/grpc proto/sentinel.proto"
    )

from ..core.config import get_settings
from ..core.llm import generate_remediation, is_model_loaded, model_name
from ..core.models import Finding, OWASPCategory, Severity
from ..core.sentinel_rank import score_finding, classify_priority
from ..db.database import (
    get_cached_remediation,
    get_scan_history,
    log_findings,
    save_remediation_cache,
    save_scan_history,
)

logger = structlog.get_logger(__name__)
_service_start = time.monotonic()


# ---------------------------------------------------------------------------
# Proto ↔ Python model conversion helpers
# ---------------------------------------------------------------------------

def _pb_finding_to_model(pb: "sentinel_pb2.Finding") -> Finding:
    """Convert a protobuf Finding message to a Python Finding model."""
    from ..core.models import Endpoint, EndpointStatus, HTTPMethod

    endpoint = None
    if pb.HasField("endpoint"):
        ep = pb.endpoint
        endpoint = Endpoint(
            path=ep.path,
            method=HTTPMethod(ep.method) if ep.method else HTTPMethod.GET,
            auth_required=ep.auth_required,
            auth_type=ep.auth_type,
            has_rate_limit=ep.has_rate_limit,
            endpoint_status=EndpointStatus(ep.status) if ep.status else EndpointStatus.DOCUMENTED,
            status_code=ep.status_code,
        )

    try:
        owasp = OWASPCategory(pb.owasp)
    except ValueError:
        owasp = OWASPCategory.NONE

    try:
        severity = Severity(pb.severity)
    except ValueError:
        severity = Severity.INFO

    return Finding(
        id=pb.id,
        severity=severity,
        owasp_category=owasp,
        title=pb.title,
        description=pb.description,
        evidence=pb.evidence,
        cvss_score=pb.cvss_score,
        risk_score=pb.risk_score,
        tags=list(pb.tags),
        endpoint=endpoint,
    )


def _remediated_finding_to_pb(
    finding_id: str,
    remediation: str,
    code_snippet: str,
    risk_score: int,
    cvss_adjusted: float,
    priority: str,
) -> "sentinel_pb2.RemediatedFinding":
    return sentinel_pb2.RemediatedFinding(
        id=finding_id,
        remediation=remediation,
        code_snippet=code_snippet,
        risk_score=risk_score,
        cvss_score=cvss_adjusted,
        priority=priority,
    )


# ---------------------------------------------------------------------------
# SentinelAI servicer
# ---------------------------------------------------------------------------

class SentinelAIServicer(sentinel_pb2_grpc.SentinelAIServicer):
    """
    Implements all four RPC methods defined in proto/sentinel.proto.
    """

    # ------------------------------------------------------------------
    # AnalyzeFindings — batch LLM remediation
    # ------------------------------------------------------------------

    def AnalyzeFindings(
        self,
        request: "sentinel_pb2.AnalyzeFindingsRequest",
        context: grpc.ServicerContext,
    ) -> "sentinel_pb2.AnalyzeFindingsResponse":
        log = logger.bind(scan_id=request.scan_id, finding_count=len(request.findings))
        log.info("grpc_analyze_findings_start")
        t0 = time.monotonic()

        findings = [_pb_finding_to_model(pb) for pb in request.findings]
        remediated = []
        enriched = 0

        for finding in findings:
            try:
                # 1. Check cache first
                cached = get_cached_remediation(finding)
                if cached:
                    remediation, code_snippet = cached
                else:
                    # 2. LLM inference
                    remediation, code_snippet = generate_remediation(finding)
                    save_remediation_cache(finding, remediation, code_snippet, model_name())

                risk = score_finding(finding)
                priority = classify_priority(finding)

                remediated.append(
                    _remediated_finding_to_pb(
                        finding_id=finding.id,
                        remediation=remediation,
                        code_snippet=code_snippet,
                        risk_score=risk,
                        cvss_adjusted=finding.cvss_score,
                        priority=priority,
                    )
                )
                enriched += 1

            except Exception as exc:
                log.warning("finding_enrichment_failed", finding_id=finding.id, error=str(exc))
                # Emit an empty remediation so the Go reporter doesn't stall
                remediated.append(
                    sentinel_pb2.RemediatedFinding(
                        id=finding.id,
                        remediation="Remediation unavailable — see logs.",
                        priority="SHORT_TERM",
                    )
                )

        # Persist findings to DuckDB log
        try:
            log_findings(request.scan_id, request.target, findings)
        except Exception as exc:
            log.warning("findings_log_failed", error=str(exc))

        elapsed = (time.monotonic() - t0) * 1000
        log.info("grpc_analyze_findings_complete", enriched=enriched, elapsed_ms=round(elapsed))

        return sentinel_pb2.AnalyzeFindingsResponse(
            findings=remediated,
            findings_enriched=enriched,
            model_used=model_name(),
            inference_ms=elapsed,
        )

    # ------------------------------------------------------------------
    # StreamScanEvents — client-streaming fan-out to dashboard
    # ------------------------------------------------------------------

    def StreamScanEvents(
        self,
        request_iterator: Iterator["sentinel_pb2.ScanEvent"],
        context: grpc.ServicerContext,
    ) -> "sentinel_pb2.StreamAck":
        """
        Receives a stream of ScanEvent messages from the Go orchestrator.
        Each event is broadcast to any connected WebSocket dashboard clients
        via the shared event bus (see ai/core/event_bus.py).
        """
        from ..core.event_bus import publish_event

        scan_id = None
        count = 0

        for event in request_iterator:
            scan_id = event.scan_id
            count += 1
            publish_event(
                scan_id=event.scan_id,
                phase=event.phase,
                message=event.message,
                done=event.done,
                total=event.total,
            )
            logger.debug(
                "scan_event_received",
                scan_id=event.scan_id,
                phase=event.phase,
                done=event.done,
                total=event.total,
            )

        logger.info("stream_scan_events_complete", scan_id=scan_id, events=count)
        return sentinel_pb2.StreamAck(scan_id=scan_id or "", events_received=count)

    # ------------------------------------------------------------------
    # ScoreFinding — single-finding rescore
    # ------------------------------------------------------------------

    def ScoreFinding(
        self,
        request: "sentinel_pb2.ScoreFindingRequest",
        context: grpc.ServicerContext,
    ) -> "sentinel_pb2.ScoreFindingResponse":
        finding = _pb_finding_to_model(request.finding)
        risk = score_finding(finding)

        severity_map = {
            range(80, 101): "CRITICAL",
            range(60, 80):  "HIGH",
            range(40, 60):  "MEDIUM",
            range(20, 40):  "LOW",
        }
        sev_label = "INFO"
        for r, label in severity_map.items():
            if risk in r:
                sev_label = label
                break

        justification = (
            f"SentinelRank score {risk}/100. "
            f"OWASP weight for {finding.owasp_category}: "
            f"{__import__('ai.core.sentinel_rank', fromlist=['OWASP_WEIGHTS']).OWASP_WEIGHTS.get(finding.owasp_category, 0.70):.2f}. "
            f"Asset criticality: {'elevated' if 'admin' in (finding.endpoint.path if finding.endpoint else '') else 'standard'}."
        )

        return sentinel_pb2.ScoreFindingResponse(
            risk_score=risk,
            severity=sev_label,
            justification=justification,
        )

    # ------------------------------------------------------------------
    # GetScanHistory — DuckDB trend data
    # ------------------------------------------------------------------

    def GetScanHistory(
        self,
        request: "sentinel_pb2.HistoryRequest",
        context: grpc.ServicerContext,
    ) -> "sentinel_pb2.HistoryResponse":
        history = get_scan_history(
            target=request.target or "",
            limit=request.limit or 20,
            offset=request.offset or 0,
        )

        pb_entries = [
            sentinel_pb2.ScanHistoryEntry(
                scan_id=e.scan_id,
                target=e.target,
                scanned_at=e.scanned_at.isoformat(),
                duration=e.duration,
                sentinel_score=e.sentinel_score,
                critical_count=e.critical_count,
                high_count=e.high_count,
                medium_count=e.medium_count,
                endpoint_count=e.endpoint_count,
                shadow_count=e.shadow_count,
            )
            for e in history.entries
        ]

        return sentinel_pb2.HistoryResponse(entries=pb_entries, total=history.total)

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def Health(
        self,
        request: "sentinel_pb2.HealthRequest",
        context: grpc.ServicerContext,
    ) -> "sentinel_pb2.HealthResponse":
        uptime = time.monotonic() - _service_start
        loaded = is_model_loaded()
        cfg = get_settings()
        return sentinel_pb2.HealthResponse(
            status="ok" if loaded else "starting",
            model_loaded=loaded,
            model_name=model_name(),
            uptime_s=round(uptime, 2),
            version=cfg.version,
        )


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

def create_grpc_server() -> grpc.Server:
    """Create and configure the gRPC server (does not start it)."""
    cfg = get_settings()
    max_msg = cfg.grpc_max_message_mb * 1024 * 1024

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=cfg.grpc_max_workers),
        options=[
            ("grpc.max_send_message_length", max_msg),
            ("grpc.max_receive_message_length", max_msg),
            ("grpc.keepalive_time_ms", cfg.grpc_keepalive_s * 1000),
            ("grpc.keepalive_timeout_ms", 5000),
            ("grpc.keepalive_permit_without_calls", True),
        ],
    )
    sentinel_pb2_grpc.add_SentinelAIServicer_to_server(SentinelAIServicer(), server)

    # Enable gRPC server reflection so tools like grpcurl work out of the box
    try:
        from grpc_reflection.v1alpha import reflection
        service_names = (
            sentinel_pb2.DESCRIPTOR.services_by_name["SentinelAI"].full_name,
            reflection.SERVICE_NAME,
        )
        reflection.enable_server_reflection(service_names, server)
    except Exception:
        pass  # reflection is optional

    return server


def start_grpc_server(server: grpc.Server) -> None:
    """Bind and start the gRPC server on the configured port."""
    cfg = get_settings()
    addr = f"[::]:{cfg.grpc_port}"
    server.add_insecure_port(addr)
    server.start()
    logger.info("grpc_server_started", address=addr)


def stop_grpc_server(server: grpc.Server, grace: float = 5.0) -> None:
    """Gracefully stop the gRPC server."""
    server.stop(grace)
    logger.info("grpc_server_stopped")
