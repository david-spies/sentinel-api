// Package engine — orchestrator_grpc.go
//
// GRPCOrchestrator extends the base Orchestrator by wiring a gRPC AI client
// for both real-time event streaming and batch finding enrichment.
//
// Drop-in replacement for Orchestrator when cfg.AIBackendURL is a gRPC address
// (identified by the "grpc://" scheme prefix).
//
// Streaming behaviour vs. HTTP:
//   HTTP mode  — findings are POSTed to /analyze-findings after scan completes
//   gRPC mode  — scan events are streamed to the AI service in real time AND
//                findings are sent via AnalyzeFindings RPC (lower latency,
//                dashboard sees live progress without polling)
package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sentinel-api/scanner/internal/analyzer"
	"github.com/sentinel-api/scanner/internal/discovery"
	grpcclient "github.com/sentinel-api/scanner/internal/grpc"
	"github.com/sentinel-api/scanner/internal/models"
	"github.com/sentinel-api/scanner/internal/reporter"
	"go.uber.org/zap"
)

// GRPCOrchestrator orchestrates the full scan pipeline using gRPC for AI integration.
type GRPCOrchestrator struct {
	cfg      *models.ScanConfig
	log      *zap.SugaredLogger
	onEvent  func(ScanEvent)
	aiClient *grpcclient.AIClient
}

// NewGRPCOrchestrator constructs a GRPCOrchestrator and dials the AI service.
// grpcTarget is the gRPC server address, e.g. "ai:50051".
func NewGRPCOrchestrator(
	cfg *models.ScanConfig,
	log *zap.SugaredLogger,
	onEvent func(ScanEvent),
	grpcTarget string,
) (*GRPCOrchestrator, error) {
	if onEvent == nil {
		onEvent = func(ScanEvent) {}
	}

	aiClient, err := grpcclient.NewAIClient(grpcTarget, log.Sugar())
	if err != nil {
		return nil, fmt.Errorf("connect AI gRPC service: %w", err)
	}

	return &GRPCOrchestrator{
		cfg:      cfg,
		log:      log,
		onEvent:  onEvent,
		aiClient: aiClient,
	}, nil
}

// Close releases the gRPC connection. Call defer orch.Close() after construction.
func (o *GRPCOrchestrator) Close() error {
	return o.aiClient.Close()
}

// Run executes the full scan pipeline with gRPC event streaming.
func (o *GRPCOrchestrator) Run(ctx context.Context) (*models.ScanResult, error) {
	result := &models.ScanResult{
		ScanID:    uuid.New().String()[:8],
		Target:    o.cfg.Target,
		StartedAt: time.Now(),
	}

	o.log.Infow("grpc_scan_starting",
		"scan_id", result.ScanID,
		"target", o.cfg.Target,
	)

	// Open gRPC event stream so the Python AI service can relay events to
	// WebSocket dashboard clients in real time.
	streamer, err := o.aiClient.OpenEventStream(ctx, result.ScanID)
	if err != nil {
		o.log.Warnw("grpc_event_stream_unavailable", "error", err)
		streamer = nil // graceful degradation — scan continues without streaming
	}

	emitWithStream := func(phase, message string, done, total int) {
		o.onEvent(ScanEvent{Phase: phase, Message: message, Done: done, Total: total})
		if streamer != nil {
			if err := streamer.Send(phase, message, done, total); err != nil {
				o.log.Warnw("grpc_stream_send_error", "phase", phase, "error", err)
				streamer = nil // stop trying after first error
			}
		}
	}

	// -----------------------------------------------------------------------
	// Stage 0 — Fingerprint
	// -----------------------------------------------------------------------
	emitWithStream("fingerprint", "Fingerprinting tech stack...", 0, 0)
	client := NewClient(o.cfg, o.log)
	result.TechStack = client.Fingerprint(ctx, o.cfg.Target)
	emitWithStream("fingerprint", fmt.Sprintf(
		"Tech stack: %s · WAF: %s · TLS: %s",
		result.TechStack.Language,
		orNone(result.TechStack.WAF),
		result.TechStack.TLSVersion,
	), 1, 1)

	// -----------------------------------------------------------------------
	// Stage 1 — Discovery
	// -----------------------------------------------------------------------
	emitWithStream("discovery", "Phase 1: endpoint enumeration...", 0, 0)
	progressFn := func(done, total int) {
		emitWithStream("discovery", fmt.Sprintf("Probing %d / %d paths", done, total), done, total)
	}

	enum := discovery.NewEnumerator(client, o.cfg, o.log, progressFn)
	endpoints, shadows, err := enum.Run(ctx)
	if err != nil && ctx.Err() == nil {
		o.log.Warnw("discovery_partial", "error", err)
	}
	result.Endpoints = endpoints
	result.ShadowAPIs = shadows
	emitWithStream("discovery", fmt.Sprintf(
		"Discovered %d endpoints · %d shadow/zombie",
		len(endpoints), len(shadows),
	), len(endpoints), len(endpoints))

	// -----------------------------------------------------------------------
	// Stage 2 — OWASP Analysis
	// -----------------------------------------------------------------------
	emitWithStream("analysis", "Phase 2: OWASP checks...", 0, len(endpoints))
	a := analyzer.NewAnalyzer(client, o.cfg, o.log)
	findings, rateLimitProbes := a.Run(ctx, endpoints)
	result.Findings = findings
	result.RateLimitData = rateLimitProbes
	emitWithStream("analysis", fmt.Sprintf(
		"%d findings across %d endpoints", len(findings), len(endpoints),
	), len(endpoints), len(endpoints))

	// -----------------------------------------------------------------------
	// Stage 3a — SentinelRank + local report
	// -----------------------------------------------------------------------
	emitWithStream("reporting", "Phase 3: scoring and local report...", 0, 0)
	rep := reporter.New(o.cfg, o.log)

	// Temporarily clear the HTTP AI backend URL — we use gRPC instead.
	cfgCopy := *o.cfg
	cfgCopy.AIBackendURL = ""
	repNoHTTP := reporter.New(&cfgCopy, o.log)
	if err := repNoHTTP.Finalise(ctx, result); err != nil {
		o.log.Warnw("local_report_warning", "error", err)
	}
	_ = rep // keep import alive; use repNoHTTP above

	// -----------------------------------------------------------------------
	// Stage 3b — gRPC AI enrichment
	// -----------------------------------------------------------------------
	emitWithStream("reporting", fmt.Sprintf(
		"Sending %d findings to AI service for remediation...", len(findings),
	), 0, len(findings))

	enriched, err := o.aiClient.AnalyzeFindings(ctx, result.ScanID, result.Target, result.Findings)
	if err != nil {
		o.log.Warnw("grpc_enrich_warning", "error", err)
	} else {
		o.log.Infow("grpc_enrichment_done", "enriched", len(enriched))
	}

	// Close the event stream — sends final ACK to AI service.
	if streamer != nil {
		if _, err := streamer.Close(); err != nil {
			o.log.Warnw("grpc_stream_close_error", "error", err)
		}
	}

	// Re-write reports now that remediations are back-filled.
	if err := rep.Finalise(ctx, result); err != nil {
		o.log.Warnw("final_report_warning", "error", err)
	}

	emitWithStream("complete", fmt.Sprintf(
		"Scan complete — SentinelRank: %d/100 · %d findings",
		result.SentinelScore, len(result.Findings),
	), 1, 1)

	o.log.Infow("grpc_scan_complete",
		"scan_id", result.ScanID,
		"score", result.SentinelScore,
		"duration", result.Duration,
	)

	return result, ctx.Err()
}

// GRPCTarget extracts the gRPC address from cfg.AIBackendURL.
// Handles "grpc://ai:50051" → "ai:50051".
func GRPCTarget(aiBackendURL string) string {
	s := strings.TrimPrefix(aiBackendURL, "grpc://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimSuffix(s, "/")
	// If no port is specified, default to 50051.
	if !strings.Contains(s, ":") {
		s += ":50051"
	}
	return s
}
