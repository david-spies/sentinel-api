// Package engine — orchestrator.go
//
// Orchestrator is the top-level pipeline coordinator. It owns the lifecycle
// of a single scan run and sequences five stages:
//
//   Stage 0a  Fingerprint          engine.Client.Fingerprint()
//   Stage 0b  CVE Enrichment       nvd.CVEToFindings() → injected into findings
//   Stage 1   Discovery            discovery.Enumerator.Run()
//   Stage 2   Security Analysis    analyzer.Analyzer.Run()
//   Stage 3   Score + Report       analyzer.RankEngine + reporter.Reporter
package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/sentinel-api/scanner/internal/analyzer"
	"github.com/sentinel-api/scanner/internal/discovery"
	"github.com/sentinel-api/scanner/internal/models"
	"github.com/sentinel-api/scanner/internal/nvd"
	"github.com/sentinel-api/scanner/internal/reporter"
)

// ScanEvent is a progress/status update emitted to callers during a scan run.
type ScanEvent struct {
	Phase   string
	Message string
	Done    int
	Total   int
	Error   error
}

// Orchestrator wires and sequences all scan phases.
type Orchestrator struct {
	cfg     *models.ScanConfig
	log     *zap.SugaredLogger
	onEvent func(ScanEvent)
}

// NewOrchestrator constructs an Orchestrator. onEvent is optional (may be nil).
func NewOrchestrator(
	cfg *models.ScanConfig,
	log *zap.SugaredLogger,
	onEvent func(ScanEvent),
) *Orchestrator {
	if onEvent == nil {
		onEvent = func(ScanEvent) {}
	}
	return &Orchestrator{cfg: cfg, log: log, onEvent: onEvent}
}

// Run executes the full scan pipeline and returns a completed ScanResult.
func (o *Orchestrator) Run(ctx context.Context) (*models.ScanResult, error) {
	result := &models.ScanResult{
		ScanID:    uuid.New().String()[:8],
		Target:    o.cfg.Target,
		StartedAt: time.Now(),
	}

	o.log.Infow("sentinel-api scan starting",
		"scan_id", result.ScanID,
		"target", o.cfg.Target,
		"concurrency", o.cfg.Concurrency,
		"modes", o.cfg.ScanModes,
	)

	// -----------------------------------------------------------------------
	// Stage 0a — Fingerprint
	// -----------------------------------------------------------------------
	o.emit("fingerprint", "Fingerprinting tech stack...", 0, 0)
	client := NewClient(o.cfg, o.log)
	result.TechStack = client.Fingerprint(ctx, o.cfg.Target)

	o.log.Infow("fingerprint complete",
		"server", result.TechStack.Server,
		"language", result.TechStack.Language,
		"waf", result.TechStack.WAF,
		"gateway", result.TechStack.APIGateway,
		"tls", result.TechStack.TLSVersion,
		"cve_ids", result.TechStack.CVEIDs,
	)

	cveMsg := fmt.Sprintf(
		"Tech stack: %s · WAF: %s · TLS: %s · CVEs: %d",
		result.TechStack.Language,
		orNone(result.TechStack.WAF),
		result.TechStack.TLSVersion,
		len(result.TechStack.CVEs),
	)
	if exploitedCount := countExploited(result.TechStack.CVEs); exploitedCount > 0 {
		cveMsg += fmt.Sprintf(" (%d CISA KEV)", exploitedCount)
	}
	o.emit("fingerprint", cveMsg, 1, 1)

	// -----------------------------------------------------------------------
	// Stage 0b — CVE → Findings injection
	//
	// Convert NVD CVEDetail records into models.Finding structs so they
	// flow through the same scoring, ranking, and reporting pipeline as
	// OWASP checks. Only HIGH/CRITICAL CVEs and CISA KEV entries are emitted.
	// -----------------------------------------------------------------------
	if len(result.TechStack.CVEs) > 0 {
		cveFindings := nvd.CVEToFindings(result.TechStack.CVEs, result.TechStack.Server)
		if len(cveFindings) > 0 {
			result.Findings = append(result.Findings, cveFindings...)
			o.log.Infow("cve_findings_injected",
				"count", len(cveFindings),
				"server", result.TechStack.Server,
			)
			o.emit("fingerprint", fmt.Sprintf(
				"%d CVE-based infrastructure findings added to pipeline",
				len(cveFindings),
			), 1, 1)
		}
	}

	// -----------------------------------------------------------------------
	// Stage 1 — Discovery & Enumeration
	// -----------------------------------------------------------------------
	o.emit("discovery", "Phase 1: endpoint enumeration starting...", 0, 0)

	progressFn := func(done, total int) {
		o.emit("discovery", fmt.Sprintf("Probing %d / %d paths", done, total), done, total)
	}

	enum := discovery.NewEnumerator(client, o.cfg, o.log, progressFn)
	endpoints, shadows, err := enum.Run(ctx)
	if err != nil && ctx.Err() == nil {
		o.log.Warnw("discovery phase error (continuing with partial results)", "error", err)
	}
	result.Endpoints = endpoints
	result.ShadowAPIs = shadows

	o.log.Infow("discovery complete",
		"endpoints", len(endpoints),
		"shadow_zombie", len(shadows),
	)
	o.emit("discovery", fmt.Sprintf(
		"Discovered %d endpoints · %d shadow/zombie",
		len(endpoints), len(shadows),
	), len(endpoints), len(endpoints))

	// -----------------------------------------------------------------------
	// Stage 2 — OWASP Security Analysis
	// -----------------------------------------------------------------------
	o.emit("analysis", "Phase 2: OWASP Top 10 security checks...", 0, len(endpoints))
	a := analyzer.NewAnalyzer(client, o.cfg, o.log)
	owaspFindings, rateLimitProbes := a.Run(ctx, endpoints)

	// Merge OWASP findings with pre-injected CVE findings
	result.Findings = append(result.Findings, owaspFindings...)
	result.RateLimitData = rateLimitProbes

	o.log.Infow("analysis complete",
		"owasp_findings", len(owaspFindings),
		"cve_findings", len(result.Findings)-len(owaspFindings),
		"rate_limit_probes", len(rateLimitProbes),
	)
	o.emit("analysis", fmt.Sprintf(
		"%d findings total (%d OWASP, %d CVE) across %d endpoints",
		len(result.Findings),
		len(owaspFindings),
		len(result.Findings)-len(owaspFindings),
		len(endpoints),
	), len(endpoints), len(endpoints))

	// -----------------------------------------------------------------------
	// Stage 3 — SentinelRank Scoring + Report Generation
	// -----------------------------------------------------------------------
	o.emit("reporting", "Phase 3: scoring and report generation...", 0, 0)

	rep := reporter.New(o.cfg, o.log)
	if err := rep.Finalise(ctx, result); err != nil {
		o.log.Warnw("report finalisation warning", "error", err)
	}

	o.emit("complete", fmt.Sprintf(
		"Scan complete — SentinelRank: %d/100 · %d findings · reports/%s.*",
		result.SentinelScore, len(result.Findings), result.ScanID,
	), 1, 1)

	o.log.Infow("scan complete",
		"scan_id", result.ScanID,
		"score", result.SentinelScore,
		"duration", result.Duration,
		"critical", result.Summary.CriticalCount,
		"high", result.Summary.HighCount,
		"cve_total", result.Summary.CVETotal,
		"cve_exploited", result.Summary.CVEExploited,
	)

	return result, ctx.Err()
}

// emit dispatches a ScanEvent to the registered callback (non-blocking).
func (o *Orchestrator) emit(phase, message string, done, total int) {
	o.onEvent(ScanEvent{Phase: phase, Message: message, Done: done, Total: total})
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func countExploited(cves []models.CVEDetail) int {
	n := 0
	for _, c := range cves {
		if c.Exploited {
			n++
		}
	}
	return n
}
