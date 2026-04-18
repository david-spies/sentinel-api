// Package reporter handles all Phase 4 output: JSON and Markdown report files,
// optional AI backend enrichment (LLM remediation), and DuckDB history persistence.
package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/sentinel-api/scanner/internal/analyzer"
	"github.com/sentinel-api/scanner/internal/models"
	"go.uber.org/zap"
)

// Reporter writes all scan output and coordinates with the AI backend.
type Reporter struct {
	cfg  *models.ScanConfig
	log  *zap.SugaredLogger
	rank *analyzer.RankEngine
}

// New constructs a Reporter.
func New(cfg *models.ScanConfig, log *zap.SugaredLogger) *Reporter {
	return &Reporter{cfg: cfg, log: log, rank: analyzer.NewRankEngine()}
}

// Finalise scores all findings, assembles the ScanSummary and SentinelScore,
// writes output files, and optionally pushes to the AI backend.
func (r *Reporter) Finalise(ctx context.Context, result *models.ScanResult) error {
	// 1. Score each finding.
	for _, f := range result.Findings {
		f.RiskScore = r.rank.ScoreFinding(f)
	}

	// 2. Score each endpoint.
	for _, ep := range result.Endpoints {
		r.rank.ScoreEndpoint(ep, result.Findings)
	}

	// 3. Build summary and overall score.
	result.Summary = analyzer.BuildSummary(result)
	result.SentinelScore = r.rank.ScoreScan(result)

	// 4. Attach the directory tree to the result.
	tree := r.rank.BuildDirectoryTree(result)
	result.DirectoryTree = tree

	// 5. Finalise timing.
	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt).Round(time.Second).String()

	// 6. Write files.
	if err := os.MkdirAll(r.cfg.OutputPath, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	if err := r.writeJSON(result); err != nil {
		r.log.Warnw("JSON report write failed", "error", err)
	}
	if err := r.writeMarkdown(result, tree); err != nil {
		r.log.Warnw("Markdown report write failed", "error", err)
	}

	// 7. Push to AI backend for LLM remediation enrichment.
	if r.cfg.AIBackendURL != "" {
		if err := r.pushToAIBackend(ctx, result); err != nil {
			r.log.Warnw("AI backend unavailable — reports generated without LLM remediation",
				"url", r.cfg.AIBackendURL,
				"error", err,
			)
		}
	}

	r.log.Infow("reports finalised",
		"scan_id", result.ScanID,
		"score", result.SentinelScore,
		"output", r.cfg.OutputPath,
	)
	return nil
}

// ---------------------------------------------------------------------------
// File writers
// ---------------------------------------------------------------------------

func (r *Reporter) writeJSON(result *models.ScanResult) error {
	path := filepath.Join(r.cfg.OutputPath, fmt.Sprintf("sentinel_%s.json", result.ScanID))
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func (r *Reporter) writeMarkdown(result *models.ScanResult, tree *analyzer.DirectoryNode) error {
	path := filepath.Join(r.cfg.OutputPath, fmt.Sprintf("sentinel_%s.md", result.ScanID))
	report := analyzer.FormatMarkdownReport(result, tree)
	return os.WriteFile(path, []byte(report), 0o644)
}

// ---------------------------------------------------------------------------
// AI backend integration
// ---------------------------------------------------------------------------

// AIRequest is the payload sent to the Python FastAPI AI service.
type AIRequest struct {
	ScanID   string            `json:"scan_id"`
	Target   string            `json:"target"`
	Findings []*models.Finding `json:"findings"`
}

// AIFindingResponse is the per-finding enrichment returned by the AI service.
type AIFindingResponse struct {
	ID          string `json:"id"`
	Remediation string `json:"remediation"`
	Priority    string `json:"priority"`
	CodeSnippet string `json:"code_snippet,omitempty"`
}

// AIResponse is the full response payload from the AI service.
type AIResponse struct {
	Findings []AIFindingResponse `json:"findings"`
}

// pushToAIBackend POSTs all findings to the Python AI service and
// back-fills Finding.Remediation with the LLM-generated guidance.
func (r *Reporter) pushToAIBackend(ctx context.Context, result *models.ScanResult) error {
	payload, err := json.Marshal(AIRequest{
		ScanID:   result.ScanID,
		Target:   result.Target,
		Findings: result.Findings,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		r.cfg.AIBackendURL+"/analyze-findings",
		bytes.NewReader(payload),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 90 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("AI backend returned HTTP %d", resp.StatusCode)
	}

	var aiResp AIResponse
	if err := json.NewDecoder(resp.Body).Decode(&aiResp); err != nil {
		return fmt.Errorf("decode AI response: %w", err)
	}

	// Back-fill remediation onto matching findings.
	byID := make(map[string]AIFindingResponse, len(aiResp.Findings))
	for _, af := range aiResp.Findings {
		byID[af.ID] = af
	}

	enriched := 0
	for _, f := range result.Findings {
		if af, ok := byID[f.ID]; ok {
			text := af.Remediation
			if af.CodeSnippet != "" {
				text += "\n\n```\n" + af.CodeSnippet + "\n```"
			}
			f.Remediation = text
			enriched++
		}
	}

	r.log.Infow("AI remediation applied", "findings_enriched", enriched)
	return nil
}

// ---------------------------------------------------------------------------
// History persistence helper
// ---------------------------------------------------------------------------

// BuildHistoryEntry creates a lightweight ScanHistoryEntry from a result
// for DuckDB trend analysis storage (used by the AI backend's history.db).
func BuildHistoryEntry(result *models.ScanResult) models.ScanHistoryEntry {
	return models.ScanHistoryEntry{
		ScanID:        result.ScanID,
		Target:        result.Target,
		ScannedAt:     result.StartedAt,
		Duration:      result.Duration,
		SentinelScore: result.SentinelScore,
		CriticalCount: result.Summary.CriticalCount,
		HighCount:     result.Summary.HighCount,
		MediumCount:   result.Summary.MediumCount,
		EndpointCount: result.Summary.TotalEndpoints,
		ShadowCount:   result.Summary.UndocumentedCount + result.Summary.ZombieCount,
	}
}
