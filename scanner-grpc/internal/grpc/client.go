// Package grpc provides the Go-side gRPC client that connects the Sentinel-API
// scanner to the Python AI service.
//
// This client replaces the HTTP pushToAIBackend() call in reporter/reporter.go
// for internal deployments where both services run in the same Docker Compose stack.
// The HTTP endpoint remains available for external integrations and CI/CD pipelines.
//
// Usage:
//
//	client, err := grpc.NewAIClient(cfg, log)
//	defer client.Close()
//
//	// Stream scan events in real time
//	streamer, _ := client.OpenEventStream(ctx)
//	defer streamer.Close()
//	streamer.Send(engine.ScanEvent{...})
//
//	// Batch-enrich findings after scan completes
//	enriched, _ := client.AnalyzeFindings(ctx, scanID, target, findings)
package grpc

import (
	"context"
	"fmt"
	"io"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/sentinel-api/scanner/internal/models"
	pb "github.com/sentinel-api/scanner/internal/grpc/sentinelpb"
)

// ---------------------------------------------------------------------------
// AIClient
// ---------------------------------------------------------------------------

// AIClient wraps the gRPC connection and SentinelAI stub.
type AIClient struct {
	conn   *grpc.ClientConn
	stub   pb.SentinelAIClient
	log    *zap.SugaredLogger
	target string // gRPC server address, e.g. "localhost:50051"
}

// NewAIClient dials the Python AI service and returns a ready AIClient.
// The caller must call Close() when done.
func NewAIClient(grpcTarget string, log *zap.SugaredLogger) (*AIClient, error) {
	conn, err := grpc.NewClient(
		grpcTarget,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             5 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(64*1024*1024),
			grpc.MaxCallSendMsgSize(64*1024*1024),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("dial AI gRPC server %s: %w", grpcTarget, err)
	}

	return &AIClient{
		conn:   conn,
		stub:   pb.NewSentinelAIClient(conn),
		log:    log,
		target: grpcTarget,
	}, nil
}

// Close releases the gRPC connection.
func (c *AIClient) Close() error {
	return c.conn.Close()
}

// ---------------------------------------------------------------------------
// AnalyzeFindings — batch LLM remediation
// ---------------------------------------------------------------------------

// EnrichedFinding is the result of a single finding enrichment from the AI layer.
type EnrichedFinding struct {
	ID          string
	Remediation string
	CodeSnippet string
	Priority    string  // IMMEDIATE | SHORT_TERM | LONG_TERM
	RiskScore   int
}

// AnalyzeFindings sends all findings to the Python AI service and returns
// enriched remediation data. Back-fills Finding.Remediation in-place.
// Timeout is set to 120 seconds to accommodate large finding sets + LLM inference.
func (c *AIClient) AnalyzeFindings(
	ctx context.Context,
	scanID, target string,
	findings []*models.Finding,
) ([]EnrichedFinding, error) {
	if len(findings) == 0 {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	pbFindings := make([]*pb.Finding, 0, len(findings))
	for _, f := range findings {
		pbFindings = append(pbFindings, modelFindingToPB(f))
	}

	req := &pb.AnalyzeFindingsRequest{
		ScanId:   scanID,
		Target:   target,
		Findings: pbFindings,
	}

	c.log.Infow("grpc_analyze_findings", "scan_id", scanID, "findings", len(findings))
	t0 := time.Now()

	resp, err := c.stub.AnalyzeFindings(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("AnalyzeFindings RPC: %w", err)
	}

	c.log.Infow("grpc_analyze_findings_done",
		"enriched", resp.FindingsEnriched,
		"model", resp.ModelUsed,
		"inference_ms", resp.InferenceMs,
		"elapsed_ms", time.Since(t0).Milliseconds(),
	)

	// Build result slice and back-fill remediation onto original findings.
	byID := make(map[string]*pb.RemediatedFinding, len(resp.Findings))
	for _, rf := range resp.Findings {
		byID[rf.Id] = rf
	}

	var results []EnrichedFinding
	for _, f := range findings {
		if rf, ok := byID[f.ID]; ok {
			// Back-fill onto the original finding (mirrors HTTP pushToAIBackend behaviour).
			text := rf.Remediation
			if rf.CodeSnippet != "" {
				text += "\n\n```\n" + rf.CodeSnippet + "\n```"
			}
			f.Remediation = text

			results = append(results, EnrichedFinding{
				ID:          rf.Id,
				Remediation: rf.Remediation,
				CodeSnippet: rf.CodeSnippet,
				Priority:    rf.Priority,
				RiskScore:   int(rf.RiskScore),
			})
		}
	}

	return results, nil
}

// ---------------------------------------------------------------------------
// StreamScanEvents — real-time event streaming
// ---------------------------------------------------------------------------

// EventStreamer holds the open gRPC client-streaming call for scan events.
type EventStreamer struct {
	stream pb.SentinelAI_StreamScanEventsClient
	scanID string
	log    *zap.SugaredLogger
}

// OpenEventStream opens a client-streaming RPC to the AI service.
// The caller should defer streamer.Close() and call Send() as events arrive.
func (c *AIClient) OpenEventStream(ctx context.Context, scanID string) (*EventStreamer, error) {
	stream, err := c.stub.StreamScanEvents(ctx)
	if err != nil {
		return nil, fmt.Errorf("open StreamScanEvents: %w", err)
	}
	c.log.Infow("grpc_event_stream_opened", "scan_id", scanID)
	return &EventStreamer{stream: stream, scanID: scanID, log: c.log}, nil
}

// Send pushes one scan event to the Python AI service (and on to WebSocket clients).
func (s *EventStreamer) Send(phase, message string, done, total int) error {
	return s.stream.Send(&pb.ScanEvent{
		ScanId:  s.scanID,
		Phase:   phase,
		Message: message,
		Done:    int32(done),
		Total:   int32(total),
		TsMs:    time.Now().UnixMilli(),
	})
}

// Close flushes the stream and receives the server's StreamAck.
func (s *EventStreamer) Close() (*pb.StreamAck, error) {
	ack, err := s.stream.CloseAndRecv()
	if err != nil && err != io.EOF {
		s.log.Warnw("grpc_event_stream_close_error", "scan_id", s.scanID, "error", err)
		return nil, err
	}
	if ack != nil {
		s.log.Infow("grpc_event_stream_closed",
			"scan_id", s.scanID,
			"events_received", ack.EventsReceived,
		)
	}
	return ack, nil
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

// Health calls the AI service Health RPC and returns true if the model is loaded.
func (c *AIClient) Health(ctx context.Context) (bool, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := c.stub.Health(ctx, &pb.HealthRequest{})
	if err != nil {
		return false, "", fmt.Errorf("Health RPC: %w", err)
	}
	return resp.ModelLoaded, resp.Status, nil
}

// ---------------------------------------------------------------------------
// ScoreFinding — single-finding rescore
// ---------------------------------------------------------------------------

// ScoreFinding asks the Python SentinelRank engine to rescore a single finding.
// Used by the dashboard "rescore" action.
func (c *AIClient) ScoreFinding(ctx context.Context, f *models.Finding) (int, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := c.stub.ScoreFinding(ctx, &pb.ScoreFindingRequest{
		Finding: modelFindingToPB(f),
	})
	if err != nil {
		return 0, "", fmt.Errorf("ScoreFinding RPC: %w", err)
	}
	return int(resp.RiskScore), resp.Severity, nil
}

// ---------------------------------------------------------------------------
// GetScanHistory
// ---------------------------------------------------------------------------

// GetScanHistory fetches paginated scan history from the DuckDB store.
func (c *AIClient) GetScanHistory(
	ctx context.Context,
	target string,
	limit, offset int,
) ([]*pb.ScanHistoryEntry, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := c.stub.GetScanHistory(ctx, &pb.HistoryRequest{
		Target: target,
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		return nil, 0, fmt.Errorf("GetScanHistory RPC: %w", err)
	}
	return resp.Entries, int(resp.Total), nil
}

// ---------------------------------------------------------------------------
// Model conversion helpers
// ---------------------------------------------------------------------------

// modelFindingToPB converts a models.Finding to a proto Finding message.
func modelFindingToPB(f *models.Finding) *pb.Finding {
	pb := &pb.Finding{
		Id:          f.ID,
		Severity:    string(f.Severity),
		Owasp:       string(f.OWASP),
		Title:       f.Title,
		Description: f.Description,
		Evidence:    f.Evidence,
		CvssScore:   f.CVSSScore,
		RiskScore:   int32(f.RiskScore),
		Tags:        f.Tags,
	}

	if f.Endpoint != nil {
		pb.Endpoint = &pb.Endpoint{
			Path:         f.Endpoint.Path,
			Method:       string(f.Endpoint.Method),
			AuthRequired: f.Endpoint.AuthRequired,
			AuthType:     f.Endpoint.AuthType,
			HasRateLimit: f.Endpoint.HasRateLimit,
			Status:       string(f.Endpoint.Status),
			StatusCode:   int32(f.Endpoint.StatusCode),
		}
	}

	return pb
}
