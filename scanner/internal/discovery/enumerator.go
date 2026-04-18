// Package discovery implements Phase 1 of the Sentinel-API scan pipeline:
// high-concurrency endpoint enumeration, auth/rate-limit enrichment, and
// Shadow/Zombie API detection via OpenAPI schema diff or heuristic patterns.
package discovery

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sentinel-api/scanner/internal/engine"
	"github.com/sentinel-api/scanner/internal/models"
	"go.uber.org/zap"
)

// Enumerator orchestrates Phase 1 discovery. It manages a bounded goroutine
// pool, collects live endpoints, enriches each with auth/rate-limit metadata,
// and compares results against an optional OpenAPI schema for Shadow API detection.
type Enumerator struct {
	client   *engine.Client
	cfg      *models.ScanConfig
	log      *zap.SugaredLogger
	progress func(done, total int)
}

// NewEnumerator constructs an Enumerator. progress is an optional callback
// invoked after each path probe with (done, total) counts.
func NewEnumerator(
	client *engine.Client,
	cfg *models.ScanConfig,
	log *zap.SugaredLogger,
	progress func(done, total int),
) *Enumerator {
	return &Enumerator{client: client, cfg: cfg, log: log, progress: progress}
}

// Run performs full discovery. Returns (all live endpoints, shadow/zombie subset, error).
func (e *Enumerator) Run(ctx context.Context) ([]*models.Endpoint, []*models.Endpoint, error) {
	e.log.Infow("discovery phase starting",
		"target", e.cfg.Target,
		"concurrency", e.cfg.Concurrency,
	)

	paths, err := e.loadWordlist()
	if err != nil {
		return nil, nil, fmt.Errorf("load wordlist: %w", err)
	}

	endpoints, err := e.enumerate(ctx, paths)
	if err != nil && ctx.Err() == nil {
		return nil, nil, err
	}

	e.enrichAll(ctx, endpoints)

	var shadows []*models.Endpoint
	if e.cfg.OpenAPISpecURL != "" {
		documented, specErr := e.fetchDocumentedPaths(ctx)
		if specErr != nil {
			e.log.Warnw("OpenAPI spec fetch failed — falling back to heuristic shadow detection",
				"error", specErr)
			shadows = e.heuristicShadows(endpoints)
		} else {
			shadows = e.detectShadows(endpoints, documented)
		}
	} else {
		shadows = e.heuristicShadows(endpoints)
	}

	e.log.Infow("discovery complete",
		"endpoints_found", len(endpoints),
		"shadows", len(shadows),
	)
	return endpoints, shadows, nil
}

// ---------------------------------------------------------------------------
// Wordlist loading
// ---------------------------------------------------------------------------

func (e *Enumerator) loadWordlist() ([]string, error) {
	if e.cfg.WordlistPath == "" {
		return builtinWordlist(), nil
	}
	f, err := os.Open(e.cfg.WordlistPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := make(map[string]struct{})
	var paths []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "/") {
			line = "/" + line
		}
		if _, dup := seen[line]; !dup {
			seen[line] = struct{}{}
			paths = append(paths, line)
		}
	}
	return paths, sc.Err()
}

// ---------------------------------------------------------------------------
// Concurrent enumeration
// ---------------------------------------------------------------------------

func (e *Enumerator) enumerate(ctx context.Context, paths []string) ([]*models.Endpoint, error) {
	total := len(paths)
	work := make(chan string, e.cfg.Concurrency*4)
	results := make(chan *models.Endpoint, e.cfg.Concurrency*4)

	var done atomic.Int64
	var wg sync.WaitGroup

	for i := 0; i < e.cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range work {
				if ctx.Err() != nil {
					return
				}
				if ep := e.probeEndpoint(ctx, path); ep != nil {
					results <- ep
				}
				n := int(done.Add(1))
				if e.progress != nil {
					e.progress(n, total)
				}
			}
		}()
	}

	go func() {
		for _, path := range paths {
			select {
			case <-ctx.Done():
				break
			case work <- path:
			}
		}
		close(work)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var endpoints []*models.Endpoint
	for ep := range results {
		endpoints = append(endpoints, ep)
	}
	return endpoints, nil
}

// probeEndpoint fires one HTTP probe. Returns nil for dead paths.
func (e *Enumerator) probeEndpoint(ctx context.Context, path string) *models.Endpoint {
	url := e.cfg.Target + path
	resp, err := e.client.Probe(ctx, url)
	if err != nil || !isLive(resp.StatusCode) {
		return nil
	}

	return &models.Endpoint{
		URL:          url,
		Path:         path,
		Method:       models.MethodGET,
		StatusCode:   resp.StatusCode,
		ContentType:  resp.ContentType,
		ResponseSize: resp.Size,
		TTFB:         resp.TTFB,
		Headers:      resp.Headers,
		DiscoveredAt: time.Now(),
		Status:       models.StatusDocumented,
	}
}

// isLive returns true for status codes that confirm an endpoint exists.
// 404 and 410 are definitively dead; everything else is interesting.
func isLive(code int) bool {
	return code != http.StatusNotFound &&
		code != http.StatusGone &&
		code != http.StatusNotImplemented
}

// ---------------------------------------------------------------------------
// Endpoint enrichment
// ---------------------------------------------------------------------------

func (e *Enumerator) enrichAll(ctx context.Context, endpoints []*models.Endpoint) {
	sem := make(chan struct{}, e.cfg.Concurrency)
	var wg sync.WaitGroup
	for _, ep := range endpoints {
		ep := ep
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			e.enrichEndpoint(ctx, ep)
		}()
	}
	wg.Wait()
}

// enrichEndpoint probes without credentials to determine auth requirements,
// detects rate-limit headers, and applies status heuristics.
func (e *Enumerator) enrichEndpoint(ctx context.Context, ep *models.Endpoint) {
	// Auth detection — re-probe without credentials.
	unauthCfg := *e.cfg
	unauthCfg.BearerToken = ""
	unauthCfg.APIKey = ""
	unauthClient := engine.NewClient(&unauthCfg, e.log)
	unauthResp, err := unauthClient.Probe(ctx, ep.URL)
	if err == nil {
		switch unauthResp.StatusCode {
		case http.StatusUnauthorized:
			ep.AuthRequired = true
			ep.AuthType = detectAuthType(unauthResp.Headers)
		case http.StatusForbidden:
			ep.AuthRequired = true
			ep.AuthType = "Opaque (403)"
		default:
			ep.AuthRequired = false
			ep.AuthType = "None"
		}
	}

	// Rate-limit header detection.
	for _, header := range rateLimitHeaders {
		if val, ok := ep.Headers[header]; ok && val != "" {
			ep.HasRateLimit = true
			ep.RateLimitHeader = header
			break
		}
	}

	// Internal path classification.
	for _, prefix := range internalPrefixes {
		if strings.HasPrefix(strings.ToLower(ep.Path), prefix) {
			ep.Status = models.StatusInternal
			break
		}
	}

	// Zombie / legacy API classification.
	if ep.Status == models.StatusDocumented {
		for _, prefix := range legacyPrefixes {
			if strings.HasPrefix(strings.ToLower(ep.Path), prefix) {
				ep.Status = models.StatusZombie
				break
			}
		}
	}
}

func detectAuthType(headers map[string]string) string {
	wwwAuth := strings.ToLower(headers["WWW-Authenticate"])
	switch {
	case strings.Contains(wwwAuth, "bearer"):
		return "JWT/Bearer"
	case strings.Contains(wwwAuth, "basic"):
		return "HTTP Basic"
	default:
		return "Unknown"
	}
}

// ---------------------------------------------------------------------------
// Shadow API detection
// ---------------------------------------------------------------------------

// fetchDocumentedPaths downloads an OpenAPI 3.x or Swagger 2.x spec and
// returns all documented path strings in a set.
func (e *Enumerator) fetchDocumentedPaths(ctx context.Context) (map[string]struct{}, error) {
	resp, err := e.client.Do(ctx, http.MethodGet, e.cfg.OpenAPISpecURL, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("spec returned HTTP %d", resp.StatusCode)
	}

	var spec map[string]interface{}
	if err := json.Unmarshal(resp.Body, &spec); err != nil {
		return nil, fmt.Errorf("parse spec JSON: %w", err)
	}

	paths := make(map[string]struct{})
	if rawPaths, ok := spec["paths"].(map[string]interface{}); ok {
		for path := range rawPaths {
			paths[normalisePath(path)] = struct{}{}
			// Also index the base segment before any path parameter.
			base := normalisePath(strings.SplitN(path, "{", 2)[0])
			paths[base] = struct{}{}
		}
	}
	return paths, nil
}

// detectShadows marks any discovered path not present in the schema as undocumented.
func (e *Enumerator) detectShadows(
	discovered []*models.Endpoint,
	documented map[string]struct{},
) []*models.Endpoint {
	var shadows []*models.Endpoint
	for _, ep := range discovered {
		if _, found := documented[normalisePath(ep.Path)]; !found {
			ep.Status = models.StatusUndocumented
			ep.RiskScore = scoreShadow(ep)
			shadows = append(shadows, ep)
		}
	}
	return shadows
}

// heuristicShadows applies pattern matching when no schema is available.
func (e *Enumerator) heuristicShadows(endpoints []*models.Endpoint) []*models.Endpoint {
	var shadows []*models.Endpoint
	for _, ep := range endpoints {
		if ep.Status == models.StatusInternal || ep.Status == models.StatusZombie {
			shadows = append(shadows, ep)
			continue
		}
		path := strings.ToLower(ep.Path)
		for _, pat := range shadowPatterns {
			if strings.Contains(path, pat) {
				ep.Status = models.StatusUndocumented
				ep.RiskScore = scoreShadow(ep)
				shadows = append(shadows, ep)
				break
			}
		}
	}
	return shadows
}

// scoreShadow produces an initial risk score for a shadow endpoint.
func scoreShadow(ep *models.Endpoint) int {
	score := 40
	path := strings.ToLower(ep.Path)
	for pattern, bonus := range map[string]int{
		"admin": 30, "internal": 30, "debug": 25, "metrics": 20,
		"token": 20, "secret": 25, "backup": 20, "env": 25,
		"config": 20, "test": 10, "beta": 10, "v0": 15,
		"graphql": 15, "llm": 20, "ai": 10,
	} {
		if strings.Contains(path, pattern) {
			score += bonus
		}
	}
	if !ep.AuthRequired {
		score += 20
	}
	if score > 100 {
		return 100
	}
	return score
}

func normalisePath(p string) string {
	p = strings.SplitN(p, "?", 2)[0]
	p = strings.TrimRight(p, "/")
	if p == "" {
		return "/"
	}
	return p
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

var rateLimitHeaders = []string{
	"X-RateLimit-Limit", "X-RateLimit-Remaining",
	"X-Rate-Limit-Limit", "RateLimit-Limit", "Retry-After",
}

var internalPrefixes = []string{
	"/internal/", "/admin/", "/debug/", "/metrics",
	"/health", "/actuator", "/_", "/private/",
}

var legacyPrefixes = []string{
	"/v0/", "/api/v0/", "/api/legacy/", "/legacy/",
	"/old/", "/deprecated/",
}

var shadowPatterns = []string{
	"internal", "debug", "metrics", "actuator", "env", "config",
	"backup", "test", "beta", "staging", "dev", "admin", "secret",
	"token", "key", "swagger", "graphql", "llm", "ai", "v0",
}

// builtinWordlist returns the built-in high-signal path list.
// Covers REST conventions, framework defaults, internal/debug routes,
// legacy patterns, schema endpoints, and emerging AI/LLM surfaces.
func builtinWordlist() []string {
	return []string{
		// Versioned API roots
		"/api", "/api/v1", "/api/v2", "/api/v3",
		"/v1", "/v2", "/v3", "/v4",

		// Auth & identity
		"/v1/auth", "/v1/auth/token", "/v1/auth/login", "/v1/auth/logout",
		"/v1/auth/refresh", "/v1/auth/register", "/v1/auth/forgot-password",
		"/v1/oauth/token", "/v1/oauth/authorize",
		"/api/auth", "/api/token", "/api/login",

		// User management
		"/v1/users", "/v1/users/me", "/v1/user",
		"/v1/profile", "/v1/account", "/v1/accounts",
		"/v1/admin", "/v1/admin/users", "/v1/admin/roles",

		// Common business resources
		"/v1/orders", "/v1/products", "/v1/items",
		"/v1/payments", "/v1/invoices", "/v1/subscriptions",
		"/v1/search", "/v1/upload", "/v1/files",
		"/v1/notifications", "/v1/messages",
		"/v1/reports", "/v1/analytics", "/v1/events",

		// Shadow / internal (high risk)
		"/internal", "/internal/metrics", "/internal/debug",
		"/internal/config", "/internal/health", "/internal/status",
		"/admin", "/admin/panel", "/admin/config",
		"/debug", "/debug/vars", "/debug/pprof",
		"/metrics", "/prometheus",
		"/actuator", "/actuator/health", "/actuator/env",
		"/actuator/beans", "/actuator/mappings",
		"/env", "/.env", "/config", "/config.json",
		"/backup", "/backup.sql", "/dump.sql",

		// Legacy / zombie
		"/v0", "/v0/users", "/api/v0",
		"/api/legacy", "/api/old", "/api/deprecated", "/legacy",

		// API schema / docs
		"/swagger", "/swagger.json", "/swagger-ui.html",
		"/api-docs", "/openapi.json", "/openapi.yaml",
		"/docs", "/redoc", "/graphql", "/graphiql",

		// Health / status
		"/.well-known/openid-configuration",
		"/health", "/healthz", "/ready", "/live",
		"/ping", "/status", "/version", "/info",

		// DevOps exposure
		"/.git/config", "/Dockerfile", "/docker-compose.yml",

		// AI / LLM endpoints (emerging threat surface, API9)
		"/ai", "/api/ai", "/ai/generate", "/ai/chat",
		"/v1/completions", "/v1/chat/completions",
		"/beta/ai", "/beta/ai/generate",
		"/llm", "/api/llm", "/api/ai/stream",
	}
}
