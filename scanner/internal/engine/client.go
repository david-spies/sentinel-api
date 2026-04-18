// Package engine provides the core HTTP client and tech-stack fingerprinting
// shared by all Sentinel-API scanner phases. It is the only package allowed
// to open network connections; all other packages call through this client.
package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/sentinel-api/scanner/internal/models"
	"github.com/sentinel-api/scanner/internal/nvd"
)

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

// Response wraps an HTTP response with scanner-specific timing metadata.
type Response struct {
	StatusCode   int
	Headers      map[string]string
	Body         []byte
	TTFB         time.Duration
	TotalLatency time.Duration
	ContentType  string
	Size         int64
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// Client is the central, hardened HTTP client for all scanner phases.
//
// Guarantees:
//   - Global token-bucket rate limiter — prevents accidental DoS of target.
//   - Per-host connection pool sized to cfg.Concurrency.
//   - Automatic TTFB measurement via httptrace on every request.
//   - TLS version recorded on first handshake (used in TechStack report).
//   - WAF-evasion headers applied to every request.
//   - Probe() falls back GET on 405 so HEAD-only detection never silently fails.
type Client struct {
	http    *http.Client
	limiter *rate.Limiter
	cfg     *models.ScanConfig
	log     *zap.SugaredLogger

	mu           sync.Mutex
	requestCount int64
	errorCount   int64
	tlsVersion   string
}

// NewClient constructs a Client from cfg.
func NewClient(cfg *models.ScanConfig, log *zap.SugaredLogger) *Client {
	c := &Client{cfg: cfg, log: log}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec — scanner must inspect self-signed certs
		VerifyConnection: func(cs tls.ConnectionState) error {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.tlsVersion == "" {
				switch cs.Version {
				case tls.VersionTLS13:
					c.tlsVersion = "TLS 1.3"
				case tls.VersionTLS12:
					c.tlsVersion = "TLS 1.2"
				case tls.VersionTLS11:
					c.tlsVersion = "TLS 1.1 (deprecated)"
				case tls.VersionTLS10:
					c.tlsVersion = "TLS 1.0 (deprecated)"
				default:
					c.tlsVersion = "Unknown"
				}
			}
			return nil
		},
	}

	transport := &http.Transport{
		MaxIdleConnsPerHost:   cfg.Concurrency,
		MaxConnsPerHost:       cfg.Concurrency * 2,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsCfg,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}
	if !cfg.FollowRedirects {
		httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	c.http = httpClient
	c.limiter = rate.NewLimiter(rate.Limit(cfg.RateLimit), cfg.RateLimit)
	return c
}

// ---------------------------------------------------------------------------
// Core request execution
// ---------------------------------------------------------------------------

// Do executes a single HTTP request with rate limiting and TTFB tracing.
func (c *Client) Do(ctx context.Context, method, url string, body io.Reader) (*Response, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("build request %s %s: %w", method, url, err)
	}
	c.injectHeaders(req)

	var (
		writeEnd time.Time
		ttfb     time.Duration
	)
	trace := &httptrace.ClientTrace{
		WroteRequest: func(_ httptrace.WroteRequestInfo) {
			writeEnd = time.Now()
		},
		GotFirstResponseByte: func() {
			if !writeEnd.IsZero() {
				ttfb = time.Since(writeEnd)
			}
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	wallStart := time.Now()
	resp, err := c.http.Do(req)
	totalLatency := time.Since(wallStart)

	c.mu.Lock()
	c.requestCount++
	c.mu.Unlock()

	if err != nil {
		c.mu.Lock()
		c.errorCount++
		c.mu.Unlock()
		return nil, fmt.Errorf("http %s %s: %w", method, url, err)
	}
	defer resp.Body.Close()

	const maxBody = 512 * 1024
	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	return &Response{
		StatusCode:   resp.StatusCode,
		Headers:      flattenHeaders(resp.Header),
		Body:         rawBody,
		TTFB:         ttfb,
		TotalLatency: totalLatency,
		ContentType:  resp.Header.Get("Content-Type"),
		Size:         int64(len(rawBody)),
	}, nil
}

// Probe issues a HEAD to quickly check if a URL is live.
// Falls back to GET on 405 Method Not Allowed.
func (c *Client) Probe(ctx context.Context, url string) (*Response, error) {
	resp, err := c.Do(ctx, http.MethodHead, url, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusMethodNotAllowed {
		return c.Do(ctx, http.MethodGet, url, nil)
	}
	return resp, nil
}

// Stats returns total requests and error counts (thread-safe).
func (c *Client) Stats() (requests, errors int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requestCount, c.errorCount
}

// TLSVersion returns the negotiated TLS version from the first handshake.
func (c *Client) TLSVersion() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tlsVersion
}

// ---------------------------------------------------------------------------
// Header injection
// ---------------------------------------------------------------------------

func (c *Client) injectHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/json, */*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")

	ua := c.cfg.UserAgent
	if ua == "" {
		ua = "Mozilla/5.0 (compatible; SentinelAPI/2.4; +https://sentinel-api.io)"
	}
	req.Header.Set("User-Agent", ua)

	if c.cfg.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.BearerToken)
	}
	if c.cfg.APIKey != "" {
		req.Header.Set("X-API-Key", c.cfg.APIKey)
	}
}

// ---------------------------------------------------------------------------
// Tech-stack fingerprinting
// ---------------------------------------------------------------------------

// Fingerprint probes well-known paths and returns a populated TechStack.
// When cfg.ScanModes.CVELookup is true (and cfg.NVDOffline is false),
// it calls the live NVD API 2.0 via nvd.Client for structured CVEDetail records.
// Falls back to the static table automatically on NVD errors or when offline.
func (c *Client) Fingerprint(ctx context.Context, target string) *models.TechStack {
	ts := &models.TechStack{}

	for _, p := range []string{"/", "/health", "/api", "/v1", "/swagger.json", "/openapi.json", "/metrics"} {
		resp, err := c.Probe(ctx, target+p)
		if err != nil {
			continue
		}
		if ts.Server == "" {
			ts.Server = resp.Headers["Server"]
		}
		if ts.Framework == "" {
			ts.Framework = resp.Headers["X-Powered-By"]
		}
		if ts.WAF == "" {
			ts.WAF = detectWAF(resp.Headers)
		}
		if ts.APIGateway == "" {
			ts.APIGateway = detectGateway(resp.Headers)
		}
		if ts.Language == "" {
			ts.Language = inferLanguage(resp.Headers)
		}
	}

	c.mu.Lock()
	ts.TLSVersion = c.tlsVersion
	c.mu.Unlock()

	// ---------------------------------------------------------------------------
	// CVE lookup — NVD live or static fallback
	// ---------------------------------------------------------------------------
	if c.cfg.ScanModes.CVELookup && ts.Server != "" {
		nvdClient := nvd.NewClient(nvd.Config{
			APIKey:   c.cfg.NVDAPIKey,
			Timeout:  c.cfg.NVDTimeout,
			CacheTTL: c.cfg.NVDCacheTTL,
			Offline:  c.cfg.NVDOffline,
		}, c.log)

		c.log.Infow("nvd_cve_lookup_starting", "server", ts.Server)
		ts.CVEs = nvdClient.LookupServer(ctx, ts.Server)
		ts.CVEIDs = nvd.ExtractIDs(ts.CVEs)

		c.log.Infow("nvd_cve_lookup_complete",
			"server", ts.Server,
			"cves_found", len(ts.CVEs),
			"cve_ids", ts.CVEIDs,
		)
	} else if ts.Server != "" {
		// CVE lookup disabled — use static fallback for minimal coverage
		ts.CVEs = nvd.StaticFallbackPublic(ts.Server)
		ts.CVEIDs = nvd.ExtractIDs(ts.CVEs)
		if len(ts.CVEIDs) > 0 {
			c.log.Infow("static_cve_fallback_applied",
				"server", ts.Server,
				"cve_ids", ts.CVEIDs,
			)
		}
	}

	return ts
}

// ---------------------------------------------------------------------------
// Detection helpers
// ---------------------------------------------------------------------------

func detectWAF(h map[string]string) string {
	lower := lowercaseKeys(h)
	for header, name := range map[string]string{
		"cf-ray":                     "Cloudflare",
		"x-sucuri-id":                "Sucuri",
		"x-waf-status":               "Generic WAF",
		"x-amzn-requestid":           "AWS WAF",
		"x-kong-upstream-latency":    "Kong",
		"x-apigee-fault-code":        "Apigee",
		"x-ratelimit-limit-requests": "Rate-Limited Gateway",
	} {
		if _, ok := lower[header]; ok {
			return name
		}
	}
	return ""
}

func detectGateway(h map[string]string) string {
	lower := lowercaseKeys(h)
	switch {
	case lower["x-amzn-requestid"] != "":
		return "AWS API Gateway"
	case lower["x-kong-upstream-latency"] != "":
		return "Kong"
	case lower["x-apigee-fault-code"] != "":
		return "Apigee"
	case lower["x-mulesoft-transaction-id"] != "":
		return "MuleSoft"
	}
	return ""
}

func inferLanguage(h map[string]string) string {
	xpb := strings.ToLower(h["X-Powered-By"])
	srv := strings.ToLower(h["Server"])
	switch {
	case strings.Contains(xpb, "php"):
		return "PHP"
	case strings.Contains(xpb, "express") || strings.Contains(xpb, "node"):
		return "Node.js"
	case strings.Contains(srv, "gunicorn") || strings.Contains(srv, "uvicorn") || strings.Contains(xpb, "python"):
		return "Python"
	case strings.Contains(srv, "jetty") || strings.Contains(srv, "tomcat") || strings.Contains(xpb, "java"):
		return "Java"
	case strings.Contains(srv, "kestrel") || strings.Contains(xpb, ".net"):
		return ".NET / ASP.NET"
	case strings.Contains(srv, "go") || strings.Contains(xpb, "gin") || strings.Contains(xpb, "echo"):
		return "Go"
	case strings.Contains(srv, "ruby") || strings.Contains(xpb, "rails"):
		return "Ruby"
	}
	return ""
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vs := range h {
		out[k] = strings.Join(vs, ", ")
	}
	return out
}

func lowercaseKeys(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[strings.ToLower(k)] = v
	}
	return out
}
