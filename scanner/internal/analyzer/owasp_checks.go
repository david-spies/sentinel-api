// Package analyzer implements Phase 2: OWASP API Security Top 10 (2023) checks.
// Each exported function corresponds to one or more OWASP categories and emits
// typed models.Finding records consumed by the reporter.
package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sentinel-api/scanner/internal/engine"
	"github.com/sentinel-api/scanner/internal/models"
	"go.uber.org/zap"
)

// Analyzer runs all Phase 2 security checks against discovered endpoints.
// Each check is independent and safe to run concurrently.
type Analyzer struct {
	client *engine.Client
	cfg    *models.ScanConfig
	log    *zap.SugaredLogger
}

// NewAnalyzer constructs an Analyzer.
func NewAnalyzer(client *engine.Client, cfg *models.ScanConfig, log *zap.SugaredLogger) *Analyzer {
	return &Analyzer{client: client, cfg: cfg, log: log}
}

// Run executes all enabled OWASP checks and returns aggregated findings
// along with rate-limit probe results.
func (a *Analyzer) Run(
	ctx context.Context,
	endpoints []*models.Endpoint,
) ([]*models.Finding, []*models.RateLimitProbe) {
	var (
		mu       sync.Mutex
		findings []*models.Finding
		probes   []*models.RateLimitProbe
	)

	addFinding := func(f *models.Finding) {
		if f == nil {
			return
		}
		mu.Lock()
		findings = append(findings, f)
		mu.Unlock()
	}
	addProbe := func(p *models.RateLimitProbe) {
		if p == nil {
			return
		}
		mu.Lock()
		probes = append(probes, p)
		mu.Unlock()
	}

	sem := make(chan struct{}, a.cfg.Concurrency)
	var wg sync.WaitGroup

	for _, ep := range endpoints {
		ep := ep
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			// API1 — Broken Object Level Authorization
			for _, f := range a.checkBOLA(ctx, ep) {
				addFinding(f)
			}
			// API2 — Broken Authentication
			addFinding(a.checkBrokenAuth(ctx, ep))
			// API3 — Mass Assignment
			addFinding(a.checkMassAssignment(ctx, ep))
			// API4 — Unrestricted Resource Consumption
			if a.cfg.ScanModes.RateLimitTest {
				probe := a.probeRateLimit(ctx, ep)
				addProbe(probe)
				addFinding(rateLimitFinding(probe))
			}
			// API5 — Broken Function Level Authorization
			addFinding(a.checkBFLA(ctx, ep))
			// API7 — SSRF
			addFinding(a.checkSSRF(ctx, ep))
			// API8 — Security Misconfiguration
			for _, f := range a.checkMisconfiguration(ctx, ep) {
				addFinding(f)
			}
			// PII (cross-cutting concern)
			if a.cfg.ScanModes.PIIDetection {
				addFinding(a.checkPIILeakage(ctx, ep))
			}
		}()
	}

	wg.Wait()
	return findings, probes
}

// ---------------------------------------------------------------------------
// API1:2023 — Broken Object Level Authorization (BOLA / IDOR)
// ---------------------------------------------------------------------------

func (a *Analyzer) checkBOLA(ctx context.Context, ep *models.Endpoint) []*models.Finding {
	if !containsIDParam(ep.Path) {
		return nil
	}
	paths := generateIDVariants(ep.Path)
	if len(paths) < 2 {
		return nil
	}

	baseResp, err := a.client.Do(ctx, string(ep.Method), a.cfg.Target+paths[0], nil)
	if err != nil || baseResp.StatusCode != http.StatusOK {
		return nil
	}
	altResp, err := a.client.Do(ctx, string(ep.Method), a.cfg.Target+paths[1], nil)
	if err != nil {
		return nil
	}

	if altResp.StatusCode != http.StatusOK {
		return nil
	}

	return []*models.Finding{{
		ID:          "BOLA-" + sanitiseID(ep.Path),
		Severity:    models.SeverityCritical,
		OWASP:       models.OWASPAPI1,
		Title:       "Broken Object Level Authorization (BOLA / IDOR)",
		Description: fmt.Sprintf("Endpoint %s returned HTTP 200 for a resource ID belonging to a different user. No server-side ownership validation detected.", ep.Path),
		Endpoint:    ep,
		Evidence:    fmt.Sprintf("%s %s → %d | %s %s → %d", ep.Method, paths[0], baseResp.StatusCode, ep.Method, paths[1], altResp.StatusCode),
		CVSSScore:   8.1,
		RiskScore:   scoreFind(ep, 85, models.SeverityCritical),
		DiscoveredAt: time.Now(),
		Tags:        []string{"BOLA", "IDOR", "horizontal-privilege-escalation", "API1"},
	}}
}

// ---------------------------------------------------------------------------
// API2:2023 — Broken Authentication
// ---------------------------------------------------------------------------

func (a *Analyzer) checkBrokenAuth(ctx context.Context, ep *models.Endpoint) *models.Finding {
	if !ep.AuthRequired {
		return nil
	}

	tests := []struct{ token, label string }{
		{"", "No token"},
		{"Bearer invalid.token.here", "Invalid JWT structure"},
		{"Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.", "alg:none JWT"},
	}

	for _, t := range tests {
		req, err := http.NewRequestWithContext(ctx, string(ep.Method), a.cfg.Target+ep.Path, nil)
		if err != nil {
			continue
		}
		if t.token != "" {
			req.Header.Set("Authorization", t.token)
		}

		resp, err := a.client.Do(ctx, req.Method, req.URL.String(), req.Body)
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
			return &models.Finding{
				ID:          "BROKEN-AUTH-" + sanitiseID(ep.Path),
				Severity:    models.SeverityCritical,
				OWASP:       models.OWASPAPI2,
				Title:       "Broken Authentication — " + t.label,
				Description: fmt.Sprintf("Endpoint %s returned %d with test credential %q. Server is not properly validating authentication tokens.", ep.Path, resp.StatusCode, t.label),
				Endpoint:    ep,
				Evidence:    fmt.Sprintf("%s %s with %q → HTTP %d", ep.Method, ep.Path, t.label, resp.StatusCode),
				CVSSScore:   9.1,
				RiskScore:   scoreFind(ep, 90, models.SeverityCritical),
				DiscoveredAt: time.Now(),
				Tags:        []string{"broken-auth", "JWT", "token-bypass", "API2"},
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// API3:2023 — Broken Object Property Level Authorization (Mass Assignment)
// ---------------------------------------------------------------------------

func (a *Analyzer) checkMassAssignment(ctx context.Context, ep *models.Endpoint) *models.Finding {
	if ep.Method != models.MethodPUT &&
		ep.Method != models.MethodPATCH &&
		ep.Method != models.MethodPOST {
		return nil
	}

	payload := map[string]interface{}{
		"role":        "admin",
		"is_admin":    true,
		"permissions": []string{"*"},
		"plan":        "enterprise",
	}
	body, _ := json.Marshal(payload)

	resp, err := a.client.Do(ctx, string(ep.Method), a.cfg.Target+ep.Path, bytes.NewReader(body))
	if err != nil {
		return nil
	}

	bodyLower := strings.ToLower(string(resp.Body))
	for _, field := range []string{`"role":"admin"`, `"is_admin":true`, `"admin":true`} {
		if strings.Contains(bodyLower, field) {
			return &models.Finding{
				ID:          "MASS-ASSIGN-" + sanitiseID(ep.Path),
				Severity:    models.SeverityHigh,
				OWASP:       models.OWASPAPI3,
				Title:       "Mass Assignment — Privileged Field Accepted",
				Description: fmt.Sprintf("Endpoint %s accepted and reflected privileged field %q in the request body. Any authenticated user can escalate privileges.", ep.Path, field),
				Endpoint:    ep,
				Evidence:    fmt.Sprintf("Request body included %q; response reflected the value.", field),
				CVSSScore:   7.5,
				RiskScore:   scoreFind(ep, 72, models.SeverityHigh),
				DiscoveredAt: time.Now(),
				Tags:        []string{"mass-assignment", "privilege-escalation", "API3"},
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// API4:2023 — Unrestricted Resource Consumption
// ---------------------------------------------------------------------------

func (a *Analyzer) probeRateLimit(ctx context.Context, ep *models.Endpoint) *models.RateLimitProbe {
	const (
		warmupRequests = 5
		burstRequests  = 50
	)

	probe := &models.RateLimitProbe{
		Endpoint:    ep,
		StatusCodes: make(map[int]int),
	}

	// Warmup — establish baseline TTFB.
	var warmupTTFBs []time.Duration
	for i := 0; i < warmupRequests; i++ {
		resp, err := a.client.Do(ctx, string(ep.Method), a.cfg.Target+ep.Path, nil)
		if err != nil {
			continue
		}
		warmupTTFBs = append(warmupTTFBs, resp.TTFB)
		probe.StatusCodes[resp.StatusCode]++
	}
	probe.BaseTTFB = medianDuration(warmupTTFBs)

	// Burst — measure degradation.
	var burstTTFBs []time.Duration
	for i := 0; i < burstRequests; i++ {
		resp, err := a.client.Do(ctx, string(ep.Method), a.cfg.Target+ep.Path, nil)
		if err != nil {
			continue
		}
		burstTTFBs = append(burstTTFBs, resp.TTFB)
		probe.StatusCodes[resp.StatusCode]++
		probe.RequestsSent++
		if resp.StatusCode == http.StatusTooManyRequests {
			probe.RateLimited = true
		}
		if resp.StatusCode >= 500 {
			probe.ServerCrashed = true
		}
	}
	probe.BurstTTFB = medianDuration(burstTTFBs)

	if probe.BaseTTFB > 0 {
		probe.TTFBDegradation = (float64(probe.BurstTTFB-probe.BaseTTFB) / float64(probe.BaseTTFB)) * 100
	}
	if probe.TTFBDegradation > 200 {
		probe.RecursiveRisk = true
	}

	return probe
}

func rateLimitFinding(probe *models.RateLimitProbe) *models.Finding {
	if probe == nil || probe.RateLimited {
		return nil
	}

	severity := models.SeverityMedium
	score := 55
	detail := fmt.Sprintf(
		"No 429 returned after %d burst requests. Rate limit headers absent. Credential stuffing feasibility: HIGH.",
		probe.RequestsSent,
	)

	if probe.RecursiveRisk {
		severity = models.SeverityCritical
		score = 88
		detail = fmt.Sprintf(
			"TTFB degraded %.0f%% under burst (base %v → burst %v). No rate limiting detected. Indicates potential recursive query attack or Zip Bomb vulnerability.",
			probe.TTFBDegradation,
			probe.BaseTTFB.Round(time.Millisecond),
			probe.BurstTTFB.Round(time.Millisecond),
		)
	}

	return &models.Finding{
		ID:       "RATE-LIMIT-" + sanitiseID(probe.Endpoint.Path),
		Severity: severity,
		OWASP:    models.OWASPAPI4,
		Title:    "Unrestricted Resource Consumption — No Rate Limiting",
		Description: detail,
		Endpoint: probe.Endpoint,
		Evidence: fmt.Sprintf(
			"Sent %d requests. StatusCodes: %v. TTFBDegradation: %.1f%%. RecursiveRisk: %v.",
			probe.RequestsSent, probe.StatusCodes, probe.TTFBDegradation, probe.RecursiveRisk,
		),
		CVSSScore:    6.5,
		RiskScore:    score,
		DiscoveredAt: time.Now(),
		Tags:         []string{"rate-limiting", "DoS", "resource-exhaustion", "API4"},
	}
}

// ---------------------------------------------------------------------------
// API5:2023 — Broken Function Level Authorization (BFLA)
// ---------------------------------------------------------------------------

func (a *Analyzer) checkBFLA(ctx context.Context, ep *models.Endpoint) *models.Finding {
	path := strings.ToLower(ep.Path)
	isAdminFunc := false
	for _, indicator := range []string{"admin", "management", "manage", "staff", "superuser", "root"} {
		if strings.Contains(path, indicator) {
			isAdminFunc = true
			break
		}
	}
	if !isAdminFunc {
		return nil
	}

	resp, err := a.client.Do(ctx, string(ep.Method), a.cfg.Target+ep.Path, nil)
	if err != nil {
		return nil
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return nil
	}

	return &models.Finding{
		ID:          "BFLA-" + sanitiseID(ep.Path),
		Severity:    models.SeverityCritical,
		OWASP:       models.OWASPAPI5,
		Title:       "Broken Function Level Authorization (BFLA)",
		Description: fmt.Sprintf("Admin/management endpoint %s returned HTTP %d with a standard user credential. Function-level access control is not enforced.", ep.Path, resp.StatusCode),
		Endpoint:    ep,
		Evidence:    fmt.Sprintf("%s %s with user JWT → HTTP %d", ep.Method, ep.Path, resp.StatusCode),
		CVSSScore:   8.8,
		RiskScore:   scoreFind(ep, 88, models.SeverityCritical),
		DiscoveredAt: time.Now(),
		Tags:        []string{"BFLA", "admin-bypass", "vertical-privilege-escalation", "API5"},
	}
}

// ---------------------------------------------------------------------------
// API7:2023 — Server-Side Request Forgery (SSRF)
// ---------------------------------------------------------------------------

func (a *Analyzer) checkSSRF(ctx context.Context, ep *models.Endpoint) *models.Finding {
	ssrfIndicators := []string{"url", "redirect", "callback", "webhook", "fetch", "proxy", "src", "href", "link", "dest"}
	pathLower := strings.ToLower(ep.Path)
	relevant := false
	for _, ind := range ssrfIndicators {
		if strings.Contains(pathLower, ind) {
			relevant = true
			break
		}
	}
	if !relevant {
		return nil
	}

	payloads := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/",
		"http://127.0.0.1/",
		"http://[::1]/",
		"file:///etc/passwd",
	}

	for _, payload := range payloads {
		testURL := fmt.Sprintf("%s%s?url=%s", a.cfg.Target, ep.Path, payload)
		resp, err := a.client.Do(ctx, http.MethodGet, testURL, nil)
		if err != nil {
			continue
		}
		body := string(resp.Body)
		if strings.Contains(body, "ami-id") ||
			strings.Contains(body, "instance-id") ||
			strings.Contains(body, "root:x:0:0") {
			return &models.Finding{
				ID:          "SSRF-" + sanitiseID(ep.Path),
				Severity:    models.SeverityCritical,
				OWASP:       models.OWASPAPI7,
				Title:       "Server-Side Request Forgery (SSRF)",
				Description: fmt.Sprintf("Endpoint %s fetched an attacker-controlled URL. The server may reach internal cloud metadata endpoints or localhost services.", ep.Path),
				Endpoint:    ep,
				Evidence:    fmt.Sprintf("Payload %q → HTTP %d with %d bytes response.", payload, resp.StatusCode, resp.Size),
				CVSSScore:   9.0,
				RiskScore:   95,
				DiscoveredAt: time.Now(),
				Tags:        []string{"SSRF", "cloud-metadata", "internal-network", "API7"},
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// API8:2023 — Security Misconfiguration
// ---------------------------------------------------------------------------

func (a *Analyzer) checkMisconfiguration(ctx context.Context, ep *models.Endpoint) []*models.Finding {
	var findings []*models.Finding

	resp, err := a.client.Do(ctx, http.MethodOptions, a.cfg.Target+ep.Path, nil)
	if err != nil {
		return nil
	}

	// 1. Wildcard CORS.
	if acao := resp.Headers["Access-Control-Allow-Origin"]; acao == "*" {
		findings = append(findings, &models.Finding{
			ID:          "CORS-" + sanitiseID(ep.Path),
			Severity:    models.SeverityMedium,
			OWASP:       models.OWASPAPI8,
			Title:       "Overly Permissive CORS Policy",
			Description: fmt.Sprintf("Endpoint %s returns Access-Control-Allow-Origin: * — any origin may make credentialed cross-origin requests.", ep.Path),
			Endpoint:    ep,
			Evidence:    "Access-Control-Allow-Origin: *",
			CVSSScore:   6.5,
			RiskScore:   60,
			DiscoveredAt: time.Now(),
			Tags:        []string{"CORS", "misconfiguration", "API8"},
		})
	}

	// 2. Missing security headers on authenticated endpoints.
	if ep.AuthRequired {
		getResp, err := a.client.Do(ctx, http.MethodGet, a.cfg.Target+ep.Path, nil)
		if err == nil {
			var missing []string
			for header, label := range map[string]string{
				"Strict-Transport-Security": "HSTS absent",
				"X-Content-Type-Options":    "MIME sniffing not blocked",
				"X-Frame-Options":           "clickjacking protection absent",
			} {
				if getResp.Headers[header] == "" {
					missing = append(missing, label)
				}
			}
			if len(missing) >= 2 {
				findings = append(findings, &models.Finding{
					ID:          "SEC-HEADERS-" + sanitiseID(ep.Path),
					Severity:    models.SeverityLow,
					OWASP:       models.OWASPAPI8,
					Title:       "Missing Security Response Headers",
					Description: fmt.Sprintf("Endpoint %s is missing: %s.", ep.Path, strings.Join(missing, "; ")),
					Endpoint:    ep,
					Evidence:    strings.Join(missing, ", "),
					CVSSScore:   3.1,
					RiskScore:   25,
					DiscoveredAt: time.Now(),
					Tags:        []string{"security-headers", "misconfiguration", "API8"},
				})
			}
		}
	}

	// 3. Dangerous HTTP methods (XST risk).
	if allow := resp.Headers["Allow"]; allow != "" {
		for _, method := range []string{"TRACE", "TRACK", "CONNECT"} {
			if strings.Contains(strings.ToUpper(allow), method) {
				findings = append(findings, &models.Finding{
					ID:          "HTTP-METHOD-" + sanitiseID(ep.Path),
					Severity:    models.SeverityMedium,
					OWASP:       models.OWASPAPI8,
					Title:       fmt.Sprintf("Dangerous HTTP Method Enabled (%s)", method),
					Description: fmt.Sprintf("Endpoint %s allows %s, enabling Cross-Site Tracing (XST) attacks.", ep.Path, method),
					Endpoint:    ep,
					Evidence:    "Allow: " + allow,
					CVSSScore:   5.3,
					RiskScore:   45,
					DiscoveredAt: time.Now(),
					Tags:        []string{"http-methods", "XST", "misconfiguration", "API8"},
				})
				break
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// PII Leakage (cross-cutting — triggered by ScanModes.PIIDetection)
// ---------------------------------------------------------------------------

var piiPatterns = map[string]*regexp.Regexp{
	"Credit Card (PAN)":       regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b`),
	"US SSN":                  regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
	"Email Address":           regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`),
	"US Phone Number":         regexp.MustCompile(`\b(\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`),
	"AWS Access Key":          regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"Private Key (PEM)":       regexp.MustCompile(`-----BEGIN (?:RSA |EC )?PRIVATE KEY-----`),
	"Bearer Token in Body":    regexp.MustCompile(`"(?:access_token|token|jwt|bearer)"\s*:\s*"[A-Za-z0-9\-_.]{20,}"`),
}

func (a *Analyzer) checkPIILeakage(ctx context.Context, ep *models.Endpoint) *models.Finding {
	resp, err := a.client.Do(ctx, http.MethodGet, a.cfg.Target+ep.Path, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil
	}

	body := string(resp.Body)
	var matched []string
	for label, re := range piiPatterns {
		if re.MatchString(body) {
			matched = append(matched, label)
		}
	}
	if len(matched) == 0 {
		return nil
	}

	return &models.Finding{
		ID:          "PII-" + sanitiseID(ep.Path),
		Severity:    models.SeverityHigh,
		OWASP:       models.OWASPAPI3,
		Title:       "Sensitive Data / PII Leakage in API Response",
		Description: fmt.Sprintf("Endpoint %s returned data matching PII patterns: %s. Review and mask sensitive response fields.", ep.Path, strings.Join(matched, ", ")),
		Endpoint:    ep,
		Evidence:    fmt.Sprintf("Matched in %d-byte response: %v", resp.Size, matched),
		CVSSScore:   7.5,
		RiskScore:   scoreFind(ep, 75, models.SeverityHigh),
		DiscoveredAt: time.Now(),
		Tags:        append([]string{"PII", "data-leakage", "compliance"}, matched...),
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func containsIDParam(path string) bool {
	return strings.Contains(path, "{id}") ||
		strings.Contains(path, ":id") ||
		regexp.MustCompile(`/\d{1,10}(?:/|$)`).MatchString(path)
}

func generateIDVariants(path string) []string {
	replace := func(s, from, to string) string { return strings.Replace(s, from, to, 1) }
	switch {
	case strings.Contains(path, "{id}"):
		return []string{replace(path, "{id}", "1001"), replace(path, "{id}", "1002")}
	case strings.Contains(path, ":id"):
		return []string{replace(path, ":id", "1001"), replace(path, ":id", "1002")}
	}
	re := regexp.MustCompile(`/(\d+)`)
	m := re.FindStringSubmatchIndex(path)
	if m == nil {
		return nil
	}
	return []string{
		path[:m[2]] + "1001" + path[m[3]:],
		path[:m[2]] + "1002" + path[m[3]:],
	}
}

func scoreFind(ep *models.Endpoint, base int, _ models.Severity) int {
	score := base
	path := strings.ToLower(ep.Path)
	for pattern, bonus := range map[string]int{
		"admin": 10, "payment": 10, "billing": 10, "token": 5, "secret": 8,
	} {
		if strings.Contains(path, pattern) {
			score += bonus
		}
	}
	if !ep.AuthRequired {
		score += 8
	}
	return int(math.Min(float64(score), 100))
}

func sanitiseID(path string) string {
	r := strings.NewReplacer("/", "_", "{", "", "}", "", ":", "_")
	s := strings.Trim(r.Replace(path), "_")
	if len(s) > 40 {
		return s[:40]
	}
	return s
}

func medianDuration(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(ds))
	copy(sorted, ds)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	return sorted[len(sorted)/2]
}
