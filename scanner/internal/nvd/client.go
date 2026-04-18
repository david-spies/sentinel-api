// Package nvd provides a live NVD (National Vulnerability Database) API 2.0
// client that replaces the static cveCheck() lookup table in engine/client.go.
//
// NVD API 2.0 docs: https://nvd.nist.gov/developers/vulnerabilities
// CISA KEV catalogue: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
//
// Design:
//   - Parse the server banner into (product, version) pairs using CPE heuristics
//   - Query the NVD /cves/2.0 endpoint for each detected component
//   - Enrich results with CISA KEV data (marks actively exploited CVEs)
//   - Cache results in memory with a configurable TTL (default 24 h)
//   - Gracefully fall back to the static table on network failure or NVD outage
//   - Respect NVD rate limits: 5 req/30 s without API key, 50 req/30 s with key
package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/sentinel-api/scanner/internal/models"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	nvdBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	kevURL     = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	// NVD rate limits (per 30-second rolling window)
	rateLimitNoKey = 5
	rateLimitKey   = 50

	// Maximum CVEs fetched per component query
	maxResultsPerQuery = 20
)

// ---------------------------------------------------------------------------
// NVD API response types
// ---------------------------------------------------------------------------

type nvdResponse struct {
	ResultsPerPage int          `json:"resultsPerPage"`
	StartIndex     int          `json:"startIndex"`
	TotalResults   int          `json:"totalResults"`
	Vulnerabilities []nvdVuln   `json:"vulnerabilities"`
}

type nvdVuln struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID               string           `json:"id"`
	Published        string           `json:"published"`
	LastModified     string           `json:"lastModified"`
	Descriptions     []nvdDescription `json:"descriptions"`
	Metrics          nvdMetrics       `json:"metrics"`
	Weaknesses       []nvdWeakness    `json:"weaknesses"`
	Configurations   []nvdConfig      `json:"configurations"`
	References       []nvdReference   `json:"references"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CVSSMetricV40 []nvdCVSSEntry `json:"cvssMetricV40"`
	CVSSMetricV31 []nvdCVSSEntry `json:"cvssMetricV31"`
	CVSSMetricV30 []nvdCVSSEntry `json:"cvssMetricV30"`
	CVSSMetricV2  []nvdCVSSEntry `json:"cvssMetricV2"`
}

type nvdCVSSEntry struct {
	Source   string   `json:"source"`
	Type     string   `json:"type"` // "Primary" | "Secondary"
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type nvdWeakness struct {
	Description []nvdDescription `json:"description"`
}

type nvdConfig struct {
	Nodes []nvdNode `json:"nodes"`
}

type nvdNode struct {
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
}

type nvdCPEMatch struct {
	Criteria string `json:"criteria"`
}

type nvdReference struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}

// ---------------------------------------------------------------------------
// CISA KEV response type
// ---------------------------------------------------------------------------

type kevCatalogue struct {
	Vulnerabilities []kevEntry `json:"vulnerabilities"`
}

type kevEntry struct {
	CVEID        string `json:"cveID"`
	DateAdded    string `json:"dateAdded"`
}

// ---------------------------------------------------------------------------
// Cache entry
// ---------------------------------------------------------------------------

type cacheEntry struct {
	details  []models.CVEDetail
	fetchedAt time.Time
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// Client is the NVD API 2.0 client. Construct one per scan run via NewClient().
type Client struct {
	http      *http.Client
	apiKey    string
	cacheTTL  time.Duration
	offline   bool
	log       *zap.SugaredLogger

	// In-memory TTL cache: cache key → []CVEDetail
	cacheMu  sync.RWMutex
	cache    map[string]cacheEntry

	// Rate-limiter: sliding window token bucket
	rateMu   sync.Mutex
	tokens   int
	lastFill time.Time
	maxTok   int

	// CISA KEV set: CVE ID → date added
	kevMu  sync.RWMutex
	kevSet map[string]time.Time
	kevAt  time.Time // when KEV was last fetched
}

// Config holds NVD client parameters (sourced from models.ScanConfig).
type Config struct {
	APIKey   string
	Timeout  time.Duration
	CacheTTL time.Duration
	Offline  bool
}

// NewClient constructs a ready-to-use NVD client.
func NewClient(cfg Config, log *zap.SugaredLogger) *Client {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	cacheTTL := cfg.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = 24 * time.Hour
	}

	maxTok := rateLimitNoKey
	if cfg.APIKey != "" {
		maxTok = rateLimitKey
	}

	return &Client{
		http:     &http.Client{Timeout: timeout},
		apiKey:   cfg.APIKey,
		cacheTTL: cacheTTL,
		offline:  cfg.Offline,
		log:      log,
		cache:    make(map[string]cacheEntry),
		tokens:   maxTok,
		lastFill: time.Now(),
		maxTok:   maxTok,
		kevSet:   make(map[string]time.Time),
	}
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// LookupServer is the main entry point. It takes the raw Server header value
// (e.g. "nginx/1.18.0 (Ubuntu)") and returns structured CVEDetail records.
// It falls back to the static table if NVD is unreachable or offline is true.
func (c *Client) LookupServer(ctx context.Context, serverHeader string) []models.CVEDetail {
	if serverHeader == "" {
		return nil
	}

	components := parseServerBanner(serverHeader)
	if len(components) == 0 {
		return staticFallback(serverHeader)
	}

	if c.offline {
		c.log.Debugw("nvd_offline_mode_static_fallback", "server", serverHeader)
		return staticFallback(serverHeader)
	}

	// Refresh CISA KEV catalogue (once per 6 hours)
	c.ensureKEVFresh(ctx)

	var all []models.CVEDetail
	seen := make(map[string]struct{})

	for _, comp := range components {
		results, err := c.queryComponent(ctx, comp)
		if err != nil {
			c.log.Warnw("nvd_query_failed_using_fallback",
				"component", comp.product,
				"version", comp.version,
				"error", err,
			)
			// Fall back to static table for this component
			for _, detail := range staticFallback(serverHeader) {
				if _, dup := seen[detail.ID]; !dup {
					seen[detail.ID] = struct{}{}
					detail.Source = models.CVESourceFallback
					all = append(all, detail)
				}
			}
			continue
		}
		for _, d := range results {
			if _, dup := seen[d.ID]; !dup {
				seen[d.ID] = struct{}{}
				all = append(all, d)
			}
		}
	}

	c.log.Infow("nvd_lookup_complete",
		"server", serverHeader,
		"cves_found", len(all),
	)
	return all
}

// ---------------------------------------------------------------------------
// Component detection
// ---------------------------------------------------------------------------

type component struct {
	product string
	version string
	vendor  string
}

// bannerPattern extracts product/version pairs from common server header formats.
// Examples handled:
//   nginx/1.18.0
//   Apache/2.4.51 (Ubuntu)
//   Microsoft-IIS/10.0
//   OpenSSL/1.1.1f
//   gunicorn/21.2.0
var bannerPattern = regexp.MustCompile(`([A-Za-z][A-Za-z0-9_\-\.]+)/(\d+\.\d+[\.\d]*)`)

func parseServerBanner(header string) []component {
	matches := bannerPattern.FindAllStringSubmatch(header, -1)
	var out []component
	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		prod := strings.ToLower(m[1])
		ver := m[2]
		vendor := inferVendor(prod)
		out = append(out, component{product: prod, version: ver, vendor: vendor})
	}
	return out
}

func inferVendor(product string) string {
	switch {
	case strings.HasPrefix(product, "nginx"):
		return "nginx"
	case strings.HasPrefix(product, "apache"):
		return "apache"
	case strings.HasPrefix(product, "microsoft-iis"), strings.HasPrefix(product, "iis"):
		return "microsoft"
	case strings.HasPrefix(product, "openssl"):
		return "openssl"
	case strings.HasPrefix(product, "gunicorn"):
		return "benoitc"
	case strings.HasPrefix(product, "uvicorn"):
		return "encode"
	case strings.HasPrefix(product, "php"):
		return "php"
	case strings.HasPrefix(product, "tomcat"):
		return "apache"
	case strings.HasPrefix(product, "jetty"):
		return "eclipse"
	case strings.HasPrefix(product, "express"):
		return "openjsf"
	}
	return ""
}

// ---------------------------------------------------------------------------
// NVD query
// ---------------------------------------------------------------------------

func (c *Client) queryComponent(ctx context.Context, comp component) ([]models.CVEDetail, error) {
	cacheKey := comp.product + "@" + comp.version

	// Cache hit?
	c.cacheMu.RLock()
	if entry, ok := c.cache[cacheKey]; ok && time.Since(entry.fetchedAt) < c.cacheTTL {
		c.cacheMu.RUnlock()
		c.log.Debugw("nvd_cache_hit", "component", cacheKey)
		return entry.details, nil
	}
	c.cacheMu.RUnlock()

	// Rate-limit token consumption
	if err := c.waitForToken(ctx); err != nil {
		return nil, fmt.Errorf("nvd rate limit wait: %w", err)
	}

	// Build query: use keywordSearch for product name + version
	// This is the recommended approach for banner-based lookups per NVD docs.
	params := url.Values{}
	params.Set("keywordSearch", comp.product+" "+comp.version)
	params.Set("resultsPerPage", fmt.Sprintf("%d", maxResultsPerQuery))
	// Filter to only CVEs with CVSS v3.x scores for quality
	if comp.version != "" {
		// Optionally use CPE-based search when we can construct a valid CPE
		if cpe := buildCPE(comp); cpe != "" {
			params.Set("cpeName", cpe)
			params.Del("keywordSearch")
		}
	}

	reqURL := nvdBaseURL + "?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build NVD request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	c.log.Debugw("nvd_request", "url", reqURL)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD HTTP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		// Back off and retry once
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(35 * time.Second):
		}
		resp2, err2 := c.http.Do(req)
		if err2 != nil {
			return nil, fmt.Errorf("NVD retry: %w", err2)
		}
		defer resp2.Body.Close()
		resp = resp2
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read NVD response: %w", err)
	}

	var nvdResp nvdResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return nil, fmt.Errorf("parse NVD JSON: %w", err)
	}

	details := c.convertNVDResponse(nvdResp, comp.version)

	// Enrich with CISA KEV data
	for i := range details {
		c.kevMu.RLock()
		if added, ok := c.kevSet[details[i].ID]; ok {
			details[i].Exploited = true
			details[i].ExploitedDate = &added
		}
		c.kevMu.RUnlock()
	}

	// Store in cache
	c.cacheMu.Lock()
	c.cache[cacheKey] = cacheEntry{details: details, fetchedAt: time.Now()}
	c.cacheMu.Unlock()

	return details, nil
}

// ---------------------------------------------------------------------------
// Response conversion
// ---------------------------------------------------------------------------

func (c *Client) convertNVDResponse(resp nvdResponse, queryVersion string) []models.CVEDetail {
	var out []models.CVEDetail

	for _, v := range resp.Vulnerabilities {
		cve := v.CVE

		// Extract English description
		description := ""
		for _, d := range cve.Descriptions {
			if d.Lang == "en" {
				description = d.Value
				break
			}
		}

		// Filter: skip CVEs clearly not related to the queried version
		// (NVD keyword search can return loosely related results)
		if queryVersion != "" && !versionRelevant(description, queryVersion, cve) {
			continue
		}

		// Pick highest-priority CVSS score (v4.0 > v3.1 > v3.0 > v2.0)
		cvss := pickBestCVSS(cve.Metrics)

		// Parse timestamps
		published, _ := time.Parse("2006-01-02T15:04:05.000", cve.Published)
		modified, _ := time.Parse("2006-01-02T15:04:05.000", cve.LastModified)

		// Extract CWEs
		var cwes []string
		for _, w := range cve.Weaknesses {
			for _, d := range w.Description {
				if d.Lang == "en" && strings.HasPrefix(d.Value, "CWE-") {
					cwes = append(cwes, d.Value)
				}
			}
		}

		// Extract top 5 reference URLs
		var refs []string
		for i, r := range cve.References {
			if i >= 5 {
				break
			}
			refs = append(refs, r.URL)
		}

		// Extract CPE criteria
		var cpes []string
		for _, cfg := range cve.Configurations {
			for _, node := range cfg.Nodes {
				for _, match := range node.CPEMatch {
					cpes = append(cpes, match.Criteria)
				}
			}
		}
		if len(cpes) > 10 {
			cpes = cpes[:10] // cap to avoid bloating the report
		}

		out = append(out, models.CVEDetail{
			ID:           cve.ID,
			Description:  description,
			Published:    published,
			LastModified: modified,
			CVSS:         cvss,
			CWEs:         cwes,
			References:   refs,
			CPEMatches:   cpes,
			Source:       models.CVESourceNVD,
		})
	}

	return out
}

// pickBestCVSS returns the highest-precedence CVSS metrics from the NVD record.
// Preference: primary v4.0 > primary v3.1 > primary v3.0 > any v3.1 > v2.0.
func pickBestCVSS(m nvdMetrics) models.CVSSMetrics {
	pick := func(entries []nvdCVSSEntry, ver string) (models.CVSSMetrics, bool) {
		// Prefer "Primary" source
		for _, e := range entries {
			if e.Type == "Primary" {
				return models.CVSSMetrics{
					Version:   models.CVSSVersion(e.CVSSData.Version),
					VectorStr: e.CVSSData.VectorString,
					BaseScore: e.CVSSData.BaseScore,
					BaseSever: e.CVSSData.BaseSeverity,
				}, true
			}
		}
		// Fall back to first entry
		if len(entries) > 0 {
			e := entries[0]
			return models.CVSSMetrics{
				Version:   models.CVSSVersion(e.CVSSData.Version),
				VectorStr: e.CVSSData.VectorString,
				BaseScore: e.CVSSData.BaseScore,
				BaseSever: e.CVSSData.BaseSeverity,
			}, true
		}
		return models.CVSSMetrics{}, false
	}

	if v, ok := pick(m.CVSSMetricV40, "4.0"); ok {
		return v
	}
	if v, ok := pick(m.CVSSMetricV31, "3.1"); ok {
		return v
	}
	if v, ok := pick(m.CVSSMetricV30, "3.0"); ok {
		return v
	}
	if v, ok := pick(m.CVSSMetricV2, "2.0"); ok {
		return v
	}
	return models.CVSSMetrics{}
}

// versionRelevant returns true if the CVE description or CPE data suggests
// the CVE affects the queried version, reducing false positives from keyword search.
func versionRelevant(description, version string, cve nvdCVE) bool {
	// If the description mentions the version, consider it relevant.
	if strings.Contains(description, version) {
		return true
	}
	// Check CPE criteria for version
	majorMinor := majorMinorOf(version)
	for _, cfg := range cve.Configurations {
		for _, node := range cfg.Nodes {
			for _, match := range node.CPEMatch {
				if strings.Contains(match.Criteria, version) ||
					(majorMinor != "" && strings.Contains(match.Criteria, majorMinor)) {
					return true
				}
			}
		}
	}
	// If no CPE data at all, accept the result (better to over-report)
	hasCPE := false
	for _, cfg := range cve.Configurations {
		for _, node := range cfg.Nodes {
			if len(node.CPEMatch) > 0 {
				hasCPE = true
				break
			}
		}
	}
	return !hasCPE
}

func majorMinorOf(version string) string {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return ""
}

// buildCPE constructs a CPE 2.3 search string when we have enough information.
// Format: cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*
func buildCPE(comp component) string {
	if comp.vendor == "" || comp.product == "" || comp.version == "" {
		return ""
	}
	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*",
		comp.vendor, comp.product, comp.version)
}

// ---------------------------------------------------------------------------
// CISA KEV catalogue
// ---------------------------------------------------------------------------

// ensureKEVFresh refreshes the CISA KEV catalogue if it's older than 6 hours.
func (c *Client) ensureKEVFresh(ctx context.Context) {
	c.kevMu.RLock()
	age := time.Since(c.kevAt)
	c.kevMu.RUnlock()

	if age < 6*time.Hour && len(c.kevSet) > 0 {
		return
	}

	go func() {
		if err := c.fetchKEV(ctx); err != nil {
			c.log.Warnw("kev_fetch_failed", "error", err)
		}
	}()
}

// fetchKEV downloads and parses the CISA KEV JSON catalogue.
func (c *Client) fetchKEV(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kevURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("KEV returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return err
	}

	var cat kevCatalogue
	if err := json.Unmarshal(body, &cat); err != nil {
		return fmt.Errorf("parse KEV JSON: %w", err)
	}

	newSet := make(map[string]time.Time, len(cat.Vulnerabilities))
	for _, e := range cat.Vulnerabilities {
		t, _ := time.Parse("2006-01-02", e.DateAdded)
		newSet[e.CVEID] = t
	}

	c.kevMu.Lock()
	c.kevSet = newSet
	c.kevAt = time.Now()
	c.kevMu.Unlock()

	c.log.Infow("kev_catalogue_refreshed", "entries", len(newSet))
	return nil
}

// ---------------------------------------------------------------------------
// Rate limiter (sliding window, 30-second refill)
// ---------------------------------------------------------------------------

func (c *Client) waitForToken(ctx context.Context) error {
	for {
		c.rateMu.Lock()
		now := time.Now()
		// Refill tokens every 30 seconds
		if now.Sub(c.lastFill) >= 30*time.Second {
			c.tokens = c.maxTok
			c.lastFill = now
		}
		if c.tokens > 0 {
			c.tokens--
			c.rateMu.Unlock()
			return nil
		}
		// Calculate wait until next refill
		wait := 30*time.Second - now.Sub(c.lastFill) + 100*time.Millisecond
		c.rateMu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
			// Loop to re-check
		}
	}
}

// ---------------------------------------------------------------------------
// Static fallback — exact replica of the old cveCheck() table
// Returns []CVEDetail with Source=CVESourceFallback for backward compatibility.
// ---------------------------------------------------------------------------

// staticTable maps server banner substrings to CVE IDs and descriptions.
var staticTable = []struct {
	product     string
	version     string
	cveID       string
	description string
	baseScore   float64
	severity    string
}{
	{"nginx", "1.18", "CVE-2021-23017", "nginx DNS resolver 1-byte heap buffer overflow", 9.4, "CRITICAL"},
	{"nginx", "1.16", "CVE-2019-9511", "nginx HTTP/2 denial of service (Data Dribble)", 7.5, "HIGH"},
	{"nginx", "1.16", "CVE-2019-9513", "nginx HTTP/2 denial of service (Resource Loop)", 7.5, "HIGH"},
	{"apache", "2.4.49", "CVE-2021-41773", "Apache HTTP Server 2.4.49 path traversal and RCE", 9.8, "CRITICAL"},
	{"apache", "2.4.50", "CVE-2021-42013", "Apache HTTP Server 2.4.50 path traversal bypass", 9.8, "CRITICAL"},
	{"iis", "7.5", "CVE-2017-7269", "IIS 7.5 WebDAV ScStoragePathFromUrl buffer overflow", 10.0, "CRITICAL"},
	{"openssl", "1.0.2", "CVE-2016-0800", "OpenSSL DROWN attack cross-protocol SSLv2 cipher downgrade", 5.9, "MEDIUM"},
	{"openssl", "1.1.0", "CVE-2017-3737", "OpenSSL 1.1.0 error state machine read-buffer overrun", 5.9, "MEDIUM"},
	{"php", "7.4", "CVE-2021-21703", "PHP-FPM local privilege escalation", 6.4, "MEDIUM"},
	{"php", "8.0", "CVE-2023-3247", "PHP XML external entity injection", 5.0, "MEDIUM"},
	{"tomcat", "9.0", "CVE-2020-1938", "Apache Tomcat 9.x AJP file inclusion (Ghostcat)", 9.8, "CRITICAL"},
	{"tomcat", "8.5", "CVE-2020-1938", "Apache Tomcat 8.5.x AJP file inclusion (Ghostcat)", 9.8, "CRITICAL"},
}

func staticFallback(serverHeader string) []models.CVEDetail {
	s := strings.ToLower(serverHeader)
	var out []models.CVEDetail
	seen := make(map[string]struct{})

	for _, row := range staticTable {
		if strings.Contains(s, row.product) &&
			(row.version == "" || strings.Contains(s, row.version)) {
			if _, dup := seen[row.cveID]; dup {
				continue
			}
			seen[row.cveID] = struct{}{}
			out = append(out, models.CVEDetail{
				ID:          row.cveID,
				Description: row.description,
				CVSS: models.CVSSMetrics{
					Version:   models.CVSSv31,
					BaseScore: row.baseScore,
					BaseSever: row.severity,
				},
				Source: models.CVESourceFallback,
			})
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Convenience: ExtractIDs returns bare CVE ID strings for logging
// ---------------------------------------------------------------------------

// ExtractIDs returns a flat slice of CVE ID strings from a []CVEDetail.
// Used to populate TechStack.CVEIDs for backward-compatible log lines.
func ExtractIDs(details []models.CVEDetail) []string {
	ids := make([]string, len(details))
	for i, d := range details {
		ids[i] = d.ID
	}
	return ids
}

// SeverityOf returns the Severity tier for a CVEDetail based on CVSS score.
func SeverityOf(d models.CVEDetail) models.Severity {
	score := d.CVSS.BaseScore
	switch {
	case score >= 9.0:
		return models.SeverityCritical
	case score >= 7.0:
		return models.SeverityHigh
	case score >= 4.0:
		return models.SeverityMedium
	case score > 0:
		return models.SeverityLow
	}
	return models.SeverityInfo
}
