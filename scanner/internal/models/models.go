// Package models defines every data structure shared across the Sentinel-API
// scanner pipeline. All packages import from here; nothing else imports models,
// keeping the dependency graph acyclic.
package models

import "time"

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

// Severity is an OWASP/CVSS-aligned risk tier.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// OWASPCategory maps findings to OWASP API Security Top 10 (2023).
type OWASPCategory string

const (
	OWASPAPI1  OWASPCategory = "API1:2023 - Broken Object Level Authorization"
	OWASPAPI2  OWASPCategory = "API2:2023 - Broken Authentication"
	OWASPAPI3  OWASPCategory = "API3:2023 - Broken Object Property Level Authorization"
	OWASPAPI4  OWASPCategory = "API4:2023 - Unrestricted Resource Consumption"
	OWASPAPI5  OWASPCategory = "API5:2023 - Broken Function Level Authorization"
	OWASPAPI6  OWASPCategory = "API6:2023 - Unrestricted Access to Sensitive Business Flows"
	OWASPAPI7  OWASPCategory = "API7:2023 - Server Side Request Forgery"
	OWASPAPI8  OWASPCategory = "API8:2023 - Security Misconfiguration"
	OWASPAPI9  OWASPCategory = "API9:2023 - Improper Inventory Management"
	OWASPAPI10 OWASPCategory = "API10:2023 - Unsafe Consumption of APIs"
	OWASPNone  OWASPCategory = "General"
)

// HTTPMethod is a typed HTTP verb string.
type HTTPMethod string

const (
	MethodGET     HTTPMethod = "GET"
	MethodPOST    HTTPMethod = "POST"
	MethodPUT     HTTPMethod = "PUT"
	MethodPATCH   HTTPMethod = "PATCH"
	MethodDELETE  HTTPMethod = "DELETE"
	MethodHEAD    HTTPMethod = "HEAD"
	MethodOPTIONS HTTPMethod = "OPTIONS"
)

// EndpointStatus classifies an endpoint's documentation and lifecycle state.
type EndpointStatus string

const (
	StatusDocumented   EndpointStatus = "DOCUMENTED"
	StatusUndocumented EndpointStatus = "UNDOCUMENTED" // Shadow API
	StatusZombie       EndpointStatus = "ZOMBIE"       // Deprecated but live
	StatusInternal     EndpointStatus = "INTERNAL"     // Should not be public
)

// ---------------------------------------------------------------------------
// CVE types — replaces the previous []string with structured detail
// ---------------------------------------------------------------------------

// CVSSVersion identifies which CVSS scoring system a metric set uses.
type CVSSVersion string

const (
	CVSSv2   CVSSVersion = "2.0"
	CVSSv30  CVSSVersion = "3.0"
	CVSSv31  CVSSVersion = "3.1"
	CVSSv40  CVSSVersion = "4.0"
)

// CVSSMetrics holds a single CVSS score set from the NVD response.
type CVSSMetrics struct {
	Version    CVSSVersion `json:"version"`
	VectorStr  string      `json:"vector_string"`
	BaseScore  float64     `json:"base_score"`
	BaseSever  string      `json:"base_severity"` // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE"
}

// CVEDetail is a fully populated CVE record returned by the NVD live lookup.
// It replaces the previous bare string slice ([]string{"CVE-2021-23017"}).
type CVEDetail struct {
	ID            string      `json:"id"`             // e.g. "CVE-2021-23017"
	Description   string      `json:"description"`    // NVD English description
	Published     time.Time   `json:"published"`
	LastModified  time.Time   `json:"last_modified"`
	CVSS          CVSSMetrics `json:"cvss"`           // Highest-priority CVSS score
	CWEs          []string    `json:"cwes,omitempty"` // e.g. ["CWE-193"]
	References    []string    `json:"references,omitempty"`
	CPEMatches    []string    `json:"cpe_matches,omitempty"` // Affected CPE strings
	Exploited     bool        `json:"exploited"`      // true if in CISA KEV catalogue
	ExploitedDate *time.Time  `json:"exploited_date,omitempty"`
	// Source tracks where this record came from
	Source CVESource `json:"source"`
}

// CVESource records whether a CVE came from live NVD lookup or the static fallback.
type CVESource string

const (
	CVESourceNVD      CVESource = "nvd_api"
	CVESourceFallback CVESource = "static_fallback"
	CVESourceCache    CVESource = "cache"
)

// ---------------------------------------------------------------------------
// Core scan entities
// ---------------------------------------------------------------------------

// Endpoint represents a single discovered API endpoint.
type Endpoint struct {
	URL             string            `json:"url"`
	Path            string            `json:"path"`
	Method          HTTPMethod        `json:"method"`
	StatusCode      int               `json:"status_code"`
	ContentType     string            `json:"content_type"`
	ResponseSize    int64             `json:"response_size_bytes"`
	TTFB            time.Duration     `json:"ttfb_ms"`
	Headers         map[string]string `json:"headers"`
	AuthRequired    bool              `json:"auth_required"`
	AuthType        string            `json:"auth_type,omitempty"`
	HasRateLimit    bool              `json:"has_rate_limit"`
	RateLimitHeader string            `json:"rate_limit_header,omitempty"`
	Status          EndpointStatus    `json:"endpoint_status"`
	Parameters      []Parameter       `json:"parameters,omitempty"`
	DiscoveredAt    time.Time         `json:"discovered_at"`
	RiskScore       int               `json:"risk_score"`
}

// Parameter describes a single request parameter.
type Parameter struct {
	Name     string `json:"name"`
	Location string `json:"location"` // path | query | body | header
	Type     string `json:"type"`
	Required bool   `json:"required"`
	IsPII    bool   `json:"is_pii"`
}

// Finding is a confirmed security vulnerability.
type Finding struct {
	ID           string        `json:"id"`
	Severity     Severity      `json:"severity"`
	OWASP        OWASPCategory `json:"owasp_category"`
	Title        string        `json:"title"`
	Description  string        `json:"description"`
	Endpoint     *Endpoint     `json:"endpoint"`
	Evidence     string        `json:"evidence,omitempty"`
	Remediation  string        `json:"remediation,omitempty"`
	CVSSScore    float64       `json:"cvss_score,omitempty"`
	RiskScore    int           `json:"risk_score"`
	DiscoveredAt time.Time     `json:"discovered_at"`
	Tags         []string      `json:"tags,omitempty"`
}

// RateLimitProbe holds results from the OWASP API4 burst test.
type RateLimitProbe struct {
	Endpoint        *Endpoint     `json:"endpoint"`
	RequestsSent    int           `json:"requests_sent"`
	RateLimited     bool          `json:"rate_limited"`
	StatusCodes     map[int]int   `json:"status_codes"`
	BaseTTFB        time.Duration `json:"base_ttfb_ms"`
	BurstTTFB       time.Duration `json:"burst_ttfb_ms"`
	TTFBDegradation float64       `json:"ttfb_degradation_pct"`
	ServerCrashed   bool          `json:"server_crashed"`
	RecursiveRisk   bool          `json:"recursive_query_risk"`
}

// TechStack holds fingerprinted server-side technology.
// CVEs is now []CVEDetail (was []string) for full NVD data.
type TechStack struct {
	Server     string      `json:"server,omitempty"`
	Framework  string      `json:"framework,omitempty"`
	Language   string      `json:"language,omitempty"`
	WAF        string      `json:"waf,omitempty"`
	APIGateway string      `json:"api_gateway,omitempty"`
	TLSVersion string      `json:"tls_version,omitempty"`
	// CVEs holds fully-structured CVE records (NVD live or static fallback).
	CVEs       []CVEDetail `json:"cves,omitempty"`
	// CVEIDs is a flat string slice for log lines and backward compat.
	CVEIDs     []string    `json:"cve_ids,omitempty"`
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// ScanConfig holds all runtime parameters for a scan run.
type ScanConfig struct {
	Target          string        `yaml:"target"`
	Concurrency     int           `yaml:"concurrency"`
	Timeout         time.Duration `yaml:"timeout"`
	RateLimit       int           `yaml:"rate_limit_rps"`
	WordlistPath    string        `yaml:"wordlist_path"`
	OpenAPISpecURL  string        `yaml:"openapi_spec_url,omitempty"`
	BearerToken     string        `yaml:"bearer_token,omitempty"`
	APIKey          string        `yaml:"api_key,omitempty"`
	FollowRedirects bool          `yaml:"follow_redirects"`
	ScanModes       ScanModes     `yaml:"scan_modes"`
	OutputPath      string        `yaml:"output_path"`
	AIBackendURL    string        `yaml:"ai_backend_url"`
	UserAgent       string        `yaml:"user_agent"`
	ConfigFile      string        `yaml:"-"`

	// NVD API configuration (new)
	NVDAPIKey       string        `yaml:"nvd_api_key,omitempty"`  // Optional — raises rate limit 5→50 req/30s
	NVDTimeout      time.Duration `yaml:"nvd_timeout"`            // Per-request timeout (default 15s)
	NVDCacheTTL     time.Duration `yaml:"nvd_cache_ttl"`          // In-memory cache TTL (default 24h)
	NVDOffline      bool          `yaml:"nvd_offline"`            // Force static fallback (air-gapped)
}

// ScanModes controls which pipeline phases are enabled.
type ScanModes struct {
	Discovery     bool `yaml:"discovery"`
	OWASP         bool `yaml:"owasp"`
	RateLimitTest bool `yaml:"rate_limit"`
	PIIDetection  bool `yaml:"pii_detection"`
	ShadowAPI     bool `yaml:"shadow_api"`
	Fuzzing       bool `yaml:"fuzzing"`
	CVELookup     bool `yaml:"cve_lookup"` // Phase 0: live NVD enrichment (new)
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

// ScanResult is the complete output of one scan run.
type ScanResult struct {
	ScanID        string             `json:"scan_id"`
	Target        string             `json:"target"`
	StartedAt     time.Time          `json:"started_at"`
	CompletedAt   time.Time          `json:"completed_at"`
	Duration      string             `json:"duration"`
	TechStack     *TechStack         `json:"tech_stack"`
	Endpoints     []*Endpoint        `json:"endpoints"`
	Findings      []*Finding         `json:"findings"`
	ShadowAPIs    []*Endpoint        `json:"shadow_apis"`
	RateLimitData []*RateLimitProbe  `json:"rate_limit_probes"`
	Summary       ScanSummary        `json:"summary"`
	SentinelScore int                `json:"sentinel_rank_score"`
	DirectoryTree interface{}        `json:"directory_tree,omitempty"`
}

// ScanSummary provides aggregate counts.
type ScanSummary struct {
	TotalEndpoints     int `json:"total_endpoints"`
	DocumentedCount    int `json:"documented"`
	UndocumentedCount  int `json:"undocumented"`
	ZombieCount        int `json:"zombie"`
	InternalCount      int `json:"internal"`
	CriticalCount      int `json:"critical"`
	HighCount          int `json:"high"`
	MediumCount        int `json:"medium"`
	LowCount           int `json:"low"`
	InfoCount          int `json:"info"`
	PIIEndpoints       int `json:"pii_endpoints"`
	RateLimitedCount   int `json:"rate_limited_endpoints"`
	UnrateLimitedCount int `json:"unrate_limited_endpoints"`
	// CVE summary fields (new)
	CVETotal       int `json:"cve_total"`
	CVECritical    int `json:"cve_critical"`
	CVEHigh        int `json:"cve_high"`
	CVEExploited   int `json:"cve_exploited"` // CVEs in CISA KEV
}

// ScanHistoryEntry is a lightweight record for DuckDB trend analysis.
type ScanHistoryEntry struct {
	ScanID        string    `json:"scan_id"`
	Target        string    `json:"target"`
	ScannedAt     time.Time `json:"scanned_at"`
	Duration      string    `json:"duration"`
	SentinelScore int       `json:"sentinel_rank_score"`
	CriticalCount int       `json:"critical"`
	HighCount     int       `json:"high"`
	MediumCount   int       `json:"medium"`
	EndpointCount int       `json:"total_endpoints"`
	ShadowCount   int       `json:"shadow_apis"`
}
