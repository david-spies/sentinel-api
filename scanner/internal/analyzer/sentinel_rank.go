// Package analyzer — sentinel_rank.go
//
// SentinelRank weighted scoring engine.
// Updated to include CVE-based infrastructure findings in scoring
// and to surface CVE summary counts in ScanSummary + Markdown report.
package analyzer

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/sentinel-api/scanner/internal/models"
	"github.com/sentinel-api/scanner/internal/nvd"
)

// ---------------------------------------------------------------------------
// Weight tables
// ---------------------------------------------------------------------------

var owaspWeights = map[models.OWASPCategory]float64{
	models.OWASPAPI1:  1.10,
	models.OWASPAPI2:  1.15,
	models.OWASPAPI3:  0.95,
	models.OWASPAPI4:  0.85,
	models.OWASPAPI5:  1.05,
	models.OWASPAPI6:  0.90,
	models.OWASPAPI7:  1.10,
	models.OWASPAPI8:  0.80,
	models.OWASPAPI9:  0.95,
	models.OWASPAPI10: 0.75,
	models.OWASPNone:  0.70,
}

var severityBaseCVSS = map[models.Severity]float64{
	models.SeverityCritical: 9.5,
	models.SeverityHigh:     7.5,
	models.SeverityMedium:   5.5,
	models.SeverityLow:      3.0,
	models.SeverityInfo:     1.0,
}

// ---------------------------------------------------------------------------
// RankEngine
// ---------------------------------------------------------------------------

type RankEngine struct{}

func NewRankEngine() *RankEngine { return &RankEngine{} }

// ScoreFinding returns the SentinelRank score (0-100) for a single finding.
// CVE-derived infrastructure findings (tagged "CVE") use their NVD CVSS score
// directly with the API8 weight and an additional KEV multiplier.
func (r *RankEngine) ScoreFinding(f *models.Finding) int {
	cvss := f.CVSSScore
	if cvss == 0 {
		cvss = severityBaseCVSS[f.Severity]
	}
	base := cvss * 10

	weight, ok := owaspWeights[f.OWASP]
	if !ok {
		weight = owaspWeights[models.OWASPNone]
	}

	score := base * weight *
		assetCriticalityMultiplier(f.Endpoint) *
		authStateMultiplier(f.Endpoint) *
		piiMultiplier(f.Endpoint) *
		kevMultiplier(f)

	return clamp(int(math.Round(score)), 0, 100)
}

// kevMultiplier returns 1.20 for CVE findings tagged as CISA KEV (actively exploited).
func kevMultiplier(f *models.Finding) float64 {
	for _, tag := range f.Tags {
		if tag == "CISA-KEV" || tag == "actively-exploited" {
			return 1.20
		}
	}
	return 1.0
}

// ---------------------------------------------------------------------------
// Environmental context multipliers (unchanged from previous version)
// ---------------------------------------------------------------------------

func assetCriticalityMultiplier(ep *models.Endpoint) float64 {
	if ep == nil {
		return 1.0
	}
	path := strings.ToLower(ep.Path)
	for _, kw := range []string{"payment", "billing", "credit", "invoice"} {
		if strings.Contains(path, kw) {
			return 1.25
		}
	}
	for _, kw := range []string{"admin", "superuser", "root"} {
		if strings.Contains(path, kw) {
			return 1.20
		}
	}
	for _, kw := range []string{"auth", "token", "login"} {
		if strings.Contains(path, kw) {
			return 1.15
		}
	}
	for _, kw := range []string{"staging", "dev", "test"} {
		if strings.Contains(path, kw) {
			return 0.75
		}
	}
	return 1.0
}

func authStateMultiplier(ep *models.Endpoint) float64 {
	if ep == nil || ep.AuthRequired {
		return 1.0
	}
	return 1.15
}

func piiMultiplier(ep *models.Endpoint) float64 {
	if ep == nil {
		return 1.0
	}
	for _, param := range ep.Parameters {
		if param.IsPII {
			return 1.20
		}
	}
	return 1.0
}

// ---------------------------------------------------------------------------
// Endpoint-level scoring
// ---------------------------------------------------------------------------

func (r *RankEngine) ScoreEndpoint(ep *models.Endpoint, findings []*models.Finding) int {
	max := 0
	for _, f := range findings {
		if f.Endpoint == nil || f.Endpoint.Path != ep.Path {
			continue
		}
		if s := r.ScoreFinding(f); s > max {
			max = s
		}
	}
	ep.RiskScore = max
	return max
}

// ---------------------------------------------------------------------------
// Overall scan score
// ---------------------------------------------------------------------------

func (r *RankEngine) ScoreScan(result *models.ScanResult) int {
	if len(result.Findings) == 0 {
		return 95
	}

	tierWeight := map[models.Severity]float64{
		models.SeverityCritical: 4.0,
		models.SeverityHigh:     2.5,
		models.SeverityMedium:   1.5,
		models.SeverityLow:      0.8,
		models.SeverityInfo:     0.2,
	}

	var weightedSum, totalWeight float64
	for _, f := range result.Findings {
		s := float64(r.ScoreFinding(f))
		w := tierWeight[f.Severity]
		weightedSum += s * w
		totalWeight += w
	}

	if totalWeight == 0 {
		return 100
	}

	avgRisk := weightedSum / totalWeight
	penalty := math.Log1p(float64(result.Summary.CriticalCount))*5 +
		math.Log1p(float64(result.Summary.HighCount))*2 +
		math.Log1p(float64(result.Summary.UndocumentedCount))*3 +
		// Additional penalty for exploited CVEs in infrastructure
		math.Log1p(float64(result.Summary.CVEExploited))*4

	raw := avgRisk + penalty
	return clamp(100-int(math.Round(raw)), 0, 100)
}

// ---------------------------------------------------------------------------
// Directory tree
// ---------------------------------------------------------------------------

type DirectoryNode struct {
	Path     string             `json:"path"`
	Score    int                `json:"risk_score"`
	Severity models.Severity    `json:"severity"`
	Children []*DirectoryNode   `json:"children,omitempty"`
	Findings []*models.Finding  `json:"findings,omitempty"`
}

func (r *RankEngine) BuildDirectoryTree(result *models.ScanResult) *DirectoryNode {
	root := &DirectoryNode{
		Path:     "ROOT/",
		Score:    result.SentinelScore,
		Severity: scoreToSeverity(100 - result.SentinelScore),
	}

	buckets := map[string][]*models.Finding{
		"Auth-AuthZ":        {},
		"Rate-Limiting":     {},
		"Data-Privacy":      {},
		"Shadow-APIs":       {},
		"Server-Logic":      {},
		"Misconfiguration":  {},
		"CVE-Infrastructure": {}, // NEW: separate bucket for CVE findings
	}

	for _, f := range result.Findings {
		// CVE-derived infrastructure findings get their own bucket
		isCVE := false
		for _, tag := range f.Tags {
			if tag == "CVE" {
				isCVE = true
				break
			}
		}
		if isCVE {
			buckets["CVE-Infrastructure"] = append(buckets["CVE-Infrastructure"], f)
			continue
		}

		switch f.OWASP {
		case models.OWASPAPI1, models.OWASPAPI2, models.OWASPAPI5:
			buckets["Auth-AuthZ"] = append(buckets["Auth-AuthZ"], f)
		case models.OWASPAPI4:
			buckets["Rate-Limiting"] = append(buckets["Rate-Limiting"], f)
		case models.OWASPAPI3:
			buckets["Data-Privacy"] = append(buckets["Data-Privacy"], f)
		case models.OWASPAPI9:
			buckets["Shadow-APIs"] = append(buckets["Shadow-APIs"], f)
		case models.OWASPAPI7:
			buckets["Server-Logic"] = append(buckets["Server-Logic"], f)
		default:
			buckets["Misconfiguration"] = append(buckets["Misconfiguration"], f)
		}
	}

	for cat, fs := range buckets {
		if len(fs) == 0 {
			continue
		}
		maxScore := 0
		for _, f := range fs {
			if s := r.ScoreFinding(f); s > maxScore {
				maxScore = s
			}
		}
		node := &DirectoryNode{
			Path:     "ROOT/" + cat + "/",
			Score:    maxScore,
			Severity: scoreToSeverity(maxScore),
			Findings: fs,
		}
		root.Children = append(root.Children, node)
	}

	sort.Slice(root.Children, func(i, j int) bool {
		return root.Children[i].Score > root.Children[j].Score
	})
	return root
}

// ---------------------------------------------------------------------------
// Summary builder — updated with CVE counts
// ---------------------------------------------------------------------------

func BuildSummary(result *models.ScanResult) models.ScanSummary {
	s := models.ScanSummary{
		TotalEndpoints: len(result.Endpoints),
	}
	for _, ep := range result.Endpoints {
		switch ep.Status {
		case models.StatusDocumented:
			s.DocumentedCount++
		case models.StatusUndocumented:
			s.UndocumentedCount++
		case models.StatusZombie:
			s.ZombieCount++
		case models.StatusInternal:
			s.InternalCount++
		}
		if ep.HasRateLimit {
			s.RateLimitedCount++
		} else {
			s.UnrateLimitedCount++
		}
	}

	for _, f := range result.Findings {
		switch f.Severity {
		case models.SeverityCritical:
			s.CriticalCount++
		case models.SeverityHigh:
			s.HighCount++
		case models.SeverityMedium:
			s.MediumCount++
		case models.SeverityLow:
			s.LowCount++
		case models.SeverityInfo:
			s.InfoCount++
		}
		for _, tag := range f.Tags {
			if strings.Contains(strings.ToLower(tag), "pii") {
				s.PIIEndpoints++
				break
			}
		}
	}

	// CVE summary counts from TechStack
	if result.TechStack != nil {
		s.CVETotal = len(result.TechStack.CVEs)
		for _, c := range result.TechStack.CVEs {
			sev := nvd.SeverityOf(c)
			if sev == models.SeverityCritical {
				s.CVECritical++
			} else if sev == models.SeverityHigh {
				s.CVEHigh++
			}
			if c.Exploited {
				s.CVEExploited++
			}
		}
	}

	return s
}

// ---------------------------------------------------------------------------
// Markdown report — updated with CVE section
// ---------------------------------------------------------------------------

func FormatMarkdownReport(result *models.ScanResult, tree *DirectoryNode) string {
	var sb strings.Builder

	sb.WriteString("# Sentinel-API Security Report\n\n")
	sb.WriteString("| Field | Value |\n|---|---|\n")
	sb.WriteString(fmt.Sprintf("| **Target** | %s |\n", result.Target))
	sb.WriteString(fmt.Sprintf("| **Scan ID** | %s |\n", result.ScanID))
	sb.WriteString(fmt.Sprintf("| **Started** | %s |\n", result.StartedAt.UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("| **Duration** | %s |\n", result.Duration))
	sb.WriteString(fmt.Sprintf("| **SentinelRank Score** | **%d / 100** |\n\n", result.SentinelScore))

	// Tech stack
	if result.TechStack != nil {
		ts := result.TechStack
		sb.WriteString("## Tech Stack\n\n")
		sb.WriteString("| Field | Detected |\n|---|---|\n")
		sb.WriteString(fmt.Sprintf("| Server | `%s` |\n", ts.Server))
		sb.WriteString(fmt.Sprintf("| Framework | `%s` |\n", ts.Framework))
		sb.WriteString(fmt.Sprintf("| Language | %s |\n", ts.Language))
		sb.WriteString(fmt.Sprintf("| WAF | %s |\n", ts.WAF))
		sb.WriteString(fmt.Sprintf("| API Gateway | %s |\n", ts.APIGateway))
		sb.WriteString(fmt.Sprintf("| TLS | %s |\n", ts.TLSVersion))
		if len(ts.CVEIDs) > 0 {
			sb.WriteString(fmt.Sprintf("| CVE IDs | `%s` |\n", strings.Join(ts.CVEIDs, "`, `")))
		}
		sb.WriteString("\n")

		// CVE detail table (new)
		if len(ts.CVEs) > 0 {
			sb.WriteString("## CVE Infrastructure Findings\n\n")
			sb.WriteString("> Source: ")
			hasLive := false
			for _, c := range ts.CVEs {
				if c.Source == models.CVESourceNVD {
					hasLive = true
					break
				}
			}
			if hasLive {
				sb.WriteString("NVD API 2.0 (live) + CISA KEV catalogue")
			} else {
				sb.WriteString("Static fallback table (enable `--nvd-lookup` for live data)")
			}
			sb.WriteString("\n\n")
			sb.WriteString("| CVE ID | CVSS | Severity | KEV | Description |\n|---|---|---|---|---|\n")
			for _, c := range ts.CVEs {
				kev := ""
				if c.Exploited {
					kevDate := ""
					if c.ExploitedDate != nil {
						kevDate = " (" + c.ExploitedDate.Format("2006-01-02") + ")"
					}
					kev = "⚠ Yes" + kevDate
				} else {
					kev = "No"
				}
				desc := c.Description
				if len(desc) > 100 {
					desc = desc[:97] + "..."
				}
				sb.WriteString(fmt.Sprintf("| `%s` | %.1f | %s | %s | %s |\n",
					c.ID, c.CVSS.BaseScore, c.CVSS.BaseSever, kev, desc))
			}
			sb.WriteString("\n")
		}
	}

	// Summary
	s := result.Summary
	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf(
		"- **Endpoints:** %d (%d documented, %d undocumented, %d zombie, %d internal)\n",
		s.TotalEndpoints, s.DocumentedCount, s.UndocumentedCount, s.ZombieCount, s.InternalCount,
	))
	sb.WriteString(fmt.Sprintf(
		"- **Findings:** Critical %d · High %d · Medium %d · Low %d · Info %d\n",
		s.CriticalCount, s.HighCount, s.MediumCount, s.LowCount, s.InfoCount,
	))
	sb.WriteString(fmt.Sprintf("- **PII-exposing endpoints:** %d\n", s.PIIEndpoints))
	sb.WriteString(fmt.Sprintf("- **Endpoints without rate limiting:** %d\n", s.UnrateLimitedCount))
	if s.CVETotal > 0 {
		sb.WriteString(fmt.Sprintf(
			"- **CVEs (infrastructure):** %d total · %d critical · %d high · %d CISA KEV\n",
			s.CVETotal, s.CVECritical, s.CVEHigh, s.CVEExploited,
		))
	}
	sb.WriteString("\n")

	// Directory risk map
	if tree != nil {
		sb.WriteString("## Directory Risk Map\n\n")
		sb.WriteString("| Path | Score | Severity |\n|---|---|---|\n")
		sb.WriteString(fmt.Sprintf("| `%s` | %d | Overall |\n", tree.Path, tree.Score))
		for _, child := range tree.Children {
			sb.WriteString(fmt.Sprintf("| `%s` | %d | %s |\n", child.Path, child.Score, child.Severity))
		}
		sb.WriteString("\n")
	}

	// Findings
	sb.WriteString("## Findings\n\n")
	for i, f := range result.Findings {
		epPath := ""
		if f.Endpoint != nil {
			epPath = fmt.Sprintf("`%s %s`", f.Endpoint.Method, f.Endpoint.Path)
		}
		sb.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, f.Title))
		sb.WriteString("| | |\n|---|---|\n")
		sb.WriteString(fmt.Sprintf("| Severity | **%s** |\n", f.Severity))
		sb.WriteString(fmt.Sprintf("| OWASP | %s |\n", f.OWASP))
		sb.WriteString(fmt.Sprintf("| Endpoint | %s |\n", epPath))
		sb.WriteString(fmt.Sprintf("| CVSS | %.1f |\n", f.CVSSScore))
		sb.WriteString(fmt.Sprintf("| SentinelRank | %d |\n\n", f.RiskScore))
		sb.WriteString(f.Description + "\n\n")
		if f.Evidence != "" {
			sb.WriteString("**Evidence:**\n\n```\n" + f.Evidence + "\n```\n\n")
		}
		if f.Remediation != "" {
			sb.WriteString("**Remediation:**\n\n" + f.Remediation + "\n\n")
		}
		if len(f.Tags) > 0 {
			sb.WriteString(fmt.Sprintf("**Tags:** %s\n\n", strings.Join(f.Tags, ", ")))
		}
		sb.WriteString("---\n\n")
	}

	sb.WriteString(fmt.Sprintf("*Generated by Sentinel-API v2.4.1 at %s*\n",
		time.Now().UTC().Format(time.RFC3339)))
	return sb.String()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func scoreToSeverity(score int) models.Severity {
	switch {
	case score >= 80:
		return models.SeverityCritical
	case score >= 60:
		return models.SeverityHigh
	case score >= 40:
		return models.SeverityMedium
	case score >= 20:
		return models.SeverityLow
	default:
		return models.SeverityInfo
	}
}
