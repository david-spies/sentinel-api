// Package nvd — findings.go
//
// CVEToFindings converts CVEDetail records (from LookupServer) into
// models.Finding structs so CVE-related infrastructure vulnerabilities
// surface in the same finding pipeline as OWASP checks.
//
// A Finding is emitted for every CVEDetail that meets the threshold:
//   - CVSS score ≥ 7.0  (HIGH or CRITICAL)  — always emitted
//   - CVSS score 4.0–6.9 (MEDIUM)           — emitted only if Exploited=true
//   - CVSS score < 4.0                       — suppressed (informational)
//
// Exploited CVEs (CISA KEV) are always emitted regardless of score and
// receive a severity bump: a MEDIUM KEV entry is treated as HIGH.
package nvd

import (
	"fmt"
	"strings"
	"time"

	"github.com/sentinel-api/scanner/internal/models"
)

// emitThreshold is the minimum CVSS base score to generate a Finding.
const emitThreshold = 7.0

// CVEToFindings converts a slice of CVEDetail records into models.Finding structs.
// endpoint may be nil — CVE findings are attached to a synthetic "infrastructure" endpoint.
func CVEToFindings(cves []models.CVEDetail, serverBanner string) []*models.Finding {
	if len(cves) == 0 {
		return nil
	}

	// Build a synthetic endpoint to attach CVE findings to.
	// This represents the server infrastructure rather than an API endpoint.
	infraEP := &models.Endpoint{
		URL:          "server://" + serverBanner,
		Path:         "/",
		Method:       models.MethodGET,
		Status:       models.StatusDocumented,
		DiscoveredAt: time.Now(),
	}

	var findings []*models.Finding
	for _, cve := range cves {
		if !shouldEmit(cve) {
			continue
		}

		sev := deriveSeverity(cve)
		risk := deriveCVERiskScore(cve)

		finding := &models.Finding{
			ID:          "CVE-INFRA-" + strings.ReplaceAll(cve.ID, "-", "_"),
			Severity:    sev,
			OWASP:       models.OWASPAPI8, // Security Misconfiguration — closest OWASP category
			Title:       fmt.Sprintf("%s in server component (%s)", cve.ID, serverBanner),
			Description: buildDescription(cve),
			Endpoint:    infraEP,
			Evidence:    buildEvidence(cve),
			CVSSScore:   cve.CVSS.BaseScore,
			RiskScore:   risk,
			DiscoveredAt: time.Now(),
			Tags:        buildTags(cve),
		}
		findings = append(findings, finding)
	}
	return findings
}

// shouldEmit returns true if a CVE should generate a Finding.
func shouldEmit(cve models.CVEDetail) bool {
	if cve.Exploited {
		return true // Always emit CISA KEV entries
	}
	return cve.CVSS.BaseScore >= emitThreshold
}

// deriveSeverity maps CVSS score + KEV status to a models.Severity tier.
// KEV entries receive a severity bump (MEDIUM → HIGH).
func deriveSeverity(cve models.CVEDetail) models.Severity {
	score := cve.CVSS.BaseScore
	var sev models.Severity
	switch {
	case score >= 9.0:
		sev = models.SeverityCritical
	case score >= 7.0:
		sev = models.SeverityHigh
	case score >= 4.0:
		sev = models.SeverityMedium
	default:
		sev = models.SeverityLow
	}
	// Bump MEDIUM to HIGH if actively exploited
	if cve.Exploited && sev == models.SeverityMedium {
		return models.SeverityHigh
	}
	return sev
}

// deriveCVERiskScore produces a 0-100 SentinelRank risk score for a CVE finding.
// Scores are anchored to CVSS base score with KEV and recency bonuses.
func deriveCVERiskScore(cve models.CVEDetail) int {
	score := cve.CVSS.BaseScore * 10.0 // scale 0-10 → 0-100

	// KEV bonus: actively exploited CVEs are more dangerous
	if cve.Exploited {
		score += 10
	}

	// Recency bonus: CVEs published in the last 12 months get a small boost
	if !cve.Published.IsZero() && time.Since(cve.Published) < 365*24*time.Hour {
		score += 5
	}

	if score > 100 {
		return 100
	}
	return int(score)
}

// buildDescription creates a human-readable description combining NVD data.
func buildDescription(cve models.CVEDetail) string {
	var parts []string

	if cve.Description != "" {
		parts = append(parts, cve.Description)
	} else {
		parts = append(parts, fmt.Sprintf("Vulnerability %s detected in server banner.", cve.ID))
	}

	if cve.Exploited {
		dateStr := ""
		if cve.ExploitedDate != nil {
			dateStr = " (added " + cve.ExploitedDate.Format("2006-01-02") + ")"
		}
		parts = append(parts, fmt.Sprintf(
			"⚠ This CVE is listed in the CISA Known Exploited Vulnerabilities catalogue%s — active exploitation confirmed in the wild.",
			dateStr,
		))
	}

	if cve.CVSS.VectorStr != "" {
		parts = append(parts, fmt.Sprintf(
			"CVSS %s score %.1f (%s) — vector: %s",
			cve.CVSS.Version, cve.CVSS.BaseScore, cve.CVSS.BaseSever, cve.CVSS.VectorStr,
		))
	}

	if len(cve.CWEs) > 0 {
		parts = append(parts, "Weakness types: "+strings.Join(cve.CWEs, ", "))
	}

	return strings.Join(parts, "\n\n")
}

// buildEvidence creates the evidence string shown in the Finding card.
func buildEvidence(cve models.CVEDetail) string {
	src := "NVD live lookup"
	if cve.Source == models.CVESourceFallback {
		src = "static fallback table"
	} else if cve.Source == models.CVESourceCache {
		src = "NVD cache"
	}

	published := "unknown"
	if !cve.Published.IsZero() {
		published = cve.Published.Format("2006-01-02")
	}

	return fmt.Sprintf(
		"CVE ID: %s | Source: %s | Published: %s | CVSS: %.1f (%s) | CISA KEV: %v",
		cve.ID, src, published, cve.CVSS.BaseScore, cve.CVSS.BaseSever, cve.Exploited,
	)
}

// buildTags assembles the tag slice for a CVE Finding.
func buildTags(cve models.CVEDetail) []string {
	tags := []string{"CVE", "infrastructure", "server-component", string(models.OWASPAPI8)}
	tags = append(tags, cve.ID)

	if cve.Exploited {
		tags = append(tags, "CISA-KEV", "actively-exploited")
	}
	for _, cwe := range cve.CWEs {
		tags = append(tags, cwe)
	}
	if cve.CVSS.BaseScore >= 9.0 {
		tags = append(tags, "CVSS-critical")
	}
	if cve.Source == models.CVESourceNVD {
		tags = append(tags, "nvd-verified")
	}

	return tags
}
