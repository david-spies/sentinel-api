"""
ai/core/sentinel_rank.py

Python port of the Go SentinelRank scoring engine (analyzer/sentinel_rank.go).
All weight tables, formulas, and multipliers must remain in sync with the Go source.

The Python engine is used by:
  - The AI service when rescoring findings after LLM analysis
  - The gRPC ScoreFinding endpoint
  - The DuckDB history writer (to store consistent scores)

Formula:
    RiskScore = (CVSS × 10) × owasp_weight
                × asset_criticality_multiplier
                × auth_state_multiplier
                × pii_multiplier

Overall scan score (0 = critical risk, 100 = excellent posture):
    raw = weighted_avg_risk + log_penalty(finding_counts)
    SentinelScore = 100 − clamp(raw, 0, 100)
"""

from __future__ import annotations

import math
from typing import Optional

from .models import (
    Endpoint,
    Finding,
    OWASPCategory,
    Severity,
    ScanHistoryEntry,
)


# ---------------------------------------------------------------------------
# Weight tables — must mirror Go owaspWeights and severityBaseCVSS exactly
# ---------------------------------------------------------------------------

OWASP_WEIGHTS: dict[OWASPCategory, float] = {
    OWASPCategory.API1:  1.10,  # BOLA — most prevalent
    OWASPCategory.API2:  1.15,  # Broken auth — highest impact
    OWASPCategory.API3:  0.95,  # Object property auth
    OWASPCategory.API4:  0.85,  # Resource consumption
    OWASPCategory.API5:  1.05,  # Function-level auth
    OWASPCategory.API6:  0.90,  # Sensitive business flows
    OWASPCategory.API7:  1.10,  # SSRF — often leads to RCE
    OWASPCategory.API8:  0.80,  # Misconfiguration
    OWASPCategory.API9:  0.95,  # Inventory management
    OWASPCategory.API10: 0.75,  # Unsafe consumption
    OWASPCategory.NONE:  0.70,  # General / unclassified
}

SEVERITY_BASE_CVSS: dict[Severity, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH:     7.5,
    Severity.MEDIUM:   5.5,
    Severity.LOW:      3.0,
    Severity.INFO:     1.0,
}

TIER_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 4.0,
    Severity.HIGH:     2.5,
    Severity.MEDIUM:   1.5,
    Severity.LOW:      0.8,
    Severity.INFO:     0.2,
}


# ---------------------------------------------------------------------------
# Environmental context multipliers
# ---------------------------------------------------------------------------

def asset_criticality_multiplier(endpoint: Optional[Endpoint]) -> float:
    """
    Increase risk score for financial/admin/auth paths;
    decrease for staging/dev/test environments.
    Mirrors Go assetCriticalityMultiplier().
    """
    if endpoint is None:
        return 1.0
    path = endpoint.path.lower()
    # Financial data
    for kw in ("payment", "billing", "credit", "invoice"):
        if kw in path:
            return 1.25
    # Privileged operations
    for kw in ("admin", "superuser", "root"):
        if kw in path:
            return 1.20
    # Authentication surface
    for kw in ("auth", "token", "login"):
        if kw in path:
            return 1.15
    # Lower-criticality environments
    for kw in ("staging", "dev", "test"):
        if kw in path:
            return 0.75
    return 1.0


def auth_state_multiplier(endpoint: Optional[Endpoint]) -> float:
    """Unauthenticated endpoints are scored higher. Mirrors Go authStateMultiplier()."""
    if endpoint is None or endpoint.auth_required:
        return 1.0
    return 1.15


def pii_multiplier(endpoint: Optional[Endpoint]) -> float:
    """Endpoints serving PII are scored higher. Mirrors Go piiMultiplier()."""
    if endpoint is None:
        return 1.0
    if endpoint.has_pii_params:
        return 1.20
    return 1.0


# ---------------------------------------------------------------------------
# Finding-level scoring
# ---------------------------------------------------------------------------

def score_finding(finding: Finding) -> int:
    """
    Compute the SentinelRank score (0-100) for a single finding.
    Mirrors Go RankEngine.ScoreFinding().
    """
    cvss = finding.cvss_score if finding.cvss_score > 0 else SEVERITY_BASE_CVSS.get(finding.severity, 5.0)
    base = cvss * 10.0  # scale CVSS (0-10) to 0-100

    weight = OWASP_WEIGHTS.get(finding.owasp_category, OWASP_WEIGHTS[OWASPCategory.NONE])

    score = (
        base
        * weight
        * asset_criticality_multiplier(finding.endpoint)
        * auth_state_multiplier(finding.endpoint)
        * pii_multiplier(finding.endpoint)
    )

    return _clamp(round(score), 0, 100)


# ---------------------------------------------------------------------------
# Scan-level scoring
# ---------------------------------------------------------------------------

def score_scan(
    findings: list[Finding],
    critical_count: int,
    high_count: int,
    undocumented_count: int,
) -> int:
    """
    Compute the overall SentinelRank health score (0 = critical, 100 = excellent).
    Mirrors Go RankEngine.ScoreScan().
    """
    if not findings:
        return 95

    weighted_sum = 0.0
    total_weight = 0.0

    for f in findings:
        s = float(score_finding(f))
        w = TIER_WEIGHTS.get(f.severity, 0.2)
        weighted_sum += s * w
        total_weight += w

    if total_weight == 0:
        return 100

    avg_risk = weighted_sum / total_weight

    # Logarithmic count penalty — more criticals → lower score
    penalty = (
        math.log1p(critical_count) * 5
        + math.log1p(high_count) * 2
        + math.log1p(undocumented_count) * 3
    )

    raw = avg_risk + penalty
    return _clamp(100 - round(raw), 0, 100)


# ---------------------------------------------------------------------------
# Priority classification
# ---------------------------------------------------------------------------

def classify_priority(finding: Finding) -> str:
    """
    Map a finding's severity and risk score to a remediation priority tier.
    Used to populate AIFindingResponse.priority.
    """
    risk = score_finding(finding)
    if finding.severity == Severity.CRITICAL or risk >= 85:
        return "IMMEDIATE"
    if finding.severity == Severity.HIGH or risk >= 60:
        return "SHORT_TERM"
    return "LONG_TERM"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clamp(value: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, value))
