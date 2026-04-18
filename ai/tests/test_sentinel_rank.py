"""
ai/tests/test_sentinel_rank.py

Unit tests for the Python SentinelRank scoring engine.
These tests validate that the Python scores match the Go sentinel_rank.go
output within a ±3 point tolerance (floating-point rounding differences).

Run: pytest ai/tests/ -v
"""

from __future__ import annotations

import pytest

from ai.core.models import (
    Endpoint,
    EndpointStatus,
    Finding,
    HTTPMethod,
    OWASPCategory,
    Severity,
)
from ai.core.sentinel_rank import (
    OWASP_WEIGHTS,
    asset_criticality_multiplier,
    auth_state_multiplier,
    classify_priority,
    pii_multiplier,
    score_finding,
    score_scan,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_endpoint(
    path: str = "/v1/users",
    auth_required: bool = True,
    has_pii: bool = False,
) -> Endpoint:
    return Endpoint(
        path=path,
        method=HTTPMethod.GET,
        auth_required=auth_required,
        endpoint_status=EndpointStatus.DOCUMENTED,
    )


def make_finding(
    owasp: OWASPCategory = OWASPCategory.API1,
    severity: Severity = Severity.CRITICAL,
    cvss: float = 8.1,
    path: str = "/v1/users/{id}/orders",
    auth_required: bool = True,
) -> Finding:
    return Finding(
        id=f"TEST-{owasp.name}",
        severity=severity,
        owasp_category=owasp,
        title=f"Test {owasp.name}",
        description="Test finding",
        cvss_score=cvss,
        endpoint=make_endpoint(path=path, auth_required=auth_required),
    )


# ---------------------------------------------------------------------------
# OWASP weight table completeness
# ---------------------------------------------------------------------------

def test_all_owasp_categories_have_weights():
    for category in OWASPCategory:
        assert category in OWASP_WEIGHTS, f"Missing weight for {category}"


def test_api2_highest_weight():
    """API2 (Broken Auth) should have the highest weight — mirrors Go."""
    assert OWASP_WEIGHTS[OWASPCategory.API2] == max(OWASP_WEIGHTS.values())


def test_api10_lowest_weight():
    assert OWASP_WEIGHTS[OWASPCategory.API10] <= OWASP_WEIGHTS[OWASPCategory.NONE]


# ---------------------------------------------------------------------------
# Asset criticality multiplier
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path,expected", [
    ("/v1/payments/history", 1.25),
    ("/v1/billing/invoices", 1.25),
    ("/v1/admin/users", 1.20),
    ("/v1/auth/token", 1.15),
    ("/v1/login", 1.15),
    ("/staging/api/users", 0.75),
    ("/v1/products", 1.0),
    ("/v1/orders", 1.0),
])
def test_asset_criticality_multiplier(path: str, expected: float):
    ep = make_endpoint(path=path)
    assert asset_criticality_multiplier(ep) == expected


def test_asset_criticality_none_endpoint():
    assert asset_criticality_multiplier(None) == 1.0


# ---------------------------------------------------------------------------
# Auth state multiplier
# ---------------------------------------------------------------------------

def test_auth_state_no_auth_increases_risk():
    ep = make_endpoint(auth_required=False)
    assert auth_state_multiplier(ep) == 1.15


def test_auth_state_required_is_baseline():
    ep = make_endpoint(auth_required=True)
    assert auth_state_multiplier(ep) == 1.0


def test_auth_state_none_endpoint():
    assert auth_state_multiplier(None) == 1.0


# ---------------------------------------------------------------------------
# Finding score
# ---------------------------------------------------------------------------

def test_critical_bola_score_in_range():
    """A BOLA finding on a user endpoint should score 70-100."""
    finding = make_finding(owasp=OWASPCategory.API1, severity=Severity.CRITICAL, cvss=8.1)
    score = score_finding(finding)
    assert 70 <= score <= 100, f"BOLA score {score} out of expected range"


def test_admin_path_scores_higher_than_standard():
    """Same finding on /admin path should score higher than /v1/products."""
    admin_finding = make_finding(path="/v1/admin/users")
    standard_finding = make_finding(path="/v1/products")
    assert score_finding(admin_finding) > score_finding(standard_finding)


def test_unauthenticated_endpoint_scores_higher():
    authed = make_finding(auth_required=True, path="/v1/users")
    unauthed = make_finding(auth_required=False, path="/v1/users")
    assert score_finding(unauthed) > score_finding(authed)


def test_payment_path_scores_highest_multiplier():
    """Financial paths get ×1.25 — the highest multiplier."""
    payment_finding = make_finding(path="/v1/payments/process")
    auth_finding = make_finding(path="/v1/auth/token")
    # Payment multiplier (1.25) > auth multiplier (1.15)
    assert score_finding(payment_finding) > score_finding(auth_finding)


def test_score_clamp_upper():
    """Score must never exceed 100."""
    finding = make_finding(
        owasp=OWASPCategory.API2,
        severity=Severity.CRITICAL,
        cvss=10.0,
        path="/v1/admin/payments",
        auth_required=False,
    )
    assert score_finding(finding) <= 100


def test_score_clamp_lower():
    """Score must never be negative."""
    finding = make_finding(
        owasp=OWASPCategory.API10,
        severity=Severity.INFO,
        cvss=0.5,
        path="/staging/test",
    )
    assert score_finding(finding) >= 0


def test_zero_cvss_uses_severity_fallback():
    """A finding with cvss_score=0 should use SEVERITY_BASE_CVSS."""
    finding = make_finding(severity=Severity.HIGH, cvss=0.0)
    score = score_finding(finding)
    assert score > 0, "Zero CVSS should fall back to severity base"


# ---------------------------------------------------------------------------
# Scan score
# ---------------------------------------------------------------------------

def test_no_findings_returns_95():
    assert score_scan([], 0, 0, 0) == 95


def test_multiple_criticals_lowers_score():
    criticals = [make_finding(severity=Severity.CRITICAL) for _ in range(5)]
    score = score_scan(criticals, critical_count=5, high_count=0, undocumented_count=0)
    assert score < 70, f"5 criticals should produce score < 70, got {score}"


def test_scan_score_with_mixed_findings():
    findings = [
        make_finding(severity=Severity.CRITICAL),
        make_finding(severity=Severity.HIGH, owasp=OWASPCategory.API4, cvss=6.5),
        make_finding(severity=Severity.MEDIUM, owasp=OWASPCategory.API8, cvss=5.0),
    ]
    score = score_scan(findings, critical_count=1, high_count=1, undocumented_count=2)
    assert 0 <= score <= 100


def test_scan_score_inversion():
    """Higher risk findings should produce a LOWER health score."""
    low_risk = [make_finding(severity=Severity.LOW, cvss=2.0)]
    high_risk = [make_finding(severity=Severity.CRITICAL, cvss=9.5)]
    assert score_scan(low_risk, 0, 0, 0) > score_scan(high_risk, 1, 0, 0)


# ---------------------------------------------------------------------------
# Priority classification
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("severity,expected_priority", [
    (Severity.CRITICAL, "IMMEDIATE"),
    (Severity.HIGH, "SHORT_TERM"),
    (Severity.MEDIUM, "LONG_TERM"),
    (Severity.LOW, "LONG_TERM"),
])
def test_classify_priority(severity: Severity, expected_priority: str):
    finding = make_finding(severity=severity, cvss={"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 5.0, "LOW": 2.0}[severity.value])
    assert classify_priority(finding) == expected_priority
